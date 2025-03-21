const express = require('express');
const router = express.Router();
const userModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

router.get('/login', (req, res) => {
    res.render('login', { messages: req.flash() });
});

router.get('/signup', (req, res) => {
    res.render('signup', { messages: req.flash() });
});

router.post('/signup', async (req, res) => {
    try {
        let { username, email, password, fullName } = req.body;

        function generateCustomUid(prefix = 'PS-', length = 12) {
            const uuidWithoutHyphens = uuidv4().replace(/-/g, '');
            const customUid = `${prefix}${uuidWithoutHyphens.slice(0, length)}`;
            return customUid;
        }

        const customUid = generateCustomUid()


        let foundUser = await userModel.findOne({
            $or: [{ username }, { email }]
        });

        if (foundUser) {
            req.flash('error', 'User already exists! Try logging in.');
            return res.redirect('/auth/signup');
        }

        let hashedPassword = await bcrypt.hash(password, 10);

        await userModel.create({
            username,
            email,
            password: hashedPassword,
            fullName,
            uid: customUid
        });

        req.flash('success', 'Account created successfully. Please log in.');
        res.redirect('/auth/login');
    } catch (error) {
        console.error("Signup Error:", error);
        req.flash('error', 'An internal error occurred. Please try again.');
        res.redirect('/auth/signup');
    }
});

router.post('/login', async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;

        const foundUser = await userModel.findOne({
            $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
        });

        if (!foundUser) {
            req.flash('error', 'Invalid Username/Email or Password');
            return res.redirect('/auth/login');
        }

        const isMatch = await bcrypt.compare(password, foundUser.password);
        if (!isMatch) {
            req.flash('error', 'Invalid Username/Email or Password');
            return res.redirect('/auth/login');
        }

        if (!process.env.JWT_SECRET) {
            throw new Error("Missing JWT_SECRET in environment variables");
        }

        const token = jwt.sign(
            { user: foundUser.username, email: foundUser.email, id: foundUser._id },
            process.env.JWT_SECRET,
        );

        res.cookie("token", token);

        res.redirect('/');
    } catch (error) {
        console.error("Login Error:", error);
        req.flash('error', 'An internal error occurred. Please try again.');
        res.redirect('/auth/login');
    }
});

router.get('/ping', (req, res) => {
    res.status(200).send("Server is alive! 🚀");
});

router.get('/logout', (req, res) => {
    res.clearCookie("token");
    req.flash('success', 'Logged out successfully.');
    res.redirect("/auth/login");
});

module.exports = router;
