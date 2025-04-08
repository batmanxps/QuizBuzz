const express = require('express');
const router = express.Router();
const userModel = require('../models/userModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require("express-rate-limit");

const axios = require('axios');

async function verifyCaptcha(token) {
    const secretKey = process.env.RECAPTCHA_SECRET;
    const response = await axios.post(
        `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`
    );
    return response.data.success;
}


const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Too many login attempts. Please try again later."
});


const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

async function sendVerificationEmail(email, token) {
    const verifyUrl = `${process.env.CLIENT_URL}/auth/verify-email?token=${token}`;

    const mailOptions = {
        from: `"QuizBuzz" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Verify your email for QuizBuzz',
        html: `
            <h2>Welcome to QuizBuzz!</h2>
            <p>Click the button below to verify your email:</p>
            <a href="${verifyUrl}" style="background-color:#3b82f6;color:white;padding:10px 20px;border-radius:5px;text-decoration:none;">Verify Email</a>
            <p>If the button doesn't work, copy and paste this URL into your browser:</p>
            <p>${verifyUrl}</p>
        `
    };

    await transporter.sendMail(mailOptions);
}


router.get('/login', (req, res) => {
    res.render('login');
});

router.get('/verify', (req, res) => {
    const email = req.query.email || '';
    if (!email) {
        req.flash('error', 'Email not provided for verification.');
    }
    res.render('mailVerify', { email, messages: req.flash() });
});

router.get('/signup', (req, res) => {
    res.render('signup', { messages: req.flash() });
});

router.post('/signup', async (req, res) => {
    try {
        const { username, email, password, fullName, 'g-recaptcha-response': captchaToken } = req.body;

        if (!captchaToken || !(await verifyCaptcha(captchaToken))) {
            req.flash("error", "reCAPTCHA verification failed. Please try again.");
            return res.redirect('/auth/signup');
        }

        const existingUser = await userModel.findOne({
            $or: [{ username }, { email }]
        });

        if (existingUser) {
            req.flash('error', 'User already exists! Try logging in.');
            return res.redirect('/auth/signup');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const customUid = `PS-${uuidv4().replace(/-/g, '').slice(0, 12)}`;

        const newUser = await userModel.create({
            username,
            email,
            password: hashedPassword,
            fullName,
            uid: customUid,
            isVerified: false
        });

        const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

        await sendVerificationEmail(newUser.email, token);

        req.flash('success', 'Verification email sent. Please check your inbox.');
        return res.redirect(`/auth/verify?email=${encodeURIComponent(email)}`);
    } catch (error) {
        console.error("Signup Error:", error);
        req.flash('error', 'An internal error occurred. Please try again.');
        return res.redirect('/auth/signup');
    }
});

router.get('/verify-email', async (req, res) => {
    const token = req.query.token;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user) {
            req.flash('error', 'Invalid or expired verification link.');
            return res.redirect('/auth/login');
        }

        if (!user.isVerified) {
            user.isVerified = true;
            await user.save();
        }

        // Optionally auto-login user here if desired
        req.flash('success', 'Email verified successfully.');
        res.redirect('/');
    } catch (err) {
        console.error("Verification Error:", err);
        req.flash('error', 'Invalid or expired verification token.');
        res.redirect('/auth/login');
    }
});

router.post('/verify', async (req, res) => {
    const { email } = req.body;
    const user = await userModel.findOne({ email });

    if (!user) {
        req.flash('error', 'No user found with that email.');
        return res.redirect('/auth/verify');
    }

    if (user.isVerified) {
        req.flash('success', 'Email already verified. You can log in.');
        return res.redirect('/auth/login');
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    await sendVerificationEmail(user.email, token);

    req.flash('success', 'Verification email sent again.');
    res.redirect('/auth/login');
});

router.post('/login', loginLimiter, async (req, res) => {
    try {
        const { usernameOrEmail, password } = req.body;

        // Find user by username or email
        const foundUser = await userModel.findOne({
            $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
        });

        if (!foundUser) {
            req.flash('error', 'Invalid Username/Email or Password');
            return res.redirect('/auth/login');
        }

        // Check if user has verified their email
        if (!foundUser.isVerified) {
            req.flash('error', 'Please verify your email before logging in.');
            return res.redirect('/auth/login');
        }

        // Check if password matches
        const isMatch = await bcrypt.compare(password, foundUser.password);
        if (!isMatch) {
            req.flash('error', 'Invalid Username/Email or Password');
            return res.redirect('/auth/login');
        }

        // Check JWT secret
        if (!process.env.JWT_SECRET) {
            throw new Error("Missing JWT_SECRET in environment variables");
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: foundUser._id, email: foundUser.email, user: foundUser.username },
            process.env.JWT_SECRET,
            { expiresIn: '15d' } // Token lasts 15 days
        );

        // Store user info in session
        req.session.user = {
            id: foundUser._id,
            email: foundUser.email,
            username: foundUser.username
        };

        // Set cookie with JWT
        res.cookie("token", token, {
            httpOnly: true,
            maxAge: 15 * 24 * 60 * 60 * 1000, // 15 days
            secure: process.env.NODE_ENV === 'production' // use HTTPS in prod
        });

        // Redirect to home/dashboard
        res.redirect('/');
    } catch (error) {
        console.error("Login Error:", error);
        req.flash('error', 'An internal error occurred. Please try again.');
        res.redirect('/auth/login');
    }
});

router.get('/forgot', (req, res) => {
    res.render('forgotPassword', { messages: req.flash() });
});

router.get('/reset-password', (req, res) => {
    const token = req.query.token;
    res.render('resetPassword', { token, messages: req.flash() });
});


router.post('/forgot', async (req, res) => {
    const { email } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
        req.flash('error', 'No account found with that email.');
        return res.redirect('/auth/forgot');
    }

    const token = jwt.sign(
        { id: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
    );

    const resetLink = `${process.env.CLIENT_URL}/auth/reset-password?token=${token}`;

    const mailOptions = {
        from: `"QuizBuzz" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Reset your QuizBuzz password',
        html: `
            <h3>Forgot your password?</h3>
            <p>Click below to reset it:</p>
            <a href="${resetLink}" style="padding:10px 20px; background:#3b82f6; color:#fff; border-radius:5px;">Reset Password</a>
            <p>Or paste this link in your browser:</p>
            <p>${resetLink}</p>
        `
    };

    await transporter.sendMail(mailOptions);

    req.flash('success', 'Password reset link sent to your email. Please check your inbox and spam folder.');
    return res.redirect('/auth/login');

});

router.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user) {
            req.flash('error', 'Invalid or expired reset token.');
            return res.redirect('/auth/forgot');
        }

        const hashed = await bcrypt.hash(password, 10);
        user.password = hashed;
        await user.save();

        req.flash('success', 'Password reset successful. Please log in.');
        res.redirect('/auth/login');

    } catch (err) {
        console.error("Reset error:", err);
        req.flash('error', 'Something went wrong. Try again.');
        res.redirect('/auth/forgot');
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
