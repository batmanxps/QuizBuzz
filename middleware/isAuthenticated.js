const jwt = require("jsonwebtoken");
const userModel = require("../models/userModel");

const isAuthenticated = async (req, res, next) => {
    try {
        const token = req.cookies.token;

        if (!token) {
            return res.redirect('/auth/login');
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await userModel.findById(decoded.id);

        if (!user) {
            req.flash('error', 'Invalid session, please log in again.');
            return res.redirect('/auth/login');
        }

        // Optionally: store user in req.user for later use
        req.user = user;

        // ✅ Check if session exists, otherwise create it
        if (!req.session.user) {
            req.session.user = {
                id: user._id,
                email: user.email,
                username: user.username
            };
        }

        next(); // ✅ Only one call to next
    } catch (error) {
        console.error("Authentication error:", error);
        res.clearCookie("token");
        req.flash('error', 'Session expired. Please log in again.');
        return res.redirect('/auth/login');
    }
};

module.exports = isAuthenticated;
