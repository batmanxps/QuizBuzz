const express = require('express');
const bcrypt = require('bcrypt');
const userModel = require('../models/userModel');
const Quiz = require('../models/questionModel')
const QuizResult = require("../models/QuizResult");
const mongoose = require("mongoose");
const router = express.Router();

// Middleware to ensure authentication (if using Passport.js)
function ensureAuthenticated(req, res, next) {
    if (!req.user || !req.user._id) { // Ensure user exists and has an ID
        req.flash('error', 'Please log in to access this page.');
        return res.redirect('/auth/login');
    }
    next();
}


// Home route
router.get('/', ensureAuthenticated, async (req, res) => {
    try {
        const userUId = req.user;
        const now = new Date();

        // Fetch quizzes from database
        const liveQuizzes = await Quiz.find({
            startTime: { $lte: now }, // Ongoing quizzes
            endTime: { $gt: now }
        });

        const scheduledQuizzes = await Quiz.find({
            startTime: { $gt: now } // Upcoming quizzes
        });

        const previousQuizzes = await Quiz.find({
            endTime: { $lt: now } // Completed quizzes
        });

        res.render("index", { liveQuizzes, scheduledQuizzes, previousQuizzes, userUId });

    } catch (error) {
        console.error("Error fetching quizzes:", error);
        res.status(500).send("Server Error");
    }
});


// Settings page
router.get('/:id/Settings', ensureAuthenticated, (req, res) => {
    res.render('settings', { user: req.user, messages: req.flash() });
});

router.get('/:id/Delete', ensureAuthenticated, async (req, res) => {
    try {
        let loguser = req.user;

        // Check if user exists before deleting
        const user = await userModel.findById(loguser.id);
        if (!user) {
            req.flash('error', 'User not found.');
            return res.redirect('/');
        }

        await userModel.findByIdAndDelete(loguser.id);
        res.clearCookie("token")
        req.flash('success', 'Account deleted successfully.');
        res.redirect("/auth/login");

    } catch (error) {
        console.error("Error deleting user:", error);
        req.flash('error', 'Something went wrong.');
        res.redirect('/');
    }
});


router.get('/test', ensureAuthenticated, async (req, res) => {
    res.render('game')
});

router.get('/quiz/:id/result', ensureAuthenticated, async (req, res) => {
    res.render('result', { quizId: req.params.id });
});



router.get('/leaderboard', ensureAuthenticated, async (req, res) => {
    res.render('leaderboard')
});

// Update user
router.post('/:id/Update', ensureAuthenticated, async (req, res) => {
    try {
        const user = req.user._id
        const { username, email, fullName, password } = req.body;

        let hashedPassword = await bcrypt.hash(password, 10);

        await userModel.findByIdAndUpdate(
            user,
            { username, email, password: hashedPassword, fullName },
            { new: true }
        );

        req.flash('success', 'Profile updated successfully.');
        res.redirect(`/${user}/Settings`);
    } catch (error) {
        console.error('Error updating user:', error);
        req.flash('error', 'Something went wrong. Please try again.');
        res.redirect('/auth/login');
    }
});

router.get("/test/:id", async (req, res) => {
    try {
        const quiz = await Quiz.findById(req.params.id);
        if (!quiz) {
            return res.status(404).send("Quiz not found");
        }

        res.render("game", { quiz });
    } catch (error) {
        console.error(error);
        res.status(500).send("Server Error");
    }
});

router.post("/submit-result", async (req, res) => {
    try {
        const { quizId, score, correctAnswers, wrongAnswers, totalTimeTaken } = req.body;

        // Check if quizId is provided
        if (!quizId) {
            return res.status(400).json({ success: false, message: "Quiz ID is required!" });
        }

        // Check if user is authenticated
        if (!req.user || !req.user.id) {
            return res.status(401).json({ success: false, message: "User authentication required!" });
        }

        const userId = req.user.id;

        // Check if user already has an entry for this quiz
        const existingResult = await QuizResult.findOne({ userId, quizId });

        if (existingResult) {
            return res.status(200).json({ success: false, message: "First attempt already recorded. No new entry saved." });
        }

        // Save quiz result (only first attempt)
        await QuizResult.create({
            userId,
            quizId,
            score,
            correctAnswers,
            wrongAnswers,
            timeTaken: totalTimeTaken
        });

        res.json({ success: true, message: "First attempt recorded successfully!" });

    } catch (error) {
        console.error("Error saving quiz result:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});


// Fetch quizzes
router.get("/quizzes", async (req, res) => {
    try {
        const quizzes = await Quiz.find({}, "_id title");
        res.json(quizzes);
    } catch (error) {
        console.error("❌ Error fetching quizzes:", error);
        res.status(500).json({ message: "Server error" });
    }
});

// Fetch leaderboard by quiz ID
router.get("/leaderboard/:quizId", async (req, res) => {
    try {
        const { quizId } = req.params;

        let query = { quizId }; // Default as string
        if (mongoose.Types.ObjectId.isValid(quizId)) {
            query = { quizId: new mongoose.Types.ObjectId(quizId) };
        }

        const topResults = await QuizResult.find(query)
            .populate("userId", "username isAdmin isTopper")
            .sort({ score: -1, timeTaken: 1 })
            .limit(10);

        const leaderboard = topResults
            .filter(result => result.userId)
            .map(result => ({
                username: result.userId.username || "Unknown",
                isAdmin: result.userId.isAdmin || false,
                isTopper: result.userId.isTopper || false,
                score: result.score,
                correctAnswers: result.correctAnswers,
                timeTaken: result.timeTaken
            }));

        res.json(leaderboard);
    } catch (error) {
        console.error("❌ Error fetching leaderboard:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
});


router.get('/logout', (req, res) => {
    res.clearCookie("token");
    req.flash('success', 'Logged out successfully.');
    res.redirect("/auth/login");
})


module.exports = router;
