const express = require('express');
const router = express.Router();
const Quiz = require('../models/questionModel')
const User = require('../models/userModel')
const moment = require("moment-timezone");

router.get('/adminDashboard', (req, res) => {
    res.render('adminDashboard')
})

router.get('/deleteUser', async (req, res) => {
    try {
        const users = await User.find({}, 'fullName email isAdmin');
        res.render('deleteUser', { users });
    } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).send("Server Error");
    }
});

router.delete('/delete-user/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        const deletedUser = await User.findByIdAndDelete(userId);

        if (!deletedUser) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.json({ success: true, message: "User deleted successfully!" });
    } catch (error) {
        console.error("Error deleting user:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

router.get('/verifyUser', async (req, res) => {
    try {
        const users = await User.find({}, 'fullName email');
        res.render('verifyUser', { users });
    } catch (error) {
        console.error("Error deleting user:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

router.post('/verify/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;

        // Find the user first
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // Toggle isTopper value (switch between true & false)
        user.isTopper = !user.isTopper;
        await user.save();

        res.json({ success: true, isTopper: user.isTopper });
    } catch (error) {
        console.error("Error toggling user verification:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});




router.get('/add-test', (req, res) => {
    res.render('admin-add-test')
})

router.post("/add-quiz", async (req, res) => {
    try {
        let { title, questions, startTime, endTime } = req.body;

        startTime = moment.tz(startTime, "Asia/Kolkata").utc().toISOString();
        endTime = moment.tz(endTime, "Asia/Kolkata").utc().toISOString();

        await Quiz.create({
            title,
            questions,
            startTime,
            endTime,
            status: new Date() < new Date(startTime) ? "scheduled" : "live"
        });

        res.json({ message: "Quiz added successfully!" });
    } catch (error) {
        console.error("Server error:", error);
        res.status(500).json({ error: "Error adding quiz" });
    }
});


router.get('/delete-test', async (req, res) => {
    const now = new Date();

    const liveQuizzes = await Quiz.find({ startTime: { $lte: now }, endTime: { $gt: now } });
    const scheduledQuizzes = await Quiz.find({ startTime: { $gt: now } });
    const previousQuizzes = await Quiz.find({ endTime: { $lt: now } });

    res.render("deleteTest", { liveQuizzes, scheduledQuizzes, previousQuizzes });
});

router.delete('/delete-quiz/:id', async (req, res) => {
    try {
        const quizId = req.params.id;
        const deletedQuiz = await Quiz.findByIdAndDelete(quizId);

        if (!deletedQuiz) {
            return res.status(404).json({ success: false, message: "Quiz not found" });
        }

        res.json({ success: true, message: "Quiz deleted successfully!" });
    } catch (error) {
        console.error("Error deleting quiz:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});



module.exports = router;
