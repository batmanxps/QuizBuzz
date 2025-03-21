const mongoose = require("mongoose");

const quizResultSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    quizId: { type: mongoose.Schema.Types.ObjectId, ref: "Quiz", required: true },
    score: { type: Number, required: true },
    correctAnswers: { type: Number, required: true },
    wrongAnswers: { type: Number, required: true },
    timeTaken: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now }
});

const QuizResult = mongoose.model("QuizResult", quizResultSchema);
module.exports = QuizResult;
