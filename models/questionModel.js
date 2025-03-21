const mongoose = require("mongoose");

const quizSchema = new mongoose.Schema({
    title: { type: String, required: true },  
    questions: [
        {
            question: { type: String, required: true },
            options: { type: [String], required: true },
            ans: { type: Number, required: true } 
        }
    ],
    status: { type: String, enum: ["live", "scheduled", "ended"], default: "scheduled" },  
    startTime: { type: Date, required: true },  
    endTime: { type: Date, required: true }  
});

const Quiz = mongoose.model("Quiz", quizSchema);
module.exports = Quiz;
