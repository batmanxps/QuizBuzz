const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            min: 6,
            lowercase: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
        },
        password: {
            type: String,
            required: true,
        },
        fullName: {
            type: String,
            default: "",
        },
        isAdmin: {
            type: Boolean,
            default: false,
        },
        isTopper: {
            type: Boolean,
            default: false,
        },
        uid: String,
    },
    {
        timestamps: true,
    }
);

module.exports = mongoose.model("User", userSchema);