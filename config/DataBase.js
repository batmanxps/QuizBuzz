const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 15000,
            socketTimeoutMS: 20000,
            bufferCommands: false
        });
        console.log("MongoDB Connected Successfully!");
    } catch (error) {
        console.error("MongoDB Connection Error:", error.message);
        process.exit(1);
    }
};

module.exports = connectDB;
