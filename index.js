const express = require('express')
const app = express();
require('dotenv').config()
const path = require('path')
const db = require('./config/DataBase')
const session = require('express-session');
const cookie = require('cookie-parser');
const flash = require('connect-flash');
const axios = require("axios");
const cron = require("node-cron");
const moment = require("moment-timezone");

let PORT = process.env.PORT || 5050
db()

process.env.TZ = "Asia/Kolkata";
moment().tz("Asia/Kolkata").format();


const authRoutes = require('./routes/authRoutes')
const indexRoutes = require('./routes/indexRoutes')
const adminRoutes = require('./routes/adminRoutes')
const isAuthenticated = require('./middleware/isAuthenticated')
const { ensureAuthenticated, ensureAdmin } = require('./middleware/isAdmin')

app.use(flash());
app.use(cookie());
app.set('view engine', 'ejs')
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

const MongoStore = require("connect-mongo");

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        collectionName: "sessions"
    }),
    cookie: {
        maxAge: 15 * 24 * 60 * 60 * 1000, // 15 days (User stays logged in)
        secure: true,  // Set to true if using HTTPS
        httpOnly: true
    }
}));

process.on("uncaughtException", (err) => {
    console.error("Uncaught Exception:", err);
    process.exit(1); 
});

process.on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection:", reason);
    process.exit(1);
});

app.use('/auth', authRoutes)
app.use('/', isAuthenticated, indexRoutes)
app.use('/admin', isAuthenticated, ensureAuthenticated, ensureAdmin, adminRoutes)

app.use((req, res) => {
    res.status(404).render("error", { url: req.originalUrl });
});

app.use((req, res, next) => {
    req.setTimeout(15000, () => { 
        res.status(408).send("Request Timeout");
    });
    next();
});

app.use((err, req, res, next) => {
    console.error("Unexpected Error:", err);
    res.status(500).json({ message: "Server error, please try again later" });
});

const SERVER_URL = process.env.SERVER_URL || "http://localhost:3000";

app.get('/health', (req, res) => {
    res.status(200).json({ status: "Server is running", time: new Date() });
});

cron.schedule("*/14 * * * *", async () => {
    try {
        console.log(`Pinging ${SERVER_URL}/health`);
        const response = await axios.get(`${SERVER_URL}/health`);
        console.log("✅ Server keep-alive response:", response.data);
    } catch (error) {
        console.error("❌ Error keeping server alive:", error.message);
    }
});


app.listen(PORT, () => {
    console.log(`Server listen on ${PORT}`);
})