const express = require('express');
const session = require('express-session');
const path = require('path'); // Import the path module
const connection = require('./db'); // Import the database connection
const routes = require('./routes'); // Import routes

require('dotenv').config();

const app = express();
const PORT = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Route for the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html')); // Serve the index.html file
});

// Route for Profile
app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html')); // Serve the profile.html file
});

// Route for Admin Login
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login-admin.html'));
});

// Serve static files from the public directory
app.use(express.static('public'));

// Session management
app.use(session({
    secret: process.env.SECRETKEY,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // Set to true if using HTTPS
        maxAge: 1000 * 60 * 60 * 24 // 1 day (adjust as needed)
    }
}));

// Middleware to check if the user is logged in
function isLoggedIn(req, res, next) {
    if (req.session.patientId) {
        next(); // User is logged in, proceed to the next middleware or route
    } else {
        res.status(401).send('Unauthorized'); // User is not logged in
    }
}

// Middleware to check if admin is logged in
function isAdminLoggedIn(req, res, next) {
    if (req.session.adminId) {
        next(); // Admin is logged in, proceed to the next middleware or route
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized' });
    }
}

//middleware for routes that require admin login
app.use('/admin/dashboard', isAdminLoggedIn, (req, res) => {
    res.send('Welcome to the Admin Dashboard');
});


// Use routes
app.use('/', routes);

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});