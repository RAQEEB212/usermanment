const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(express.json());

let users = []; // In-memory user store

// Setup Nodemailer transporter with Gmail
const transporter = nodemailer.createTransport({
    service: 'Gmail', // Using Gmail's email service
    auth: {
        user: process.env.SMTP_EMAIL,   // Your Gmail address
        pass: process.env.SMTP_PASSWORD // Your Gmail App Password
    }
});

// Signup Route
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    // Check if user already exists
    const userExists = users.find(user => user.email === email);
    if (userExists) return res.status(400).send('User already exists');

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a JWT token for email verification
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Store the new user with 'isVerified' flag as false initially
    users.push({ name, email, password: hashedPassword, isVerified: false, verificationToken });

    // Send verification email with the verification link
    const verificationLink = `http://localhost:3000/verify-email?token=${verificationToken}`;
    const mailOptions = {
        from: process.env.SMTP_EMAIL,
        to: email,
        subject: 'Verify Your Email',
        text: `Hello ${name}, please verify your email by clicking on the link: ${verificationLink}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error); // Log detailed error in the console
            return res.status(500).send('Error sending verification email');
        }
        console.log('Email sent:', info.response); // Log success if email was sent
        res.status(200).send('Signup successful! Please verify your email.');
    });
});

// Verify Email Route
app.get('/verify-email', (req, res) => {
    const { token } = req.query;

    try {
        // Verify the JWT token
        const { email } = jwt.verify(token, process.env.JWT_SECRET);

        // Find the user by email
        const user = users.find(user => user.email === email);
        if (!user) return res.status(400).send('User not found');

        // Check if the user is already verified
        if (user.isVerified) return res.status(400).send('User is already verified');

        // Mark the user as verified
        user.isVerified = true;
        user.verificationToken = null; // Optionally remove the verification token after verification

        res.send('Email successfully verified! You can now log in.');
    } catch (error) {
        res.status(400).send('Invalid or expired token');
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Find the user by email
    const user = users.find(user => user.email === email);
    if (!user) return res.status(400).send('Invalid email or password');

    // Check if the user's email is verified
    if (!user.isVerified) return res.status(400).send('Please verify your email first');

    // Compare the hashed password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password');

    // Generate a JWT for the logged-in user
    const token = jwt.sign({ userId: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.send({ message: 'Login successful!', token });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
