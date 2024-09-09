const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(express.json());

let users = []; // In-memory user store (for now)

// Root route
app.get('/', (req, res) => {
    res.send('Hello, your server is running!');
});

// Setup Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD,
    }
});

// Signup Route
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    const userExists = users.find(user => user.email === email);
    if (userExists) return res.status(400).send('User already exists');

    // Hash the password with 10 salt rounds
    const hashedPassword = await bcrypt.hash(password, 10);  // Fixed here!

    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    users.push({ name, email, password: hashedPassword, isVerified: false, verificationToken });

    const mailOptions = {
        from: process.env.SMTP_EMAIL,
        to: email,
        subject: 'Verify Your Email',
        text: `Click this link to verify: http://localhost:3000/verify-email?token=${verificationToken}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return res.status(500).send('Error sending verification email');
        }
        res.status(200).send('Signup successful! Please verify your email.');
    });
});

// Email Verification Route
app.get('/verify-email', (req, res) => {
    const { token } = req.query;

    try {
        const { email } = jwt.verify(token, process.env.JWT_SECRET);

        const user = users.find(user => user.email === email);
        if (!user) return res.status(400).send('User not found');

        user.isVerified = true;

        res.send('Email successfully verified!');
    } catch (error) {
        res.status(400).send('Invalid or expired token');
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(user => user.email === email);
    if (!user) return res.status(400).send('Invalid email or password');

    if (!user.isVerified) return res.status(400).send('Please verify your email first');

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password');

    const token = jwt.sign({ userId: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.send({ message: 'Login successful!', token });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
