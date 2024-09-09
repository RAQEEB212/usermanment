const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

let users = []; // In-memory user store

// Signup Route
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    // Check if user already exists
    const userExists = users.find(user => user.email === email);
    if (userExists) return res.status(400).send('User already exists');

    // Hash the password with 10 salt rounds
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store the user (without verification)
    users.push({ name, email, password: hashedPassword });

    res.status(200).send('Signup successful!');
});

// Login Route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Find the user
    const user = users.find(user => user.email === email);
    if (!user) return res.status(400).send('Invalid email or password');

    // Compare the password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password');

    // Create a JWT token
    const token = jwt.sign({ userId: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.send({ message: 'Login successful!', token });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
