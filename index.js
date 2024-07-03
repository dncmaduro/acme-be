const express = require('express');
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cookieParser());

const SECRET_KEY = 'your_secret_key'; // Replace with your own secret key

// PostgreSQL connection string
const connectionString = "postgresql://gdschanu-manhdung:nVCGk5jXKU3s@ep-polished-base-a1apw349-pooler.ap-southeast-1.aws.neon.tech/acme?sslmode=require";

// Create a new PostgreSQL client
const client = new Client({ connectionString });

client.connect(err => {
  if (err) {
    console.error('Error connecting to PostgreSQL:', err);
    return;
  }

  console.log('Connected to PostgreSQL database!');

  // Create table users
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      email VARCHAR(50) PRIMARY KEY,
      password VARCHAR(255) NOT NULL
    );
  `;

  client.query(createTableQuery, (err, res) => {
    if (err) {
      console.error('Error creating table:', err);
      return;
    }
    console.log('Table users created successfully!');
  });
});

// Function to generate JWT token
const generateToken = (email) => {
  return jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });
};

// Function to authenticate token from cookies
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    req.user = user;
    next();
  });
};

// Signup route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING email';
    const result = await client.query(query, [email, hashedPassword]);

    const token = generateToken(email);
    res.cookie('acme-token', token, { httpOnly: true });

    res.status(201).json({ message: 'User registered successfully!', user: result.rows[0] });
  } catch (err) {
    console.error('Error during signup:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Signin route
app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const query = 'SELECT email, password FROM users WHERE email = $1';
    const result = await client.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect password' });
    }

    const token = generateToken(email);
    res.cookie('acme-token', token, { httpOnly: true });

    res.json({ message: 'User signed in successfully!', user: { email: user.email } });
  } catch (err) {
    console.error('Error during signin:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Change password route
app.post('/changepassword', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const email = req.user.email;

  try {
    const query = 'SELECT email, password FROM users WHERE email = $1';
    const result = await client.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Incorrect old password' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updateQuery = 'UPDATE users SET password = $1 WHERE email = $2 RETURNING email';
    const updateResult = await client.query(updateQuery, [hashedNewPassword, email]);

    res.json({ message: 'Password changed successfully!', user: updateResult.rows[0] });
  } catch (err) {
    console.error('Error during password change:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Define a simple route
app.get('/', authenticateToken, (req, res) => {
  res.send(`Hello, ${req.user.email}!`);
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
