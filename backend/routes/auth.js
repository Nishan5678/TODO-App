const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { JWT_SECRET } = require('../middleware/auth');

// POST /auth/register
router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  
  const safeUsername = username.toLowerCase().trim();

  try {
    const [existing] = await db.query('SELECT id FROM users WHERE username = ?', [safeUsername]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Username already taken. Please choose another.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    // Bootstrap: if username is exactly 'admin', make them an admin automatically
    const isAdmin = safeUsername === 'admin' ? true : false;

    const [result] = await db.query(
      'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
      [safeUsername, hashedPassword, isAdmin]
    );

    const token = jwt.sign(
      { userId: result.insertId, username: safeUsername, isAdmin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.status(201).json({ token, username: safeUsername, isAdmin });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// POST /auth/login
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  
  const safeUsername = username.toLowerCase().trim();

  try {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [safeUsername]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const isAdmin = Boolean(user.is_admin);
    const token = jwt.sign(
      { userId: user.id, username: user.username, isAdmin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, username: user.username, isAdmin });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

module.exports = router;
