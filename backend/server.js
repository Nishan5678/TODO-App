const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

// Shared JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'todo_app_secret_key_2024';

// ── Auth middleware (inline instead of importing) ─────────────────────────────
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided. Please log in.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.isAdmin = decoded.isAdmin;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token. Please log in again.' });
  }
};

const adminAuthMiddleware = (req, res, next) => {
  if (!req.isAdmin) {
    return res.status(403).json({ error: 'Access denied. Administrator privileges required.' });
  }
  next();
};

// ── Auth routes ──────────────────────────────────────────────────────────────
const authRoutes = express.Router();

// POST /auth/register
authRoutes.post('/register', async (req, res) => {
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
authRoutes.post('/login', async (req, res) => {
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

// ── Task routes ──────────────────────────────────────────────────────────────
const taskRoutes = express.Router();

// Get task statistics for the logged-in user (Dashboard)
taskRoutes.get('/stats', async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN completed = 1 THEN 1 ELSE 0 END) as completed,
        SUM(CASE WHEN in_progress = 1 AND completed = 0 THEN 1 ELSE 0 END) as in_progress
      FROM tasks WHERE user_id = ?`,
      [req.userId]
    );

    const stats = rows[0];
    res.json({
      total: Number(stats.total || 0),
      completed: Number(stats.completed || 0),
      in_progress: Number(stats.in_progress || 0),
      todo: Number(stats.total || 0) - Number(stats.completed || 0) - Number(stats.in_progress || 0),
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Get all tasks for the logged-in user
taskRoutes.get('/', async (req, res) => {
  try {
    const [tasks] = await db.query(
      'SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC',
      [req.userId]
    );
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});

// Add new task for the logged-in user
taskRoutes.post('/', async (req, res) => {
  const { text, description } = req.body;
  try {
    const [result] = await db.query(
      'INSERT INTO tasks (text, description, user_id) VALUES (?, ?, ?)',
      [text, description, req.userId]
    );
    res.json({ id: result.insertId, text, description, completed: false, in_progress: false });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add task' });
  }
});

// Update task (only if owned by the logged-in user)
taskRoutes.put('/:id', async (req, res) => {
  const { id } = req.params;
  const { text, description, completed, in_progress } = req.body;
  try {
    await db.query(
      'UPDATE tasks SET text = ?, description = ?, completed = ?, in_progress = ? WHERE id = ? AND user_id = ?',
      [text, description, completed, in_progress, id, req.userId]
    );
    res.json({ message: 'Task updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// Delete task (only if owned by the logged-in user)
taskRoutes.delete('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM tasks WHERE id = ? AND user_id = ?', [id, req.userId]);
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// ── Admin routes ─────────────────────────────────────────────────────────────
const adminRoutes = express.Router();

// GET /admin/users - Get all users with their task counts
adminRoutes.get('/users', async (req, res) => {
  try {
    const [users] = await db.query(`
      SELECT 
        u.id, 
        u.username, 
        u.is_admin, 
        u.created_at,
        COUNT(t.id) as total_tasks
      FROM users u
      LEFT JOIN tasks t ON u.id = t.user_id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);

    const formattedUsers = users.map((user) => ({
      ...user,
      total_tasks: Number(user.total_tasks),
      is_admin: Boolean(user.is_admin),
    }));

    res.json(formattedUsers);
  } catch (error) {
    console.error('Admin Fetch Users Error:', error);
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// DELETE /admin/users/:id - Delete a user and their tasks
adminRoutes.delete('/users/:id', async (req, res) => {
  const { id } = req.params;

  if (parseInt(id, 10) === req.userId) {
    return res.status(400).json({ error: 'You cannot delete your own admin account.' });
  }

  try {
    await db.query('DELETE FROM tasks WHERE user_id = ?', [id]);

    const [result] = await db.query('DELETE FROM users WHERE id = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({ message: 'User and their tasks deleted successfully.' });
  } catch (error) {
    console.error('Admin Delete User Error:', error);
    res.status(500).json({ error: 'Failed to delete user.' });
  }
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Public auth routes
app.use('/auth', authRoutes);

// Protected task routes (require JWT)
app.use('/tasks', authMiddleware, taskRoutes);

// Protected admin routes (require Admin JWT)
app.use('/admin', authMiddleware, adminAuthMiddleware, adminRoutes);

const PORT = 5001;

// Auto-create tables if they don't exist
async function initDB() {
  try {
    console.log('DB instance in initDB:', typeof db, 'query type:', typeof db.query);
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Ensure tasks table exists before trying to alter it
    await db.query(`
      CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        text VARCHAR(255) NOT NULL,
        description TEXT,
        completed BOOLEAN DEFAULT FALSE,
        in_progress BOOLEAN DEFAULT FALSE,
        user_id INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);

    // Add user_id column to tasks if it doesn't already exist
    const [columns] = await db.query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tasks' AND COLUMN_NAME = 'user_id'
    `);
    if (columns.length === 0) {
      await db.query(`ALTER TABLE tasks ADD COLUMN user_id INT, ADD FOREIGN KEY (user_id) REFERENCES users(id)`);
      console.log('✅ Added user_id column to tasks table');
    }

    // Ensure users table actually has is_admin if it was created before this update
    const [userColumns] = await db.query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'is_admin'
    `);
    if (userColumns.length === 0) {
      await db.query(`ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE`);
      console.log('✅ Added is_admin column to users table');
    }

    console.log('✅ Database tables ready');
  } catch (err) {
    console.error('❌ Database initialization failed:', err.message);
    process.exit(1);
  }
}

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});