const express = require('express');
const router = express.Router();
const db = require('../db');

// Get task statistics for the logged-in user (Dashboard)
router.get('/stats', async (req, res) => {
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
      todo: Number(stats.total || 0) - Number(stats.completed || 0) - Number(stats.in_progress || 0)
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// Get all tasks for the logged-in user
router.get('/', async (req, res) => {
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
router.post('/', async (req, res) => {
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
router.put('/:id', async (req, res) => {
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
router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM tasks WHERE id = ? AND user_id = ?', [id, req.userId]);
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

module.exports = router;