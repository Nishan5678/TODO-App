const express = require('express');
const router = express.Router();
const db = require('../db');

// GET /admin/users - Get all users with their task counts
router.get('/users', async (req, res) => {
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
    
    // Map total_tasks to a regular number since COUNT() returns BIGINT
    const formattedUsers = users.map(user => ({
      ...user,
      total_tasks: Number(user.total_tasks),
      is_admin: Boolean(user.is_admin)
    }));

    res.json(formattedUsers);
  } catch (error) {
    console.error('Admin Fetch Users Error:', error);
    res.status(500).json({ error: 'Failed to fetch users.' });
  }
});

// DELETE /admin/users/:id - Delete a user and their tasks
router.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  
  // Prevent admin from deleting themselves
  if (parseInt(id) === req.userId) {
    return res.status(400).json({ error: 'You cannot delete your own admin account.' });
  }

  try {
    // Foreign key constraint might not cascade properly depending on MySQL version/settings,
    // so we manually delete their tasks first just to be safe.
    await db.query('DELETE FROM tasks WHERE user_id = ?', [id]);
    
    // Then delete the user
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

module.exports = router;