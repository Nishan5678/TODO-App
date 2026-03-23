import React, { useState, useEffect } from 'react';
import './AdminPanel.css';

function AdminPanel({ token, handleLogout, username }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const fetchUsers = async () => {
    try {
      const response = await fetch('http://localhost:5001/admin/users', {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        }
      });
      if (response.status === 401 || response.status === 403) {
        // If not authorized, kick them out
        handleLogout();
        return;
      }
      const data = await response.json();
      setUsers(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch users:', error);
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId, targetUsername) => {
    if (targetUsername === username) {
      alert("You cannot delete your own admin account.");
      return;
    }
    
    if (!window.confirm(`Are you sure you want to permanently delete user "${targetUsername}" and all their tasks?`)) {
      return;
    }

    try {
      const response = await fetch(`http://localhost:5001/admin/users/${userId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${token}`
        }
      });

      if (response.ok) {
        // Remove from UI
        setUsers(users.filter(u => u.id !== userId));
      } else {
        const error = await response.json();
        alert(`Error: ${error.error}`);
      }
    } catch (error) {
       console.error('Delete error', error);
       alert('Network error while deleting user.');
    }
  };

  if (loading) return <div className="admin-loading">Loading Admin Panel...</div>;

  return (
    <div className="admin-container">
      <div className="admin-header">
        <h1>Admin Control Panel</h1>
        <p>Manage users and system data</p>
      </div>

      <div className="admin-table-wrapper">
        <table className="admin-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Role</th>
              <th>Total Tasks</th>
              <th>Joined Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map(user => (
              <tr key={user.id} className={user.username === username ? 'current-user-row' : ''}>
                <td>#{user.id}</td>
                <td className="admin-td-username">
                  {user.username} {user.username === username && <span className="you-badge">(You)</span>}
                </td>
                <td>
                  <span className={`role-badge ${user.is_admin ? 'role-admin' : 'role-user'}`}>
                    {user.is_admin ? 'Admin' : 'User'}
                  </span>
                </td>
                <td className="admin-td-tasks">{user.total_tasks}</td>
                <td>{new Date(user.created_at).toLocaleDateString()}</td>
                <td>
                  <button 
                    className="delete-user-btn" 
                    onClick={() => handleDeleteUser(user.id, user.username)}
                    disabled={user.username === username}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr>
                <td colSpan="6" className="no-users">No users found in database.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AdminPanel;