import React, { useState, useEffect } from 'react';
import './Dashboard.css';
import API_BASE_URL from '../apiConfig';

function Dashboard({ token, handleLogout }) {
  const [stats, setStats] = useState({ total: 0, completed: 0, in_progress: 0, todo: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/tasks/stats`, {
          headers: {
             'Content-Type': 'application/json',
             Authorization: `Bearer ${token}`
          }
        });
        if (response.status === 401) { handleLogout(); return; }
        const data = await response.json();
        setStats(data);
        setLoading(false);
      } catch (error) {
        console.error('Failed to fetch stats:', error);
        setLoading(false);
      }
    };
    fetchStats();
  }, [token, handleLogout]);

  if (loading) return <div className="dashboard-loading">Loading Analytics...</div>;

  const completionPercent = stats.total > 0 ? Math.round((stats.completed / stats.total) * 100) : 0;

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Your Productivity Dashboard</h1>
        <p>Monitor your task progress and performance in real-time.</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon total-icon">📊</div>
          <h3>Total Tasks</h3>
          <div className="stat-value">{stats.total}</div>
        </div>
        
        <div className="stat-card">
          <div className="stat-icon todo-icon">📋</div>
          <h3>To Do</h3>
          <div className="stat-value">{stats.todo}</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon progress-icon">⚙️</div>
          <h3>In Progress</h3>
          <div className="stat-value">{stats.in_progress}</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon complete-icon">✅</div>
          <h3>Completed</h3>
          <div className="stat-value">{stats.completed}</div>
        </div>
      </div>

      <div className="progress-section">
        <h3>Overall Completion Rate</h3>
        <div className="progress-bar-bg">
          <div className="progress-bar-fill" style={{ width: `${completionPercent}%` }}>
            {completionPercent}%
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;