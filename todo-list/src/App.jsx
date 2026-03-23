import React, { useState, useEffect } from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';
import AuthForm from './components/AuthForm';
import TodoBoard from './components/TodoBoard';
import Dashboard from './components/Dashboard';
import AdminPanel from './components/AdminPanel';

function App() {
  const [token, setToken] = useState(() => localStorage.getItem('auth_token') || null);
  const [username, setUsername] = useState(() => localStorage.getItem('auth_username') || '');
  const [isAdmin, setIsAdmin] = useState(() => localStorage.getItem('auth_is_admin') === 'true');
  const [theme, setTheme] = useState(() => localStorage.getItem('app_theme') || 'light');
  
  // 'board', 'dashboard', 'admin'
  const [currentView, setCurrentView] = useState('board');

  const handleAuthSuccess = (newToken, newUsername, newIsAdmin) => {
    setToken(newToken);
    setUsername(newUsername);
    setIsAdmin(newIsAdmin);
    localStorage.setItem('auth_is_admin', newIsAdmin);
    setCurrentView('board');
  };

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_username');
    localStorage.removeItem('auth_is_admin');
    setToken(null);
    setUsername('');
    setIsAdmin(false);
    setCurrentView('board');
  };

  useEffect(() => {
    if (theme === 'dark') {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
    localStorage.setItem('app_theme', theme);
  }, [theme]);

  if (!token) {
    return <AuthForm onAuthSuccess={handleAuthSuccess} />;
  }

  const renderView = () => {
    if (currentView === 'dashboard') return <Dashboard token={token} handleLogout={handleLogout} />;
    if (currentView === 'admin' && isAdmin) return <AdminPanel token={token} handleLogout={handleLogout} username={username} />;
    return <TodoBoard token={token} handleLogout={handleLogout} />;
  };

  return (
    <div className="App">
      {/* Dynamic Navbar with Tabs */}
      <div className="app-navbar">
        <div className="app-navbar-left">
          <span className="app-navbar-logo">✅ TODO-LIST</span>
          <div className="app-navbar-tabs">
            <button 
              className={`nav-tab ${currentView === 'board' ? 'active' : ''}`}
              onClick={() => setCurrentView('board')}
            >
              Tasks
            </button>
            <button 
              className={`nav-tab ${currentView === 'dashboard' ? 'active' : ''}`}
              onClick={() => setCurrentView('dashboard')}
            >
              Dashboard
            </button>
            {isAdmin && (
              <button 
                className={`nav-tab ${currentView === 'admin' ? 'active' : ''} admin-tab`}
                onClick={() => setCurrentView('admin')}
              >
                Admin Panel 👑
              </button>
            )}
          </div>
        </div>

        <div className="app-navbar-user">
          <button
            className="theme-toggle-btn"
            onClick={() => setTheme(prev => (prev === 'light' ? 'dark' : 'light'))}
          >
            {theme === 'light' ? '🌙 Dark' : '☀️ Light'}
          </button>
          <span className="app-navbar-greeting">👤 {username}</span>
          <button className="app-logout-btn" onClick={handleLogout}>Logout</button>
        </div>
      </div>

      {renderView()}
    </div>
  );
}

export default App;