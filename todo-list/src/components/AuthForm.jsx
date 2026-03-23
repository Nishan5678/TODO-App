import React, { useState } from 'react';
import './AuthForm.css';

function AuthForm({ onAuthSuccess }) {
  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const toggleMode = () => {
    setMode(prev => (prev === 'login' ? 'register' : 'login'));
    setError('');
    setUsername('');
    setPassword('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const endpoint = mode === 'login' ? '/auth/login' : '/auth/register';

    try {
      const response = await fetch(`http://localhost:5001${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || 'Something went wrong.');
        setLoading(false);
        return;
      }

      // Store token and call parent
      localStorage.setItem('auth_token', data.token);
      localStorage.setItem('auth_username', data.username);
      onAuthSuccess(data.token, data.username);
    } catch (err) {
      setError('Could not reach the server. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-wrapper">
      <div className="auth-bg-orb orb-1" />
      <div className="auth-bg-orb orb-2" />
      <div className="auth-bg-orb orb-3" />

      <div className="auth-card">
        <div className="auth-logo">
          <span className="auth-logo-icon">✅</span>
          <h1 className="auth-app-title">TODO LIST</h1>
        </div>

        <h2 className="auth-heading">
          {mode === 'login' ? 'Welcome back' : 'Create an account'}
        </h2>
        <p className="auth-subheading">
          {mode === 'login'
            ? 'Sign in to access your tasks'
            : 'Register to start managing your tasks'}
        </p>

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="auth-field">
            <label htmlFor="auth-username">Username</label>
            <input
              id="auth-username"
              type="text"
              placeholder="Enter your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              autoComplete="username"
            />
          </div>

          <div className="auth-field">
            <label htmlFor="auth-password">Password</label>
            <input
              id="auth-password"
              type="password"
              placeholder={mode === 'register' ? 'At least 6 characters' : 'Enter your password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            />
          </div>

          {error && (
            <div className="auth-error" role="alert">
              <span>⚠️</span> {error}
            </div>
          )}

          <button className="auth-submit-btn" type="submit" disabled={loading}>
            {loading ? (
              <span className="auth-spinner" />
            ) : mode === 'login' ? (
              'Sign In'
            ) : (
              'Create Account'
            )}
          </button>
        </form>

        <p className="auth-toggle-text">
          {mode === 'login' ? "Don't have an account?" : 'Already have an account?'}
          <button
            type="button"
            className="auth-toggle-btn"
            onClick={toggleMode}
          >
            {mode === 'login' ? ' Register' : ' Sign In'}
          </button>
        </p>
      </div>
    </div>
  );
}

export default AuthForm;