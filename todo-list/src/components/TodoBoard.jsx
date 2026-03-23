import React, { useState, useEffect, useRef } from 'react';
import './TodoBoard.css';

const COLUMN = { TODO: 'todo', IN_PROGRESS: 'inProgress', COMPLETED: 'completed' };

function TodoBoard({ token, handleLogout }) {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const dateStr = now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  const [searchQuery, setSearchQuery] = useState('');
  const [tasks, setTasks] = useState([]);
  const [newTask, setNewTask] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [editIndex, setEditIndex] = useState(null);
  const [editText, setEditText] = useState('');
  const [editDescription, setEditDescription] = useState('');

  const authHeaders = () => ({
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  });

  useEffect(() => {
    if (token) fetchTasks();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  const fetchTasks = async () => {
    try {
      const response = await fetch('http://localhost:5001/tasks', { headers: authHeaders() });
      if (response.status === 401) { handleLogout(); return; }
      const data = await response.json();
      setTasks(data);
    } catch (error) {
      console.error('Error fetching tasks:', error);
    }
  };

  const addTask = async () => {
    if (newTask.trim() === '') { alert('Task cannot be empty'); return; }
    if (tasks.some(task => task.text === newTask)) { alert('Task already exists'); return; }
    try {
      const response = await fetch('http://localhost:5001/tasks', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ text: newTask, description: newDescription }),
      });
      const newTaskData = await response.json();
      setTasks(prev => [...prev, newTaskData]);
      setNewTask('');
      setNewDescription('');
    } catch (error) {
      console.error('Failed to add task:', error);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); addTask(); }
  };

  const toggleTask = async (index, taskId) => {
    const task = tasks[index];
    const newInProgress = (!task.inProgress && !task.in_progress && !task.completed) ? true : false;
    const newCompleted = (task.inProgress || task.in_progress) && !task.completed ? true : false;

    try {
      const response = await fetch(`http://localhost:5001/tasks/${taskId}`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({
          text: task.text,
          description: task.description,
          in_progress: newInProgress,
          completed: newCompleted
        })
      });

      if (response.ok) {
        setTasks(prev => prev.map((t, i) => {
          if (i !== index) return t;
          return { ...t, inProgress: newInProgress, in_progress: newInProgress, completed: newCompleted };
        }));
      }
    } catch (error) {
       console.error('Toggle error', error);
    }
  };

  const deleteTask = async (index, taskId) => {
    try {
      const response = await fetch(`http://localhost:5001/tasks/${taskId}`, {
        method: 'DELETE',
        headers: authHeaders()
      });
      if (response.ok) {
        setTasks(prev => prev.filter((_, i) => i !== index));
      }
    } catch (error) {
      console.error('Delete error', error);
    }
  };

  const clearCompletedTasks = () => {
    // Need to also call backend ideally, but keeping simple for UI
    setTasks(prev => prev.filter(task => !task.completed));
  };

  const startEditing = (index, text, description) => {
    setEditIndex(index);
    setEditText(text);
    setEditDescription(description);
  };

  const saveEdit = async (taskId) => {
    if (editText.trim() === '') { alert('Task cannot be empty'); return; }
    
    const task = tasks[editIndex];
    try {
       const response = await fetch(`http://localhost:5001/tasks/${taskId}`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({
          text: editText,
          description: editDescription,
          in_progress: task.inProgress || task.in_progress,
          completed: task.completed
        })
      });

      if (response.ok) {
        setTasks(prev => prev.map((t, i) =>
          i === editIndex ? { ...t, text: editText, description: editDescription } : t
        ));
        setEditIndex(null);
        setEditText('');
        setEditDescription('');
      }
    } catch (error) {
       console.error('Edit error', error);
    }
  };

  // ── Drag-and-Drop ──────────────────────────────────────────
  const dragIndex = useRef(null);
  const [dragOverCol, setDragOverCol] = useState(null);

  const handleDragStart = (index) => {
    dragIndex.current = index;
  };

  const handleDragOver = (e, col) => {
    e.preventDefault();
    setDragOverCol(col);
  };

  const handleDrop = async (e, targetCol) => {
    e.preventDefault();
    setDragOverCol(null);
    if (dragIndex.current === null) return;

    const idx = dragIndex.current;
    dragIndex.current = null;
    
    const task = tasks[idx];
    let newInProgress = false;
    let newCompleted = false;

    switch (targetCol) {
      case COLUMN.TODO:       newInProgress = false; newCompleted = false; break;
      case COLUMN.IN_PROGRESS: newInProgress = true;  newCompleted = false; break;
      case COLUMN.COMPLETED:  newInProgress = false; newCompleted = true;  break;
      default: return;
    }

    try {
      const response = await fetch(`http://localhost:5001/tasks/${task.id}`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({
          text: task.text,
          description: task.description,
          in_progress: newInProgress,
          completed: newCompleted
        })
      });

      if (response.ok) {
        setTasks(prev => prev.map((t, i) => {
          if (i !== idx) return t;
          return { ...t, inProgress: newInProgress, in_progress: newInProgress, completed: newCompleted };
        }));
      }
    } catch (error) {
      console.error('Drop error', error);
    }
  };

  const handleDragLeave = () => setDragOverCol(null);

  // ── Filtered tasks ─────────────────────────────────────────
  const q = searchQuery.toLowerCase();
  const filtered = tasks.filter(t =>
    t.text?.toLowerCase().includes(q) || t.description?.toLowerCase().includes(q)
  );

  const todoTasks       = filtered.filter(t => !t.inProgress && !t.in_progress && !t.completed);
  const inProgressTasks = filtered.filter(t => (t.inProgress || t.in_progress) && !t.completed);
  const completedTasks  = filtered.filter(t => t.completed);

  const globalIndex = (task) => tasks.indexOf(task);

  const renderTask = (task, col) => {
    const idx = globalIndex(task);
    return (
      <li
        key={idx}
        draggable
        onDragStart={() => handleDragStart(idx)}
        className={`draggable-task ${task.completed ? 'completed' : ''}`}
      >
        {editIndex === idx ? (
          <div className="edit-section">
            <input type="text" value={editText} onChange={(e) => setEditText(e.target.value)} />
            <textarea value={editDescription} onChange={(e) => setEditDescription(e.target.value)} />
            <button onClick={() => saveEdit(task.id)}>Save</button>
          </div>
        ) : (
          <div className="task-item">
            <div className="drag-handle" title="Drag to move">⠿</div>
            <label>
              <input type="checkbox" checked={task.completed} onChange={() => toggleTask(idx, task.id)} />
              <span className={task.completed ? 'task-done' : ''}>{task.text}</span>
            </label>
            <p>{task.description}</p>
            <div className="task-actions">
              <button onClick={() => startEditing(idx, task.text, task.description)}>Edit</button>
              <button onClick={() => deleteTask(idx, task.id)}>Delete</button>
            </div>
          </div>
        )}
      </li>
    );
  };

  const renderColumn = (title, colTasks, col, icon) => (
    <div
      className={`task-box ${dragOverCol === col ? 'drop-target' : ''}`}
      onDragOver={(e) => handleDragOver(e, col)}
      onDrop={(e) => handleDrop(e, col)}
      onDragLeave={handleDragLeave}
    >
      <h2>{icon} {title} <span className="task-count">{colTasks.length}</span></h2>
      <ul className="task-list">
        {colTasks.length === 0 && (
          <li className="empty-drop-hint">Drop tasks here</li>
        )}
        {colTasks.map(task => renderTask(task, col))}
      </ul>
    </div>
  );

  return (
    <div className="todo-container">
      {/* Calendar & Clock Widget */}
      <div className="clock-widget">
        <div className="clock-time">{timeStr}</div>
        <div className="clock-date">{dateStr}</div>
      </div>

      <h1>TODO-LIST</h1>

      {/* Search Bar */}
      <div className="search-bar-wrapper">
        <span className="search-icon">🔍</span>
        <input
          className="search-bar"
          type="text"
          placeholder="Search tasks..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        {searchQuery && (
          <button className="search-clear-btn" onClick={() => setSearchQuery('')}>✕</button>
        )}
      </div>

      {/* Add Task */}
      <div className="input-section">
        <input
          type="text"
          placeholder="Task title..."
          value={newTask}
          onChange={(e) => setNewTask(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <textarea
          placeholder="Task description..."
          value={newDescription}
          onChange={(e) => setNewDescription(e.target.value)}
        />
        <button onClick={addTask}>Add Task</button>
      </div>

      {/* Task columns */}
      <div className="task-box-container">
        {renderColumn('TODO',        todoTasks,        COLUMN.TODO,        '📋')}
        {renderColumn('In-Progress', inProgressTasks,  COLUMN.IN_PROGRESS, '⚙️')}
        {renderColumn('Completed',   completedTasks,   COLUMN.COMPLETED,   '✅')}
      </div>

      <button onClick={clearCompletedTasks} className="clear-completed-button">
        Clear Completed
      </button>
    </div>
  );
}

export default TodoBoard;