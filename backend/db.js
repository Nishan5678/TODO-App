const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'asddsa@10',
  database: 'todo_app'
});

module.exports = pool.promise();