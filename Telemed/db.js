const mysql = require('mysql2/promise');
require('dotenv').config();

// Create a pool of connections
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

// Export the pool to be used elsewhere
module.exports = pool;
