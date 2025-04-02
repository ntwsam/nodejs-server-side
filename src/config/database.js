const mysql = require('mysql2/promise')

require('dotenv').config()

const pool = mysql.createPool({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    port: process.env.MYSQL_PORT
});

(async () => {
    try {
        const connection = await pool.getConnection()
        const db = process.env.MYSQL_DATABASE
        connection.query(`CREATE DATABASE IF NOT EXISTS \`${db}\``)
        connection.query(`USE \`${db}\``)

        const table = `
        CREATE TABLE IF NOT EXISTS users(
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) UNIQUE NOT NULL,
        role ENUM('admin','user') NOT NULL);`
        connection.query(table)
        console.log("Connect to MySQL")
        connection.release()
    } catch (err) {
        console.error("Error to connect MySQL:", err)
    }
})()

module.exports = pool