const pool = require('../config/database')
const redisClient = require('../config/redis')
const { generateToken, verifyRefreshToken } = require('../service/jwt')
const bcrypt = require('bcryptjs')

// ⭐️ register
const register = async (req, res) => {
    try {
        const { email, password, role } = req.body
        if (!email || !password || !role) return res.status(400).json({ message: "Email, password and role are required" })

        const [existingEmail] = await pool.query("SELECT * FROM users WHERE email = ?", [email])
        if (existingEmail > 0) return res.status(400).json({ message: "Email is already used" })

        const hashedPassword = await bcrypt.hash(password, 10)
        const [user] = await pool.query("INSERT INTO users (email,password,role) VALUE (?,?,?)", [email, hashedPassword, role])
        res.status(201).json({
            message: "Register user successfully!",
            user: {
                id: user.insertId,
                email: email,
                role: role,
            }
        })
    } catch (err) {
        res.status(500).json({ message: "Error to register new user:", err })
    }
};

// ⭐️ login
const login = async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email || !password) return res.status(400).json({ message: "Email and password are required" })

        const [result] = await pool.query("SELECT * FROM users WHERE email = ?", [email])
        const user = result[0]
        if (!user) return res.status(400).json({ message: "User not found" })

        const checkPassword = await bcrypt.compare(password, user.password)
        if (!checkPassword) return res.status(401).json({ message: "Invalid credentials" })

        const checkStatus = await redisClient.get(String(user.id)) // ⭐️ check refreshtoken in redis
        if (checkStatus !== null) return res.status(400).json({ message: "This user is logged in" })

        const tokens = await generateToken(user)
        const accessToken = tokens.accessToken
        const refreshToken = tokens.refreshToken
        res.setHeader('Authorization', 'Bearer ' + accessToken) // ⭐️ add accesstoken in header Authorization
        await redisClient.set(String(user.id), refreshToken, 'EX', 604800) // ⭐️ keep refreshtoken in redis
        res.cookie('refreshToken', refreshToken, {    // ⭐️ set refreshtoken in cookie 
            httpOnly: true,
            path: "/",
            domain: "",
            secure: false,
            maxAge: 604800000
        })

        res.status(200).json({
            message: "Login successfully!",
            refreshToken: refreshToken
        })
    } catch (err) {
        res.status(500).json({ message: "Error to login:", err })
    }
};

// ⭐️ logout
const logout = async (req, res) => {
    try {
        const userID = req.user.id
        if (!userID) return res.status(400).json({ message: "User is not logged in" })

        const token = req.token
        if (!token) return res.status(400).json({ message: "User is not logged in" })

        await redisClient.del(String(userID)) // ⭐️ remove refreshtoken in redis
        await redisClient.set(token, 'blacklisted') // ⭐️ add accesstoken to blacklist
        res.removeHeader('Authorization') // ⭐️ remove header Authorization
        res.clearCookie('refreshToken', { // ⭐️ clear refreshtoken in cookie
            httpOnly: true,
            secure: false,
            path: "/",
            domain: "",
        })

        res.status(200).json({
            message: "Logout successfully!"
        })
    } catch (err) {
        res.status(500).json({ message: "Error to logout", err })
    }
};

// ⭐️ refresh
const refresh = async (req, res) => {
    try {
        const userID = req.user.id
        if (!userID) return res.status(400).json({ message: "User is not logged in" })

        const accessToken = req.token
        if (!accessToken) return res.status(400).json({ message: "User is not logged in" })

        const refreshToken = await redisClient.get(String(userID))
        if (!refreshToken) return res.status(400).json({ message: "Token is not found" })

        const decoded = await verifyRefreshToken(refreshToken)
        if (!decoded) return res.status(403).json({ message: "Invalid refresh token" })

        const tokens = await generateToken(decoded)
        const newAccessToken = tokens.accessToken
        const newRefreshToken = tokens.refreshToken
        res.setHeader('Authorization', 'Bearer ' + newAccessToken)
        await redisClient.set(accessToken, 'blacklisted') // ⭐️ add old accesstoken to blacklist
        await redisClient.set(String(userID), newRefreshToken, 'EX', 604800) // ⭐️ update refreshtoken in redis
        res.cookie('refreshToken', newRefreshToken, { // ⭐️ update refreshtoken in cookie
            httpOnly: true,
            path: "/",
            domain: "",
            secure: false,
            maxAge: 604800000
        })

        res.status(200).json({
            message: "Generate new token successfully!",
            refreshToken: newRefreshToken
        })
    } catch (err) {
        res.status(500).json({ message: "Error to generate new token", err })
    }
};

// ⭐️ protect
const protect = async (req, res) => {
    try {
        const userID = req.user.id
        if (!userID) return res.status(400).json({ message: "User is not logged in" })

        const result = await pool.query("SELECT * FROM users WHERE id = ?", [userID])
        const user = result[0]
        res.status(200).json({
            message: "Protect route accessed",
            user: {
                id: user[0].id,
                email: user[0].email,
                role: user[0].role
            }
        })
    } catch (err) {
        res.status(500).json({ message: "Error in the protect route:", err })
    }
};

// ⭐️ admin
const admin = async (req, res) => {
    try {
        const userID = req.user.id
        if (!userID) return res.status(400).json({ message: "User is not logged in" })

        const result = await pool.query("SELECT * FROM users WHERE id = ?", [userID])
        const user = result[0]
        res.status(200).json({
            message: "Admin route accessed",
            user: {
                id: user[0].id,
                email: user[0].email,
                role: user[0].role
            }
        })
    } catch (err) {
        res.status(500).json({ message: "Error in the admin route:", err })
    }
};

module.exports = { register, login, logout, refresh, protect, admin }