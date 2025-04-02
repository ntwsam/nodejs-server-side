const express = require('express')
const { register, login, logout, refresh, protect, admin } = require('../controller/auth.controller')
const { authenticate, authorizeRole } = require('../middleware/auth.middleware')

const router = express.Router()


router.post('/register', register)
router.post('/login', login)
router.post('/logout', authenticate, logout)
router.post('/refresh', authenticate, refresh)
router.get('/protect', authenticate, protect)
router.get('/admin', authenticate, authorizeRole('admin'), admin)

module.exports = router