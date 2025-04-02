const redis = require('redis')

require('dotenv').config()

const redisClient = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
});

(async () => {
    try {
        redisClient.on('error', (err) => console.log('Redis client error:', err))
        redisClient.connect()
        console.log("Connect to Redis")
    } catch (err) {
        console.error("Error to connect Redis:", err)
        process.exit(1)
    }
})()

module.exports = redisClient