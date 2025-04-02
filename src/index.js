const express = require('express')
const cors = require('cors')
const app = express()

const authRoute = require('./routes/auth.route')

app.use(express.json())
app.use(cors())


// ⭐️ route
app.use('/', authRoute)

app.get('/', (req, res) => {
    res.send('Hello,world')
})

const port = process.env.PORT || 3000
app.listen(port, () => {
    console.log(`server starting at http://localhost:${port}`)
})