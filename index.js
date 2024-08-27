import express from 'express'
import { PORT, SECRET_KEY,REFRESH_SECRET_KEY } from './config.js'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
    const token = req.cookies.access_token
    req.session= { user: null}

    try {
        const data = jwt.verify(token, SECRET_KEY)
        req.session.user = data
    } catch {}
    next()
})

app.get('/', (req, res) => {
   const {user} = req.session
        res.render('home', user)
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body
    try {
        const user = await UserRepository.login({ username, password })
        const token = jwt.sign(
            { id: user._id, username: user.username },
            SECRET_KEY,
            { expiresIn: '1hr' })
        res
            .cookie('access_token', token, {
                httpOnly: true,
                // secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60
            })
            .send({ user, token })
    } catch (error) {
        res.status(401).send(error.message)
    }
})

app.post('/register', async (req, res) => {
    const { username, password } = req.body
    try {
        const id = await UserRepository.create({ username, password })
        res.send({ id })
    } catch (error) {
        res.status(400).send(error.message)
    }
})
app.post('/logout', (req, res) => {
    res.clearCookie('access_token')
    .clearCookie('refresh_token').json({message:'logout successful'})
})

app.get('/protected', (req, res) => {
    const {user}= req.session
    if (!user) return res.status(403).send('access not authorized')
        res.render('protected', user)
 
})

app.post('/refresh-token', (req, res) => {
    const refreshToken = req.cookies.refresh_token
    if (!refreshToken) return res.status(401).send('Refresh token not found')

    try {
        const userData = jwt.verify(refreshToken, REFRESH_SECRET_KEY)

        const newAccessToken = jwt.sign(
            { id: userData.id, username: userData.username },
            SECRET_KEY,
            { expiresIn: '1hr' }
        )

        res
            .cookie('access_token', newAccessToken, {
                httpOnly: true,
                sameSite: 'strict',
                maxAge: 1000 * 60 * 60 // 1 hour
            })
            .send({ accessToken: newAccessToken })
    } catch (error) {
        res.status(403).send('Invalid refresh token')
    }
})

app.listen(PORT, () => {
    console.log(`server running on port'${PORT}`)
})
