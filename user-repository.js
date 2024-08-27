import DBLocal from 'db-local'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
    _id: { type: String, required: true },
    username: { type: String, required: true },
    password: { type: String, required: true }

})
export class UserRepository {
    static async create ({ username, password }) {
        if (typeof username !== 'string') throw new Error('username must be a string')
        if (password.length < 3) throw new Error('username must be 3 characters long')

        const user = User.findOne({ username })
        if (user) throw new Error('user already Exist')
        const id = crypto.randomUUID()
        const hashedPassword = await bcrypt.hash(password, 10)
        User.create({
            _id: id,
            username,
            password: hashedPassword
        }).save()
        return id
    }
    static async login ({ username, password }) {
        if (typeof password !== 'string') throw new Error('password must be a string')
        if (password.length < 6) throw new Error('password must be 6 characters long')
        const user = User.findOne({username})
        if (!user) throw new Error('user dont Exist')
        if (!password) throw new Error('Password cant be blank')
        const valid =await bcrypt.compare(password, user.password)
        if (!valid) throw new Error('password is invalid')
            const {password:_, ...publicUser} = user
        return publicUser

    }
}


class validation {
    static username(username) {
        if (typeof username !== 'string') throw new Error('username must be a string')
        if (password.length < 3) throw new Error('username must be 3 characters long')
    }
    static password(password) {
        if (typeof password !== 'string') throw new Error('password must be a string')
        if (password.length < 6) throw new Error('password must be 6 characters long')
    }

}