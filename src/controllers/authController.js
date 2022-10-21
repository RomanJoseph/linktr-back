import { connection } from "../db/db.js"
import { registerSchema, loginSchema } from "../schemas/authSchema.js"
import { v4 as uuid } from "uuid"
import jwt from "jsonwebtoken"
import dotenv from 'dotenv'
dotenv.config()
import bcrypt from "bcrypt"

async function register(req, res) {
    let { name, username, email, password, image } = req.body
    const isValid = registerSchema.validate({ name, username, email, password, image })

    if (isValid.error) {
        return res.sendStatus(422)
    }

    password = bcrypt.hashSync(password, 10)

    try {
        const query = await connection.query('INSERT INTO users (name, username, email, password, image) VALUES ($1,$2,$3,$4, $5);', [name, username, email, password, image])
        return res.sendStatus(201)

    } catch (error) {
        if (error.code === "23505") {
            return res.sendStatus(409)
        }
        console.log(error)
        return res.sendStatus(500)
    }
}

async function login(req, res){
    const { email, password } = req.body
    const secret = process.env.JWT_SECRET
    const config = { expiresIn: 60*60 }
    const isValid = loginSchema.validate({ email, password })
    const token = jwt.sign({ email, password }, secret, config)
    let user
    

    if (isValid.error) {
        return res.sendStatus(422)
    }

    try {
        const query = await connection.query('SELECT * FROM users WHERE email = $1;', [email])
        const isPasswordValid = bcrypt.compareSync(password, query.rows[0].password)
        user = {...query.rows[0], token}

        if (!isPasswordValid) {
            return res.sendStatus(401)
        }

    } catch (error) {
        console.log(error)
        return res.status(500).send(error)
    }

    try {
        console.log(user)
        const query = await connection.query('INSERT INTO sessions (token,"userId") VALUES ($1, $2);', [token, user.id])
        console.log(user)
        return res.send({user:user.id, name:user.name, username:user.username, image:user.image, token})
    } catch (error) {
        console.log(error)
        return res.status(500).send(error)
    }
}

export { register, login }