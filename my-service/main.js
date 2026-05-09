const express = require('express')
const db = require('./db')
const jwt = require('jsonwebtoken')
const bcr = require('bcryptjs')
const app = express()
const SECRET = process.env.SECRET || "Enot159753"
app.use(express.json())

const auth = (req, res, next) => {
    const authHeader = req.headers.authorization
    if (!authHeader) {
        return res.status(401).json({ error: "Missing auth header" })
    }
    const token = authHeader.split(" ")[1]
    if (!token) {
        return res.status(401).json({ error: "Wrong token format" })
    }
    try {
        const decoded = jwt.verify(token, SECRET)
        const user = db.prepare("SELECT id, username, email, role FROM user WHERE id = ?").get(decoded.id)
        
        if (!user) {
            return res.status(401).json({ error: "User not found" })
        }
        
        req.user = user
        next()
    } catch (error) {
        console.error(error)
        return res.status(401).json({ error: "Invalid token" })
    }
}

app.post('/api/auth/register', (req, res) => {
    const { username, email, password } = req.body

    if (!username || !email || !password) {
        return res.status(400).json({ error: "Все поля обязательны" })
    }

    try {
        const salt = bcr.genSaltSync(10)
        const hashedPassword = bcr.hashSync(password, salt)

        const query = db.prepare(
            "INSERT INTO user (username, email, password) VALUES (?, ?, ?)"
        ).run(username, email, hashedPassword)

        const newUser = db.prepare("SELECT id, username, email, role, createdAt FROM user WHERE id = ?")
            .get(query.lastInsertRowid)

        const token = jwt.sign({ id: newUser.id, role: newUser.role }, SECRET, { expiresIn: "24h" })

        res.status(201).json({ user: newUser, token })
    } catch (error) {
        console.error(error)
        if (error.message.includes("UNIQUE")) {
            return res.status(400).json({ error: "Username или email уже существуют" })
        }
        res.status(500).json({ error: "Ошибка регистрации" })
    }
})

app.post('/api/auth/register/butadmin', (req, res) => {

    const { username, email, password, role } = req.body;
    const allowedRole = role === 'admin' ? 'admin' : 'user';

    if (!username || !email || !password) {
        return res.status(400).json({ error: "Все поля обязательны" });
    }

    try {
        const salt = bcr.genSaltSync(10);
        const hashedPassword = bcr.hashSync(password, salt);
        const query = db.prepare(
            "INSERT INTO user (username, email, password, role) VALUES (?, ?, ?, ?)"
        ).run(username, email, hashedPassword, allowedRole);

        const newUser = db.prepare("SELECT id, username, email, role, createdAt FROM user WHERE id = ?")
            .get(query.lastInsertRowid);
        const token = jwt.sign({ id: newUser.id, role: newUser.role }, SECRET, { expiresIn: "24h" });

        res.status(201).json({ user: newUser, token });

    } catch (error) {
        console.error(error);
        if (error.message.includes("UNIQUE")) {
            return res.status(400).json({ error: "Username или email уже существуют" });
        }
        res.status(500).json({ error: "Ошибка регистрации" });
    }
});


app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body

    if (!email || !password) {
        return res.status(400).json({ error: "Email и пароль обязательны" })
    }

    try {
        const user = db.prepare("SELECT * FROM user WHERE email = ?").get(email)

        if (!user) {
            return res.status(401).json({ error: "Неверный email или пароль" })
        }

        const isValid = bcr.compareSync(password, user.password)

        if (!isValid) {
            return res.status(401).json({ error: "Неверный email или пароль" })
        }

        const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: "24h" })

        const { password: _, ...safeUser } = user

        res.status(200).json({ user: safeUser, token })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка входа" })
    }
})

app.get('/api/auth/profile/', auth, (req, res) => {
    console.log(req.user);

    try {
        const user = db.prepare("SELECT id, username, email, role FROM user WHERE id = ?").get(req.user.id)

        if (!user) {
            res.status(404).json({ error: "Ошибка некая" })
        }

        res.status(200).json(req.user)


    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка входа" })
    }
})

app.get('/api/books', (req, res) => {
    const { genre, author } = req.query

    let query = `
        SELECT b.*, u.username as added_by 
        FROM book b 
        LEFT JOIN user u ON b.createdBy = u.id
    `
    const params = []

    if (genre || author) {
        query += " WHERE "
        const conditions = []

        if (genre) {
            conditions.push("b.genre = ?")
            params.push(genre)
        }
        if (author) {
            conditions.push("b.author LIKE ?")
            params.push(`%${author}%`)
        }

        query += conditions.join(" AND ")
    }

    query += " ORDER BY b.createdAt DESC"

    try {

        const books = db.prepare(query).all(...params)

        res.status(200).json(books)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка получения книг" })
    }
})

app.get('/api/books/:id', (req, res) => {
    const { id } = req.params

    try {
        const book = db.prepare(`
            SELECT b.*, u.username as added_by 
            FROM book b 
            LEFT JOIN user u ON b.createdBy = u.id 
            WHERE b.id = ?
        `).get(id)

        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }

        const reviews = db.prepare(`
            SELECT r.*, u.username 
            FROM review r 
            JOIN user u ON r.userId = u.id 
            WHERE r.bookId = ?
            ORDER BY r.createdAt DESC
        `).all(id)

        res.status(200).json({ ...book, reviews })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка получения книги" })
    }
})

app.post('/api/books', auth, (req, res) => {
    const { title, author, year, genre, description } = req.body

    if (!title || !author) {
        return res.status(400).json({ error: "Название и автор обязательны" })
    }

    try {
        const query = db.prepare(`
            INSERT INTO book (title, author, year, genre, description, createdBy) 
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(title, author, year, genre, description, req.user.id)

        const newBook = db.prepare("SELECT * FROM book WHERE id = ?").get(query.lastInsertRowid)

        res.status(201).json(newBook)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка создания книги" })
    }
})

app.put('/api/books/:id', auth, (req, res) => {
    const { id } = req.params
    const { title, author, year, genre, description } = req.body

    try {
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(id)

        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }

        if (book.createdBy !== req.user.id && req.user.role !== "admin") {
            return res.status(403).json({ error: "Вы можете редактировать только свои книги" })
        }

        db.prepare(`
            UPDATE book 
            SET title = COALESCE(?, title), 
                author = COALESCE(?, author), 
                year = COALESCE(?, year), 
                genre = COALESCE(?, genre), 
                description = COALESCE(?, description)
            WHERE id = ?
        `).run(title, author, year, genre, description, id)

        const updatedBook = db.prepare("SELECT * FROM book WHERE id = ?").get(id)
        res.status(200).json(updatedBook)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка обновления книги" })
    }
})

app.delete('/api/books/:id', auth, (req, res) => {
    const { id } = req.params

    try {
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(id)

        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }

        if (book.createdBy !== req.user.id && req.user.role !== "admin") {
            return res.status(403).json({ error: "Вы можете удалять только свои книги" })
        }

        const query = db.prepare("DELETE FROM book WHERE id = ?").run(id)

        if (query.changes === 0) {
            return res.status(404).json({ error: "Книга не найдена" })
        }

        res.status(200).json({ message: "Книга удалена" })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка удаления книги" })
    }
})

// --- REVIEWS ЭНДПОИНТЫ ---
app.post('/api/books/:id/reviews', auth, (req, res) => {
    const bookId = req.params.id
    const { rating, comment } = req.body

    if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: "Оценка должна быть от 1 до 5" })
    }

    try {
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(bookId)

        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }

        const query = db.prepare(
            "INSERT INTO review (bookId, userId, rating, comment) VALUES (?, ?, ?, ?)"
        ).run(bookId, req.user.id, rating, comment)

        const newReview = db.prepare(`
            SELECT r.*, u.username 
            FROM review r 
            JOIN user u ON r.userId = u.id 
            WHERE r.id = ?
        `).get(query.lastInsertRowid)

        res.status(201).json(newReview)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка добавления отзыва" })
    }
})

app.get('/api/books/:id/reviews', (req, res) => {
    const { id } = req.params

    try {
        const reviews = db.prepare(`
            SELECT r.*, u.username 
            FROM review r 
            JOIN user u ON r.userId = u.id 
            WHERE r.bookId = ?
            ORDER BY r.createdAt DESC
        `).all(id)

        res.status(200).json(reviews)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка получения отзывов" })
    }
})

app.delete('/api/reviews/:id', auth, (req, res) => {
    const { id } = req.params

    try {
        const review = db.prepare("SELECT * FROM review WHERE id = ?").get(id)

        if (!review) {
            return res.status(404).json({ error: "Отзыв не найден" })
        }

        if (review.userId !== req.user.id && req.user.role !== "admin") {
            return res.status(403).json({ error: "Вы можете удалять только свои отзывы" })
        }

        const query = db.prepare("DELETE FROM review WHERE id = ?").run(id)

        if (query.changes === 0) {
            return res.status(404).json({ error: "Отзыв не найден" })
        }

        res.status(200).json({ message: "Отзыв удален" })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка удаления отзыва" })
    }
})



app.get('/api/admin/users', auth, (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Требуются права администратора" })
    }

    try {
        const users = db.prepare("SELECT id, username, email, role, createdAt FROM user").all()
        res.status(200).json(users)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка получения пользователей" })
    }
})

app.delete('/api/admin/users/:id', auth, (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Требуются права администратора" })
    }

    const { id } = req.params

    try {
        const user = db.prepare("SELECT * FROM user WHERE id = ?").get(id)

        if (!user) {
            return res.status(404).json({ error: "Пользователь не найден" })
        }

        const query = db.prepare("DELETE FROM user WHERE id = ?").run(id)

        if (query.changes === 0) {
            return res.status(404).json({ error: "Пользователь не найден" })
        }

        res.status(200).json({ message: "Пользователь удален" })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка удаления пользователя" })
    }
})

app.listen(3000, () => {
    console.log('Server is running on port 3000')
})