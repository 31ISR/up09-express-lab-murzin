const Database = require('better-sqlite3')

const db = new Database('database.db')

db.pragma('foreign_keys = ON')

db.exec(`
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS book (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        year INTEGER NOT NULL,
        genre TEXT NOT NULL,
        description TEXT NOT NULL,
        createdBy INTEGER,
        createdAt DATE DEFAULT CURRENT_DATE,
        FOREIGN KEY (createdBy) REFERENCES user(id) ON DELETE SET NULL
    );
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS review(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bookId INTEGER NOT NULL,
        userId INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
        comment TEXT,
        createdAt DATE DEFAULT CURRENT_DATE,
        FOREIGN KEY(bookId) REFERENCES book(id) ON DELETE CASCADE,
        FOREIGN KEY(userId) REFERENCES user(id) ON DELETE CASCADE
    );
`);
module.exports = db