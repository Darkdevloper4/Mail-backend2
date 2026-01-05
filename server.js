require('dotenv').config();
const express = require('express');
const mariadb = require('mariadb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// --- Database Connection Pool ---
const pool = mariadb.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    connectionLimit: 5
});

// --- Middleware: JWT Authentication ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// --- Routes: Authentication ---

// POST /auth/signup
app.post('/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    let conn;
    try {
        conn = await pool.getConnection();
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await conn.query(
            'INSERT INTO users (email, password) VALUES (?, ?)', 
            [email, hashedPassword]
        );
        
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email already exists' });
        }
        res.status(500).json({ error: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// POST /auth/login
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    let conn;
    try {
        conn = await pool.getConnection();
        const rows = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
        
        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, email: user.email }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// --- Routes: Mail System ---

// POST /mail/send
app.post('/mail/send', authenticateToken, async (req, res) => {
    const { to, subject, body } = req.body;
    
    if (!to || !subject || !body) {
        return res.status(400).json({ error: 'Recipient (to), subject, and body required' });
    }

    let conn;
    try {
        conn = await pool.getConnection();
        
        // 1. Find receiver ID by email
        const receiverRows = await conn.query('SELECT id FROM users WHERE email = ?', [to]);
        
        if (receiverRows.length === 0) {
            return res.status(404).json({ error: 'Recipient user not found' });
        }

        const receiverId = receiverRows[0].id;
        const senderId = req.user.id;

        // 2. Insert message
        await conn.query(
            'INSERT INTO messages (sender_id, receiver_id, subject, body) VALUES (?, ?, ?, ?)',
            [senderId, receiverId, subject, body]
        );

        res.status(201).json({ message: 'Mail sent successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// GET /mail/inbox
app.get('/mail/inbox', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const userId = req.user.id;

        // Join with users table to show sender email instead of ID
        const query = `
            SELECT m.id, u.email as sender, m.subject, m.body, m.created_at 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.receiver_id = ? 
            ORDER BY m.created_at DESC
        `;
        
        const rows = await conn.query(query, [userId]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// GET /mail/sent
app.get('/mail/sent', authenticateToken, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const userId = req.user.id;

        // Join with users table to show receiver email instead of ID
        const query = `
            SELECT m.id, u.email as receiver, m.subject, m.body, m.created_at 
            FROM messages m 
            JOIN users u ON m.receiver_id = u.id 
            WHERE m.sender_id = ? 
            ORDER BY m.created_at DESC
        `;
        
        const rows = await conn.query(query, [userId]);
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        if (conn) conn.release();
    }
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
