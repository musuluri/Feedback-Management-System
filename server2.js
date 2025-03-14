const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const cors = require('cors');

const app = express();
const port = 5000;
const JWT_SECRET = 'your_jwt_secret'; // Replace with a secure key

app.use(bodyParser.json());
app.use(cors());

// Database connection pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'mohan@123', // Replace with your MySQL password
    database: 'feedback_system',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Event listener for pool errors
pool.on('error', (err) => {
    console.error('MySQL Pool Error:', err);
});

// Test the database connection
app.get('/test-db', async (req, res) => {
    try {
        const [result] = await pool.query('SELECT 1 + 1 AS solution');
        res.json({ message: 'Database connected!', solution: result[0].solution });
    } catch (error) {
        res.status(500).json({ message: 'Database connection failed', error: error.message });
    }
});

// User authentication
async function authenticateUser(username, password) {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return null;

    const user = rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    return isValidPassword ? user : null;
}

// Token generation
function generateToken(user) {
    return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
}

// Middleware to verify token
function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
}

// Routes
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;

    const [existingUsers] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsers.length > 0) return res.status(400).json({ message: 'Username already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, passwordHash]);

    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await authenticateUser(username, password);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ token });
});

// Updated /courses route
app.get('/courses', verifyToken, async (req, res) => {
    const userId = req.user.id;

    const [courses] = await pool.query(`
        SELECT c.id, c.name, c.description, c.image_url, c.languages, 
               COALESCE(f.feedback_given, 0) AS feedbackGiven
        FROM courses c
        LEFT JOIN feedback f ON c.id = f.course_id AND f.user_id = ?
    `, [userId]);

    res.json(courses);
});

app.post('/feedback', verifyToken, async (req, res) => {
    const { course_id, content_quality, presentation, understanding, engagement, satisfaction, feedback_text } = req.body;
    const userId = req.user.id;

    await pool.query(`
        INSERT INTO feedback (user_id, course_id, content_quality, presentation, understanding, engagement, satisfaction, feedback_text, feedback_given)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    `, [userId, course_id, content_quality, presentation, understanding, engagement, satisfaction, feedback_text]);

    res.status(201).json({ message: 'Feedback submitted successfully' });
});

app.post('/update-feedback-status', verifyToken, async (req, res) => {
    const { course_id } = req.body;
    const userId = req.user.id;

    await pool.query('UPDATE feedback SET feedback_given = 1 WHERE course_id = ? AND user_id = ?', [course_id, userId]);
    res.json({ message: 'Feedback status updated' });
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
