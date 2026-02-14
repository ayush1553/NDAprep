const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = './nda_platform.db';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('./')); // Serve frontend files from same server

// Database Initialization
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('DB Error:', err.message);
    else console.log('Connected to SQLite database.');
});

// Run Schema from schema.sql
const schema = fs.readFileSync('./schema.sql', 'utf8');
db.exec(schema, (err) => {
    if (err) {
        if (err.message.includes("already exists")) {
            console.log("Schema index/table already exists, skipping creation.");
        } else {
            console.error('Schema Error:', err.message);
        }
    } else {
        console.log('Database schema initialized.');
    }

    // Run Migrations regardless of schema initialization success
    runMigrations();
});

function runMigrations() {
    // Migration: Add role column if it doesn't exist
    db.run("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user'", (err) => {
        if (err && !err.message.includes("duplicate column name")) {
            console.error("Migration Error (role):", err.message);
        } else if (!err) {
            console.log("Migration: 'role' column added successfully.");
        }
    });

    // Migration: Add username column if it doesn't exist
    db.run("ALTER TABLE users ADD COLUMN username VARCHAR(100)", (err) => {
        if (err && !err.message.includes("duplicate column name")) {
            console.error("Migration Error (username):", err.message);
        } else if (!err) {
            console.log("Migration: 'username' column added successfully.");
        }
    });
}

// --- AUTH API ---

// 1. Check Email
app.get('/api/auth/check/:email', (req, res) => {
    const { email } = req.params;
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ exists: !!row, user: row ? { id: row.user_id, email: row.email, username: row.username } : null });
    });
});

// 2. Signup
app.post('/api/auth/signup', (req, res) => {
    const { email, password, username } = req.body;
    const userId = 'user_' + Date.now();
    const role = 'user';

    db.run('INSERT INTO users (user_id, email, username, password_hash, role) VALUES (?, ?, ?, ?, ?)',
        [userId, email, username, password, role], function (err) {
            if (err) return res.status(500).json({ error: 'Email already exists' });
            res.json({ id: userId, email, username, role });
        });
});

// 3. Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ? AND password_hash = ?', [email, password], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(401).json({ error: 'Invalid email or password' });
        res.json({ id: row.user_id, email: row.email, username: row.username, role: row.role });
    });
});

// --- ADMIN MIDDLEWARE ---
const isAdmin = (req, res, next) => {
    const adminEmail = req.headers['x-admin-email'];
    if (!adminEmail) return res.status(401).json({ error: 'Unauthorized' });

    db.get('SELECT role FROM users WHERE email = ?', [adminEmail], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row && row.role === 'admin') {
            next();
        } else {
            res.status(403).json({ error: 'Admin access required' });
        }
    });
};

// --- PERFORMANCE API ---

// 4. Save Attempt
app.post('/api/attempts', (req, res) => {
    const a = req.body;
    const attemptId = 'att_' + Date.now();

    db.run(`INSERT INTO test_attempts (
        attempt_id, user_id, test_id, test_type, subject, year, session,
        total_questions, attempted, correct, wrong, unattempted,
        score, max_score, accuracy, time_taken
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            attemptId, a.user_id, a.test_id, a.test_type, a.subject, a.year, a.session,
            a.total_questions, a.attempted, a.correct, a.wrong, a.unattempted,
            a.score, a.max_score, a.accuracy, a.time_taken
        ], function (err) {
            if (err) return res.status(500).json({ error: err.message });

            // Also save detailed results to a separate file or JSON column if needed.
            // For simplicity in this demo, we'll just store the main attempt summary in SQL.
            // If detailed results are huge, they could be saved to a JSON file indexed by attemptId.
            const detailPath = path.join(__dirname, 'data', 'details');
            if (!fs.existsSync(detailPath)) fs.mkdirSync(detailPath, { recursive: true });
            fs.writeFileSync(path.join(detailPath, `${attemptId}.json`), JSON.stringify(a.detailedResults));

            res.json({ id: attemptId, ...a });
        });
});

// 5. Get Attempts by User
app.get('/api/attempts/user/:userId', (req, res) => {
    db.all('SELECT * FROM test_attempts WHERE user_id = ? ORDER BY submitted_at DESC', [req.params.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// --- ADMIN API ---

// 7. Get All Users with Stats
app.get('/api/admin/users', isAdmin, (req, res) => {
    const sql = `
        SELECT 
            u.user_id, 
            u.email, 
            u.username,
            u.created_at,
            COUNT(a.attempt_id) as total_attempts,
            SUM(CASE WHEN a.test_type = 'PYQ' THEN 1 ELSE 0 END) as pyqs_attempted,
            SUM(CASE WHEN a.test_type = 'Mock' THEN 1 ELSE 0 END) as mocks_attempted,
            AVG(a.score) as avg_score,
            AVG(a.accuracy) as avg_accuracy,
            MAX(a.submitted_at) as last_attempt_date
        FROM users u
        LEFT JOIN test_attempts a ON u.user_id = a.user_id
        GROUP BY u.user_id
        ORDER BY u.created_at DESC
    `;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// 8. Get User History
app.get('/api/admin/user/:userId/attempts', isAdmin, (req, res) => {
    db.all('SELECT * FROM test_attempts WHERE user_id = ? ORDER BY submitted_at DESC', [req.params.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/attempts/id/:attemptId', (req, res) => {
    db.get('SELECT * FROM test_attempts WHERE attempt_id = ?', [req.params.attemptId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: 'Not found' });

        // Load details from file
        const detailFilePath = path.join(__dirname, 'data', 'details', `${req.params.attemptId}.json`);
        let detailedResults = [];
        if (fs.existsSync(detailFilePath)) {
            detailedResults = JSON.parse(fs.readFileSync(detailFilePath, 'utf8'));
        }

        res.json({ ...row, detailedResults });
    });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
