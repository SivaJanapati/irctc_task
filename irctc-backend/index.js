const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const cors = require('cors');

const app = express();

app.use(express.json());
app.use(cors());

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '#Mysqlsiva12',
    database: 'irctc'
});

// Middleware to validate JWT token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send('No token provided');

    jwt.verify(token, 'secret', (err, decoded) => {
        if (err) return res.status(500).send('Failed to authenticate token');
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
}

// Middleware to protect admin endpoints with an API key
function protectAdminEndpoints(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== 'admin-api-key') return res.status(403).send('Forbidden');
    next();
}

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// User registration
app.post('/register', 
    body('username').notEmpty().isLength({ min: 4 }).withMessage('Username must be at least 4 characters long'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, password, role } = req.body;
        const hashedPassword = bcrypt.hashSync(password, 8);

        db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], (err) => {
            if (err) {
                console.error('Error registering user:', err);
                return res.status(500).send('Error registering user');
            }
            res.status(200).send('User registered successfully');
        });
    }
);

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err || results.length === 0) return res.status(401).send('User not found');
        
        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) return res.status(401).send('Invalid password');

        const token = jwt.sign({ id: user.id, role: user.role }, 'secret', { expiresIn: 86400 });
        res.status(200).send({ auth: true, token });
    });
});

// Add new train (Admin only)
app.post('/add-train', protectAdminEndpoints, (req, res) => {
    const { name, source, destination, totalSeats } = req.body;
    
    db.query('INSERT INTO trains (name, source, destination, totalSeats, availableSeats) VALUES (?, ?, ?, ?, ?)', 
        [name, source, destination, totalSeats, totalSeats], (err) => {
            if (err) {
                console.error('Error adding train:', err);
                return res.status(500).send('Error adding train');
            }
            res.status(200).send('Train added successfully');
        });
});

// Get seat availability
app.get('/availability', (req, res) => {
    const { source, destination } = req.query;
    if (!source || !destination) {
        return res.status(400).send('Source and destination are required');
    }

    db.query('SELECT * FROM trains WHERE source = ? AND destination = ?', [source, destination], (err, results) => {
        if (err) {
            console.error('Error fetching trains:', err);
            return res.status(500).send('Error fetching trains');
        }
        res.status(200).send(results);
    });
});

// Book a seat
app.post('/book-seat', verifyToken, (req, res) => {
    const { trainId } = req.body;

    db.query('SELECT availableSeats FROM trains WHERE id = ?', [trainId], (err, results) => {
        if (err || results.length === 0) return res.status(500).send('Error fetching train');
        
        const train = results[0];
        if (train.availableSeats > 0) {
            db.query('UPDATE trains SET availableSeats = availableSeats - 1 WHERE id = ?', [trainId], (err) => {
                if (err) return res.status(500).send('Error booking seat');

                db.query('INSERT INTO bookings (userId, trainId) VALUES (?, ?)', [req.userId, trainId], (err) => {
                    if (err) return res.status(500).send('Error saving booking');
                    res.status(200).send('Seat booked successfully');
                });
            });
        } else {
            res.status(400).send('No available seats');
        }
    });
});

// Get specific booking details
app.get('/booking/:id', verifyToken, (req, res) => {
    const bookingId = req.params.id;

    db.query('SELECT * FROM bookings WHERE id = ? AND userId = ?', [bookingId, req.userId], (err, results) => {
        if (err || results.length === 0) return res.status(500).send('Error fetching booking');
        res.status(200).send(results[0]);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app; // Export app for testing
