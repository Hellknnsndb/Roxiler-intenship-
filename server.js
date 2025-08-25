const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();

const corsOptions = {
  origin: 'http://localhost:3000', // Allow only this origin
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allowed methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allowed headers
  credentials: true, // Allow cookies/auth headers (if needed)
  optionsSuccessStatus: 200 // Some legacy browsers choke on 204
};

app.use(cors(corsOptions));
app.use(bodyParser.json());

// DB Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) throw err;
    console.log('MySQL Connected');
});

// Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = decoded;  // { id, role }
        next();
    });
};

const isAdmin = (req, res, next) => {
    if (req.user.role !== 1) return res.status(403).json({ message: 'Admin access required' });
    next();
};

const isNormalUser = (req, res, next) => {
    if (req.user.role !== 2) return res.status(403).json({ message: 'Normal user access required' });
    next();
};

const isStoreOwner = (req, res, next) => {
    if (req.user.role !== 3) return res.status(403).json({ message: 'Store owner access required' });
    next();
};

// Auth Routes
app.post('/api/auth/register', (req, res) => {
    const { name, email, password, address } = req.body;
    // Validations
    if (name.length < 20 || name.length > 60) return res.status(400).json({ message: 'Name must be 20-60 chars' });
    if (address.length > 400) return res.status(400).json({ message: 'Address max 400 chars' });
    if (!/^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.{8,16})/.test(password)) return res.status(400).json({ message: 'Invalid password' });
    if (!/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ message: 'Invalid email' });

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ message: 'Error hashing password' });
        db.query('INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, 2)', [name, email, hash, address], (err, result) => {
            if (err) return res.status(400).json({ message: 'Email already exists or error' });
            res.status(201).json({ message: 'User registered' });
        });
    });
});

// backend/server.js (partial)
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ message: 'Invalid credentials' });
    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
      const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, role: user.role, name: user.name });
    });
  });
});
// User Routes (Admin)
app.post('/api/users/add', verifyToken, isAdmin, (req, res) => {
    const { name, email, password, address, role } = req.body;
    if (name.length < 20 || name.length > 60) return res.status(400).json({ message: 'Name must be 20-60 chars' });
    if (address.length > 400) return res.status(400).json({ message: 'Address max 400 chars' });
    if (!/^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.{8,16})/.test(password)) return res.status(400).json({ message: 'Invalid password' });
    if (!/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ message: 'Invalid email' });
    if (![1, 2, 3].includes(role)) return res.status(400).json({ message: 'Invalid role' });

    bcrypt.hash(password, 10, (err, hash) => {
        db.query('INSERT INTO users (name, email, password, address, role) VALUES (?, ?, ?, ?, ?)', [name, email, hash, address, role], (err) => {
            if (err) return res.status(400).json({ message: 'Email exists or error' });
            res.status(201).json({ message: 'User added' });
        });
    });
});

app.get('/api/users/dashboard', verifyToken, isAdmin, (req, res) => {
    db.query('SELECT COUNT(*) as totalUsers FROM users', (err, users) => {
        db.query('SELECT COUNT(*) as totalStores FROM stores', (err, stores) => {
            db.query('SELECT COUNT(*) as totalRatings FROM ratings', (err, ratings) => {
                res.json({
                    totalUsers: users[0].totalUsers,
                    totalStores: stores[0].totalStores,
                    totalRatings: ratings[0].totalRatings
                });
            });
        });
    });
});

app.get('/api/users/list', verifyToken, isAdmin, (req, res) => {
    const { name, email, address, role, sort = 'name', order = 'ASC' } = req.query;
    let query = 'SELECT id, name, email, address, role FROM users where 1=1';
    const params = [];
    if (name) { query += ' AND name LIKE ?'; params.push(`%${name}%`); }
    if (email) { query += ' AND email LIKE ?'; params.push(`%${email}%`); }
    if (address) { query += ' AND address LIKE ?'; params.push(`%${address}%`); }
    if (role) { query += ' AND role = ?'; params.push(role); }
    query += ` ORDER BY ${sort} ${order}`;
    console.log('query=',query)
    db.query(query, params, (err, results) => {
        if (err){
            console.log('err=',err)
            return res.status(500).json({ message: 'Error' });
        }
        res.json(results);
        console.log('results=',results)
    });
});

app.get('/api/users/:id', verifyToken, isAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT id, name, email, address, role FROM users WHERE id = ?', [id], (err, user) => {
        if (err || user.length === 0) return res.status(404).json({ message: 'User not found' });
        if (user[0].role === 3) {
            db.query('SELECT s.name as storeName, s.email as storeEmail, s.address as storeAddress FROM stores s WHERE s.owner_id = ?', [id], (err, store) => {
                user[0].storeDetails = store[0] || {};
                res.json(user[0]);
            });
        } else {
            res.json(user[0]);
        }
    });
});

app.put('/api/users/password', verifyToken, (req, res) => {
    if (req.user.role === 1) return res.status(403).json({ message: 'Admins cannot update password here' });
    const { oldPassword, newPassword } = req.body;
    if (!/^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.{8,16})/.test(newPassword)) return res.status(400).json({ message: 'Invalid new password' });

    db.query('SELECT password FROM users WHERE id = ?', [req.user.id], (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ message: 'User not found' });
        bcrypt.compare(oldPassword, results[0].password, (err, isMatch) => {
            if (!isMatch) return res.status(400).json({ message: 'Old password incorrect' });
            bcrypt.hash(newPassword, 10, (err, hash) => {
                db.query('UPDATE users SET password = ? WHERE id = ?', [hash, req.user.id], (err) => {
                    if (err) return res.status(500).json({ message: 'Error updating password' });
                    res.json({ message: 'Password updated' });
                });
            });
        });
    });
});

// Store Routes
app.post('/api/stores/add', verifyToken, isAdmin, (req, res) => {
    const { name, email, address, owner_id } = req.body;
    if (name.length > 60) return res.status(400).json({ message: 'Store name max 60 chars' });
    if (address.length > 400) return res.status(400).json({ message: 'Address max 400 chars' });
    if (!/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ message: 'Invalid email' });
    db.query('SELECT role FROM users WHERE id = ?', [owner_id], (err, result) => {
        if (err || result.length === 0 || result[0].role !== 3) return res.status(400).json({ message: 'Invalid or non-store-owner user' });
        db.query('INSERT INTO stores (name, email, address, owner_id) VALUES (?, ?, ?, ?)', [name, email, address, owner_id], (err) => {
            if (err) return res.status(400).json({ message: 'Email exists or error' });
            res.status(201).json({ message: 'Store added' });
        });
    });
});

app.get('/api/stores/admin-list', verifyToken, isAdmin, (req, res) => {
    const { name, email, address, sort = 'name', order = 'ASC' } = req.query;
    let query = 'SELECT s.id, s.name, s.email, s.address, AVG(r.rating) as rating FROM stores s LEFT JOIN ratings r ON s.id = r.store_id';
    const params = [];
    if (name) { query += ' WHERE s.name LIKE ?'; params.push(`%${name}%`); }
    if (email) { query += (name ? ' AND' : ' WHERE') + ' s.email LIKE ?'; params.push(`%${email}%`); }
    if (address) { query += (name || email ? ' AND' : ' WHERE') + ' s.address LIKE ?'; params.push(`%${address}%`); }
    query += ' GROUP BY s.id ORDER BY ? ?';
    params.push(sort, order);
    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: 'Error' });
        res.json(results);
    });
});

app.get('/api/stores', verifyToken, isNormalUser, (req, res) => {
    console.log('in stores')
    const { name, address, sort = 'name', order = 'ASC' } = req.query;
    let query = `SELECT s.id, s.name, s.address, AVG(r.rating) as overallRating, 
                 (SELECT rating FROM ratings WHERE user_id = ? AND store_id = s.id) as userRating 
                 FROM stores s LEFT JOIN ratings r ON s.id = r.store_id`;
    const params = [req.user.id];
    if (name) { query += ' WHERE s.name LIKE ?'; params.push(`%${name}%`); }
    if (address) { query += (name ? ' AND' : ' WHERE') + ' s.address LIKE ?'; params.push(`%${address}%`); }
    query += ' GROUP BY s.id ORDER BY ? ?';
    params.push(sort, order);
    db.query(query, params, (err, results) => {
        if (err) return res.status(500).json({ message: 'Error' });
        res.json(results);
    });
});

app.get('/api/stores/dashboard', verifyToken, isStoreOwner, (req, res) => {
    const storeIds = [];
    db.query('SELECT id FROM stores WHERE owner_id = ?', [req.user.id], (err, stores) => {
        if (err || stores.length === 0) return res.status(404).json({ message: 'No stores found' });
        storeIds.push(...stores.map(s => s.id));
        db.query('SELECT AVG(rating) as averageRating FROM ratings WHERE store_id IN (?)', [storeIds], (err, avg) => {
            db.query('SELECT s.id as storeId, s.name, u.id as userId, u.name as userName, u.email, r.rating FROM ratings r JOIN stores s ON r.store_id = s.id JOIN users u ON r.user_id = u.id WHERE s.owner_id = ?', [req.user.id], (err, raters) => {
                res.json({
                    averageRating: avg[0].averageRating || 0,
                    raters: raters
                });
            });
        });
    });
});

// Rating Routes
app.post('/api/ratings', verifyToken, isNormalUser, (req, res) => {
    const { storeId, rating } = req.body;
    console.log('req.body=',req.body)
    if (rating < 1 || rating > 5) return res.status(400).json({ message: 'Rating 1-5' });
    db.query('INSERT INTO ratings (user_id, store_id, rating) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE rating = ?', 
             [req.user.id, storeId, rating, rating], (err) => {
        if (err) return res.status(500).json({ message: 'Error submitting rating' });
        res.json({ message: 'Rating submitted' });
    });
});

app.listen(5000, () => console.log('Server running on port 5000'));