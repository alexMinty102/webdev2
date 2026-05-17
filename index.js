require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { MongoClient } = require('mongodb');
const { default: MongoStore } = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

// ── MongoDB connection ────────────────────────────────────────────────────────
const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;

const client = new MongoClient(mongoUrl);
let userCollection;

async function connectDB() {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    userCollection = db.collection('users');
    console.log('Connected to MongoDB');
}
connectDB().catch(console.error);

// ── Middleware ────────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: mongoUrl,
        collectionName: 'sessions',
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        }
    }),
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

// ── Auth helpers ──────────────────────────────────────────────────────────────
function isLoggedIn(req) {
    return req.session && req.session.authenticated;
}

// Middleware: must be logged in
function requireLogin(req, res, next) {
    if (!isLoggedIn(req)) {
        return res.redirect('/login');
    }
    next();
}

// Middleware: must be admin
function requireAdmin(req, res, next) {
    if (!isLoggedIn(req)) {
        return res.redirect('/login');
    }
    if (req.session.user_type !== 'admin') {
        return res.status(403).render('403');
    }
    next();
}

// ── Routes ────────────────────────────────────────────────────────────────────

// Home
app.get('/', (req, res) => {
    res.render('index', {
        loggedIn: isLoggedIn(req),
        name: req.session.name || ''
    });
});

// Sign up – GET
app.get('/signup', (req, res) => {
    res.render('signup', { error: null });
});

// Sign up – POST
app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().max(100).required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate({ name, email, password });
    if (error) {
        return res.render('signup', { error: error.details[0].message });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name,
        email,
        password: hashedPassword,
        user_type: 'user'
    });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.user_type = 'user';

    res.redirect('/members');
});

// Log in – GET
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Log in – POST
app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().max(100).required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate({ email, password });
    if (error) {
        return res.render('login', { error: 'Invalid email/password combination.' });
    }

    const user = await userCollection.findOne({ email });

    if (!user) {
        return res.render('login', { error: 'Invalid email/password combination.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.render('login', { error: 'Invalid email/password combination.' });
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type || 'user';

    res.redirect('/members');
});

// Members – GET (login required)
app.get('/members', requireLogin, (req, res) => {
    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.render('members', { name: req.session.name, images, randomImage });
});

// Log out
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Admin – GET (admin only)
app.get('/admin', requireAdmin, async (req, res) => {
    const users = await userCollection.find({}).toArray();
    res.render('admin', { users, currentEmail: req.session.email });
});

// Promote user to admin (admin only)
app.get('/admin/promote/:email', requireAdmin, async (req, res) => {
    const schema = Joi.object({ email: Joi.string().email().max(100).required() });
    const { error } = schema.validate({ email: req.params.email });
    if (error) return res.redirect('/admin');

    await userCollection.updateOne(
        { email: req.params.email },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

// Demote user to regular user (admin only)
app.get('/admin/demote/:email', requireAdmin, async (req, res) => {
    const schema = Joi.object({ email: Joi.string().email().max(100).required() });
    const { error } = schema.validate({ email: req.params.email });
    if (error) return res.redirect('/admin');

    await userCollection.updateOne(
        { email: req.params.email },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

// 404 catch-all
app.use((req, res) => {
    res.status(404).render('404');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});