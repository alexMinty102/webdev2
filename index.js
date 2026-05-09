require('dotenv').config();

const express = require('express');
const session = require('express-session');
const {MongoStore} = require('connect-mongo');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

// ── MongoDB connection ────────────────────────────────────────────────────────
const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;
console.log(mongoUrl);

const client = new MongoClient(mongoUrl);
let userCollection;

async function connectDB() {
    await client.connect();
    const db = client.db(process.env.MONGODB_DATABASE);
    userCollection = db.collection('users');
    console.log('Connected to MongoDB');
}
connectDB().catch(console.error);


app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new MongoStore({
        mongoUrl: mongoUrl,
        collectionName: 'sessions',
        crypto: { 
            secret: process.env.MONGODB_SESSION_SECRET
        }
    }),
    cookie: { maxAge: 60 * 60 * 1000 } // 1 hour
}));

function isLoggedIn(req) {
    return req.session && req.session.authenticated;
}


app.get('/', (req, res) => {
    if (isLoggedIn(req)) {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>Home</title></head>
            <body>
                <h1>Hello, ${req.session.name}!</h1>
                <form method="GET" action="/members">
                    <button type="submit">Go to Members Area</button>
                </form>
                <form method="GET" action="/logout">
                    <button type="submit">Sign Out</button>
                </form>
            </body>
            </html>
        `);
    } else {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>Home</title></head>
            <body>
                <h1>Welcome</h1>
                <a href="/signup"><button>Sign up</button></a><br><br>
                <a href="/login"><button>Log in</button></a>
            </body>
            </html>
        `);
    }
});

app.get('/signup', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Sign Up</title></head>
        <body>
            <h2>create user</h2>
            <form method="POST" action="/signupSubmit">
                <input name="name" type="text" placeholder="name" required /><br><br>
                <input name="email" type="email" placeholder="email" required /><br><br>
                <input name="password" type="password" placeholder="password" required /><br><br>
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
    `);
});

app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().max(100).required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate({ name, email, password });
    if (error) {
        const msg = error.details[0].message;
        return res.send(`
            <!DOCTYPE html><html><head><title>Error</title></head><body>
            <p>${msg}</p>
            <a href="/signup">Try again</a>
            </body></html>
        `);
    }

    if (!name) {
        return res.send(`<!DOCTYPE html><html><body><p>Name is required.</p><a href="/signup">Try again</a></body></html>`);
    }
    if (!email) {
        return res.send(`<!DOCTYPE html><html><body><p>Please provide an email address.</p><a href="/signup">Try again</a></body></html>`);
    }
    if (!password) {
        return res.send(`<!DOCTYPE html><html><body><p>Password is required.</p><a href="/signup">Try again</a></body></html>`);
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name, email, password: hashedPassword });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Log In</title></head>
        <body>
            <h2>log in</h2>
            <form method="POST" action="/loginSubmit">
                <input name="email" type="email" placeholder="email" required /><br><br>
                <input name="password" type="password" placeholder="password" required /><br><br>
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
    `);
});

app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().max(100).required(),
        password: Joi.string().max(50).required()
    });

    const { error } = schema.validate({ email, password });
    if (error) {
        return res.send(`
            <!DOCTYPE html><html><body>
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
            </body></html>
        `);
    }

    const user = await userCollection.findOne({ email });

    if (!user) {
        return res.send(`
            <!DOCTYPE html><html><body>
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
            </body></html>
        `);
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.send(`
            <!DOCTYPE html><html><body>
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
            </body></html>
        `);
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;

    res.redirect('/members');
});

app.get('/members', (req, res) => {
    if (!isLoggedIn(req)) {
        return res.redirect('/');
    }

    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Members</title></head>
        <body>
            <h1>Hello, ${req.session.name}.</h1>
            <img src="/${randomImage}" alt="random image" style="max-width:400px;" /><br><br>
            <form method="GET" action="/logout">
                <button type="submit">Sign out</button>
            </form>
        </body>
        </html>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) => {
    res.status(404).send('Page not found - 404');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});