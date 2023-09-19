const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const JWT_SECRET = 'secret';

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
]

app.get('/', verifyToken, (req, res) => {
    res.json({
        username: req.user.username,
        logout: 'http://localhost:3000/logout'
    });
})

app.get('/logout', (req, res) => {
    res.redirect('/');
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => {
        return user.login === login && user.password === password;
    });

    if (user) {
        const token = jwt.sign({ username: user.username, login: user.login }, JWT_SECRET);

        res.json({ token });
    } else {
        res.status(401).send('Unauthorized');
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

function verifyToken(req, res, next) {
    const token = req.header('Authorization');

    if (!token) {
        return res.sendFile(path.join(__dirname + '/index.html'));
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.sendFile(path.join(__dirname + '/index.html'));
        }

        req.user = decoded;
        next();
    });
}