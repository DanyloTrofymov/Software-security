const uuid = require('uuid');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const port = 3000;
const jwt = require('jsonwebtoken');
const axios = require('axios');
const fs = require('fs');


dotenv.config();
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const GrantTypes = {
    PASSWORD: 'password',
    AUTHORIZATION_CODE: 'authorization_code',
    CLIENT_CREDENTIALS: 'client_credentials',
    IMPLICIT: 'implicit',
    REFRESH_TOKEN: 'refresh_token',
    PASSWORD_REALM: 'http://auth0.com/oauth/grant-type/password-realm',
};

app.get('/create-user', (req, res) => {
    return res.sendFile(path.join(__dirname + '/create-user.html'));
});

app.get('/', verifyToken, async (req, res) => {
    console.log(req.user)
    if (req.user) {
        res.json({
            username: req.user,
            exp: req.exp,
            logout: 'http://localhost:3000/logout'
        });
    }
})

app.get('/logout', (req, res) => {
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const { code } = req.body;
    console.log(code);
    if (code) {
        try {
            const response = await axios.post(`${process.env.API_URL}oauth/token`, {
                grant_type: GrantTypes.AUTHORIZATION_CODE,
                audience: process.env.AUDIENCE_URL,
                client_id: process.env.CLIENT_ID,
                client_secret: process.env.CLIENT_SECRET,
                code: code,
                redirect_uri: 'http://localhost:3000/'
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            })
            res.json({ access_token: response.data.access_token, refresh_token: response.data.refresh_token });
        }
        catch (error) {
            res.status(401).json({ error: error.response.data });
        }
    }
});

app.post('/api/create', async (req, res) => {
    const { email, password } = req.body;
    try {
        const response = await axios.post(`${process.env.API_URL}oauth/token`, {
            grant_type: GrantTypes.CLIENT_CREDENTIALS,
            audience: process.env.AUDIENCE_URL,
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });

        const response2 = await axios.post(`${process.env.AUDIENCE_URL}users`, {
            email: email,
            password: password,
            connection: 'Username-Password-Authentication'
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${response.data.access_token}`
            }
        });
        res.status(201).json({ message: 'User created' });
    } catch (error) {
        res.status(401).json({ error: error.response.data });

    }
});

app.post('/api/refresh', async (req, res) => {
    const { refresh_token } = req.body;
    try {
        const response = await axios.post(`${process.env.API_URL}oauth/token`, {
            grant_type: GrantTypes.REFRESH_TOKEN,
            audience: process.env.AUDIENCE_URL,
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            refresh_token: refresh_token,
            scope: 'offline_access',
            realm: 'Username-Password-Authentication',
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });
        res.json({ access_token: response.data.access_token, refresh_token: response.data.refresh_token });
    } catch (error) {
        res.status(401).json({ error: error.response.data });

    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

async function verifyToken(req, res, next) {
    const token = req.header('Authorization');

    if (!token) {
        return res.sendFile(path.join(__dirname + '/index.html'));
    }

    try {
        const privateKey = fs.readFileSync('private_key.pem', 'utf8');
        jwt.verify(token, privateKey, { algorithms: ['RS256'] }, async (err, decoded) => {
            if (err) {
                return res.sendFile(path.join(__dirname + '/index.html'));
            }

            const currentTimestampInSeconds = Math.floor(Date.now() / 1000);
            if (decoded.exp > currentTimestampInSeconds) {
                try {
                    const response = await axios.get(`${process.env.AUDIENCE_URL}users/${decoded.sub}`, {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    req.user = response.data.name;
                    req.exp = decoded.exp;
                } catch (error) {
                    console.log(error);
                }
            }
            next();
        });
    } catch (error) {
        console.error('Error reading private key file:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
}