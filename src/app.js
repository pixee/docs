import express from 'express';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

app.use(express.json());

const authorize = ((req, res, next) => {

    const auth = {login: process.env.DOCS_USER, password: process.env.DOCS_PASSWORD}

    // parse login and password from headers
    const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':')

    // Verify login and password are set and correct
    if (login && password && login === auth.login && password === auth.password) {
        // Access granted...
        return next()
    }

    // Access denied...
    res.set('WWW-Authenticate', 'Basic realm="401"') // change this if desired
    res.status(401).send('Authentication required.') // custom message
});

app.use('/', authorize);
app.use('/', express.static('build'));

app.listen(3000);