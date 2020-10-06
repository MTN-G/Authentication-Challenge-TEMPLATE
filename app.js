/* write your server code here */
const ACCESS_TOKEN_SECRET = 'matan'
const REFRESH_TOKEN_SECRET = 'shahar'
const express = require('express');
const app = express()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt') 

app.use(express.json());

const USERS = [
    {
        name: 'admin',
        email: 'admin@email.com',
        password: '$2b$10$ZkwWGWl2E53SI3CnxEbp7ubM79oGR3wUa.Ijt2F7hHOMqLdVA.kgG',
        isAdmin: true
    }
];

const INFORMATION = [
    {
        name: 'admin',
        info: 'admin info'
    }
];

let refreshTokens = []

let OPTIONSMETHOD = 
  [
    {method: "post", path: "/users/register", description: "Register, required: email, user, password", example: {email: "user@email.com", name: "user", password: "password"}},
    {method: "post", path: "/users/login", description: "Login, required: valid email and password", example: {email: "user@email.com", password: "password"}},
    {method: "post", path: "/users/token", description: "Renew access token, required: valid refresh token", example: {token: "\*Refresh Token\*"}},
    {method: "post", path: "/users/tokenValidate", description: "Access Token Validation, required: valid access token", example: {authorization: "Bearer \*Access Token\*"}},
    {method: "get", path: "/api/v1/information", description: "Access user's information, required: valid access token", example: {authorization: "Bearer \*Access Token\*"}},
    {method: "post", path: "/users/logout", description: "Logout, required: access token", example: {token: "\*Refresh Token\*"}},
    {method: "get", path: "/users/all", description: "Get users DB, required: Valid access token of admin user", example: {authorization: "Bearer \*Access Token\*"}}
  ]

app.options('/',(req, res) => {
  let RestOptions;
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    RestOptions = OPTIONSMETHOD.slice(0, 2)
    res.json(RestOptions)
  }
  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      RestOptions = OPTIONSMETHOD.slice(0, 3)
      res.json(RestOptions)
    } else req.decoded = decoded;
  })
  if (req.decoded.isAdmin) res.json(OPTIONSMETHOD)
  RestOptions = OPTIONSMETHOD.slice(0,6)
  res.json(RestOptions)
})

app.post('/users/register', async (req, res) => {
    if (USERS.some(user => user.email === req.body.email)) {
        res.status(409).send("user already exists")
    }
       const hashPassword = await bcrypt.hash(req.body.password, 10);

       const user = {
        email: req.body.email,
        name: req.body.name,
        password: hashPassword,
        isAdmin: req.body.isAdmin || false
        }
        const info = {
            name: req.body.name,
            info: `${req.body.name} info`
        }
        USERS.push(user)
        INFORMATION.push(info)
        res.status(201).json({message: "Register Success"}); 
     
})


app.post('/users/login', async (req, res) => {

    try {
        const currentUser = USERS.find(user => user.email === req.body.email);
        if (!currentUser) return  res.status(404).send("cannot find user")
     
        const validPass = await bcrypt.compare(req.body.password, currentUser.password)
        if (!validPass) return res.status(403).send("User or Password incorrect");

        const accessToken = jwt.sign(currentUser, ACCESS_TOKEN_SECRET, {expiresIn: '10s'});
        const refreshToken = jwt.sign(currentUser, REFRESH_TOKEN_SECRET);
        refreshTokens.push(refreshToken);

        const body = {
            accessToken: accessToken,
            refreshToken: refreshToken,
            userName: currentUser.name,
            isAdmin: currentUser.isAdmin
        }

        res.status(200).send(body) 
    } catch (e) {
        res.status(400).send(e)
    }
   
})

app.post('/users/logout', (req, res) => {
    const token = req.body.token
    if (!token) return res.sendStatus(400).json({message: 'Refresh Token Required'});
    if (!refreshTokens.some(rf => rf === token)) return res.status(400).json({ message: 'Invalid Refresh Token'})
    refreshTokens = refreshTokens.filter(rt => rt !== token)
    res.status(200).json({message: "User Logged Out Successfully"});
})


app.post('/users/tokenValidate',checkToken, (req, res) => {
    res.status(200).json({valid: true})
})

app.get('/api/v1/information',checkToken, (req, res) => {
    if (req.decoded.isAdmin) return res.status(200).json(INFORMATION);
    console.log(req.decoded.name)
    const userInfo = INFORMATION.filter(user => req.decoded.name === user.name);

    if (userInfo){
        res.status(200).json(userInfo);
    } else ({Authenticated: true, information: "none"});

})

app.get('/api/v1/users', checkToken, (req, res) => {
    if (req.decoded.isAdmin) return res.status(200).json(USERS);
    res.status(403).json({message: "Invalid Access Token"});
});

app.post('/users/token', (req, res) => {
    const token = req.body.token;
    if (!token) return res.status(401).json({message: "Refresh Token Required"});
    if (!refreshTokens.includes(token)) return res.status(403).json({message: "Invalid Refresh Token"});
    jwt.verify(token, REFRESH_TOKEN_SECRET, (err, decoded)=>{
        if (err) return res.status(403).json({message: "Invalid Refresh Token"});
        const user = { 
            name: decoded.name, 
            email: decoded.email, 
            password: decoded.password, 
            isAdmin: decoded.isAdmin 
          };
        const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, {expiresIn: '10s'});
        res.json({accessToken});
    })
});

app.get('/users/all',checkToken ,(req, res)=>{
    if (!req.decoded.isAdmin) return res.status(403).json({message: "Admin Premissions Required"});
    res.json(USERS)
});

function checkToken (req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({message: "Access Token Required"});
    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
      if (err) return res.status(403).json({message: "Invalid Access Token"});
      req.decoded = decoded;
    });
    next();
};

const unknownEndpoint = (req, res) => {
    res.status(404).send({ error: 'unknown endpoint' })
}

app.use(unknownEndpoint)

module.exports = app