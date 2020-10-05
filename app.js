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
]
const INFORMATION = [
    {
        user: 'admin',
        info: 'admin info'
    }
]
let refreshTokens = []

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
            user: req.body.name,
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

        const accessToken = jwt.sign(currentUser, ACCESS_TOKEN_SECRET, {expiresIn: '30s'});
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

app.post('/users/tokenValidate',checkToken, (req, res) => {
    res.status(200).json({valid: true})
})

app.get('/api/v1/information',checkToken, (req, res) => {
    if (req.decoded.isAdmin) return res.status(200).json(INFORMATION);
    console.log(req.decoded.name)
    const userInfo = INFORMATION.filter(x => req.decoded.name === x.user);
    console.log(userInfo)
    if (userInfo){
        res.status(200).json(userInfo);
    } else ({Authenticated: true, information: "none"});

})

app.get('/api/v1/users', checkToken, (req, res) => {
    if (req.decoded.isAdmin) return res.status(200).json(USERS);
    res.status(403).json({message: "Invalid Access Token"});
})

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
        const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, {expiresIn: '30s'});
        res.json({accessToken});
    
})})

app.get('/users/all',checkToken ,(req, res)=>{
    if (!req.decoded.isAdmin) return res.status(403).json({message: "Admin Premissions Required"});
    res.json(USERS)
  })

module.exports = app