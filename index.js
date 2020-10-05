/* write the code to run app.js here */
const express = require('express')
const app = express();
const router = require('./app')

app.use(express.json());

app.use('/', router);

app.listen(8080, () => console.log("Server Up and Running"))