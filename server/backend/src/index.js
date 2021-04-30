const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const bodyParser = require('body-parser');
const passport = require('passport')
require('./database')
const routes=require('./routes/user')

require('./config/passport');
app.use(cors())
app.use(express.json())
app.use(passport.initialize())
app.use(routes) 
app.use(cookieParser())
const app = express()
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
      res.status(401);
      res.json({"message" : err.name + ": " + err.message});
    }
  });
app.listen(3000)
console.log('Server on port', 3000);
