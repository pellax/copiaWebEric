const express = require('express')
const app = express()
const cors = require('cors')
const passport = require('passport')
const cookieParser = require('cookie-parser')
const path = require('path');
const favicon = require('serve-favicon');
const logger = require('morgan');
const bodyParser = require('body-parser');

require('./database')
require('./config/passport');
app.use(cors())
app.use(express.json())
app.use(passport.initialize()) 
app.use(cookieParser())
app.use(require('./routes/user'))

app.listen(3000)
console.log('Server on port', 3000);
