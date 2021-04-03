const express = require('express');
const app = express();

require('./database');

app.use(express.json());
app.use(require('./routes/login'))

app.listen(3000);
console.log('Server on port', 3000);