const {Router} = require('express');
const router = Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');

router.get('/', (req,res) => res.send('Hello World'))
router.post('/signup', async (req,res) => {
    const {email, password} = req.body;
    const newUser = new User({email, password});
    await newUser.save();
    
    const token = jwt.sign({_id: newUser._id}, 'secretKey')
    res.status(200).json({token})
})

router.post('/login', async (req,res) => {
    const {email, password} = req.body;
    const user = await User.findOne({email})
    if (!user || user.password != password) return res.status(401).send("The email doesn't exist or the password is incorrect");

    const token = jwt.sign({_id: user._id}, 'secretKey');
    return res.status(200).json({token});

})

router.get('/tasks', (req,res)=>{
    res.json([
        {
            _id:1,
            name: 'Task one',
            description: 'lorem ipsum',
            date: "2021-04-03T11:52:41.220Z"
        },
        {
            _id:2,
            name: 'Task two',
            description: 'lorem ipsum',
            date: "2021-04-03T11:52:41.220Z"
        },
        {
            _id:3,
            name: 'Task three',
            description: 'lorem ipsum',
            date: "2021-04-03T11:52:41.220Z"
        },
    ])
})

router.get('/private-tasks', verifyToken, (req,res)=>{
    res.json([
        {
            _id:1,
            name: 'Task one',
            description: 'lorem ipsum',
            date: "2021-04-03T11:52:41.220Z"
        },
        {
            _id:2,
            name: 'Task two',
            description: 'lorem ipsum',
            date: "2021-04-03T11:52:41.220Z"
        },
        {
            _id:3,
            name: 'Task three',
            description: 'lorem ipsum',
            date: "2021-04-03T11:52:41.220Z"
        },
    ])
})

function verifyToken(req, res, next){
    if (!req.headers.authorization){
        return res.status(401).send("Unauthorized Request");
    }
    const token = req.headers.authorization.split(' ')[1];
    if (token == null) return res.status(401).send("Unauthorized Request");
    const payload = jwt.verify(token, 'secretKey')
    req.userID = payload._id;
    next();
}

router.get('/profile', verifyToken, (req,res) =>{
    res.send(req.userID);
})
module.exports = router;