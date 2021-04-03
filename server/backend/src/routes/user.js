const {Router} = require('express');
const router = Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');

var actual_User = new User();

router.get('/', (req,res) => res.send('Hello World'))
router.post('/signup', async (req,res) => {
    const {email, username, password} = req.body;

    var user = await User.findOne({email})
    if (user) return res.status(401).send("The email is already in use");
    user = await User.findOne({username})
    if (user) return res.status(401).send("The username is already in use");

    const newUser = new User({email, username, password});
    await newUser.save();
    actual_User.username = username;
    actual_User.password = password;
    console.log(actual_User);
    const token = jwt.sign({_id: newUser._id}, 'secretKey')
    //res.status(200).json({token})

    return res.status(200).send("User created successfully");
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

router.post('/profile/modifypassword', verifyToken, async (req,res) => {
    console.log(actual_User);
    const {old_password, new_password1, new_password2} = req.body;
    if (old_password != actual_User.password) return res.status(401).send("The old password is incorrect");
    if (new_password1 != new_password2) return res.status(401).send("The two new passwords do not match");
    if (old_password == new_password1) return res.status(401).send("The new password is the same as the old one");
    
    const name = actual_User.username;
    const user = await User.findOne({name})


})
module.exports = router;

