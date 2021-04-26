const {Router} = require('express');
const router = Router();
const User = require('../models/User');
const Raspberry = require('../models/Raspi');
const jwt = require('jsonwebtoken');
const bcrypt = require("bcrypt");
const passport = require('../passport.js')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const jwtSecret = require('crypto').randomBytes(32)
const { session } = require('passport');


const saltRounds = 10;
var user_actual = new User();

router.post('/signup', async (req,res) => {
    const {email, username, password} = req.body;

    //Comprobar que no haya repeticiones en la DB
    var user = await User.findOne({email})
    if (user) return res.status(401).send("The email is already in use");
    user = await User.findOne({username})
    if (user) return res.status(401).send("The username is already in use");

    const newUser = new User({email, username, password});
    await newUser.save();

    res.status(200).send("The user has been created sucessfully");
})

router.post('/login',
 passport.authenticate('local', { failureRedirect: '/login', session: false }),
 (req,res) => { 
    res.cookie('auth', tokenize(req),{httpOnly:true, secure:true})
    res.redirect('/')
}
) 

app.get('/logout', (req,res) => {
    res.clearCookie('auth')
    res.redirect('/login')
})

app.post('/addRaspi',(req,res)=> {
	const {username,raspberry}=req.body;
	var u
})
/*router.get('/tasks', (req,res)=>{
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

    const {old_password, new_password1, new_password2} = req.body;
    const user = user_actual;
    console.log(user);
    
    if (new_password1 != new_password2) return res.status(401).send("The two new passwords do not match");

    user.comparePassword(old_password, function(err, isMatch){
        if (isMatch && isMatch == true){
            return res.status(401).send("The new password is the same as the old one");
        }
    });
    if (new_password1 == old_password) return res.status(401).send("The new password is the same as the old one");

    user.password = new_password1;
    await user.save();
    return res.status(200).send("Password changed successfully");
});
*/
module.exports = router;

