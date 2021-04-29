const {Router} = require('express');
const router = Router();
const User = require('../models/User');
const Raspberry = require('../models/Raspi');
const jwt = require('jsonwebtoken');
//const bcrypt = require("bcrypt");

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy


const jwtSecret = require('crypto').randomBytes(32)


/*passport.use('local',new LocalStrategy({
    emailField: 'email' ,
    passwordField:'password'
},
  async function(email, password, done){
        console.log(email)
        console.log(password)
        var user = await User.findOne({email});
        console.log(user)
        if (!user) res.status(401).json({message:"The username doesn't exist or the password is incorrect"});
        const isValidPass = bcrypt.compareSync(password, user.password);
        if(isValidPass)
        {
            const ret = {username: username, description: 'A nice user'}
            return done(null,ret)
        }
        return done(null, false)
    }
));
    */
/*passport.use('jwt', new JwtStrategy({
        jwtFromRequest: req => { return (req && req.cookies) ? req.cookies.auth : null },
        secretOrKey   : jwtSecret
    },  async (token, done) => { return done(null, (token) ? token.sub : false) }
));

tokenize = (req) => {
    const jwtClaims = {
        sub : req.user.username,
        iss : 'localhost:3000',
        aud : 'localhost:3000',
        exp : Math.floor(Date.now() / 1000) + 604800,   // 1 week (7×24×60×60=604800s) from now
        role: 'user'                                    // just to show a private JWT field
    }
    const token = jwt.sign(jwtClaims, jwtSecret);
    return token;
}*/
    


router.post('/signup', async (req,res) => {
    const {email, username, password} = req.body;

    //Comprobar que no haya repeticiones en la DB
    var user = await User.findOne({email})
    if (user) return res.status(401).json({message:'The email is already in use"'})//send(""");
    user = await User.findOne({username})
    if (user) return res.status(401).json({message:'The username is already in use'})//send("");

    const newUser = new User({email, username, password});
    await newUser.save();

    res.status(200).json({message:'ok'});
})

router.post('/login',
 passport.authenticate('local', { failureRedirect: '/login', session: false }),
 (req,res) => { 
    res.cookie('auth', tokenize(req),{httpOnly:true, secure:true})
    res.redirect('/')
}
) 

router.get('/logout', (req,res) => {
    res.clearCookie('auth')
    res.redirect('/login')
})

router.post('/addRaspi',(req,res)=> {
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

