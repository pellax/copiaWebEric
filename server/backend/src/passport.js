const bcrypt = require("bcrypt");
const User = require('../models/User');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy

passport.use('local',new LocalStrategy({
    emailField: 'email',
    passwordField: 'password'
},
    function(email, password, done){
        
        var user = await User.findOne({email});
        if (!user) res.status(401).send("The username doesn't exist or the password is incorrect");
        const isValidPass = bcrypt.compareSync(password, user.password);
        if(isValidPass)
        {
            const ret = {username: username, description: 'A nice user'}
            return done(null,ret)
        }
        return done(null, false)
    }
));
    
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
    