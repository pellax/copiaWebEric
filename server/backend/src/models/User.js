//const {Schema, model, Mongoose} = require('mongoose');
const mongoose = require('mongoose');
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy = require('passport-jwt').Strategy
var jwt = require('jsonwebtoken');
var crypto = require('crypto');


    SALT_WORK_FACTOR = 10;

 const userSchema = new mongoose.Schema({
     email: {type: String, required: true, unique: true},
     name: {type: String, required: true, unique: true},
     hash: String,
     salt: String
     });

 userSchema.pre('save', function(next){
    var user = this;

    //Only hash the password if it has been modified or is new
    if (!user.isModified('password')) return next();

    //Generate a Salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function(err,salt){
        if (err) return next(err);

        //Hash the password using the new salt
        bcrypt.hash(user.password, salt, function(err, hash){
            if (err) return next(err);

            //Overwrite the password with the hashed one
            user.password = hash;
            next();
        });
    });
 });
/*
 userSchema.methods.comparePassword = function (candidatePassword, callback){
     bcrypt.compare(candidatePassword, this.password, function(err,isMatch){
         if (err) return callback(err);
         callback(undefined, isMatch);
     });
 };
*/

userSchema.methods.setPassword = function(password){
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, 'sha512').toString('hex');
  };
 userSchema.methods.validPassword = function(password) {
    var hash = crypto.pbkdf2Sync(password, this.salt, 1000, 64, 'sha512').toString('hex');
    return this.hash === hash;
  };

 userSchema.methods.generateJwt = function() {
    var expiry = new Date();
    expiry.setDate(expiry.getDate() + 7);
  
    return jwt.sign({
      _id: this._id,
      email: this.email,
      name: this.name,
      exp: parseInt(expiry.getTime() / 1000),
    }, "MY_SECRET"); // DO NOT KEEP YOUR SECRET IN THE CODE!
  };
 
 //module.exports = model('User', userSchema);
