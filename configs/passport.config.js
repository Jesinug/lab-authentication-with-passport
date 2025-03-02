const user = require('../models/User.model')
const bcrypt = require('bcryptjs')
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;



module.exports = (app) => {
    passport.serializeUser((user, cb) => {
        cb(null, user._id) });
    passport.deserializeUser((id, cb) => {
        User.findById(id)
        .then(user => cb(null, user))
    .catch((error) => {
        cb(error)
    })

})    
passport.use(new LocalStrategy({ passReqToCallback : true }, (req, username, password, next) => {
    User.findOne({ username })
    .then(user => {
        if(!user) {
            return next(null, false, {errorMessage: "User or password incorrect"});
        }
        if(bcrypt.compareSync (password, user.password)) {
            return next(null, user);
        } else {
            return next(null, false, {errorMessage: "User or password incorrect"})        }
    })
    .catch(error => next(error))
}))
}