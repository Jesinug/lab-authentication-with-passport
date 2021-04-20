const express = require('express');
const router = express.Router();
const user = require('../models/User.model')
const bcrypt = require('bcryptjs')
const passport = require('passport');
const saltRounds = 10;
const ensureLogin = require('connect-ensure-login');

//


const isLoggedOut = (req, res, next) => {
  if(req.authenticated()) {
    res.redirect('/private/profile');
  } else { next() };
}

router.get('/signup', isLoggedOut, (req, res) => {
  res.render('signup')
}) 

router.post('signup', (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) {
    res.render('signup', {errorMessage: "Username and password are required"})
  }
  User.findOne({ username })
  .then(user => {
    if(user) {
      res.render('signup', {errorMessage: "Username already exists"})  
    }
    const salt = bcrypt.genSaltSync(saltRounds);
    const hashPass = bcrypt.hashSync(password, salt);
    
    User.create({ username, password: hashPass})
    .then((newUser) => {
      req.login(newUser, (error) => {
        if(error) {
          next(error)
        } 
        return res.redirect('/private/profile')
      })
    })
  })
  .catch(error) => {
    (console.log(error))
    return res.render('signup', {errorMessage: "Server error. Try again"})
    }
})

  router.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render('passport/private', { user: req.user });
});

/* Middleware
isLoggedOut
isLoggedIn
*/



module.exports = router;
