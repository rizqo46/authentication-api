const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/user.model.js');
const keys = require('./keys');

// passport.serializeUser((user, done) => {
//     done(null, user._id);
// });

// passport.deserializeUser((id, done) => {
//     if (user) {
//         User.findById(id).then((user) => {
//             done(null, user);
//         });
//     }
    
// });

passport.serializeUser((id_token, done) => {
    // console.log('serializeUser', accessToken);
    done(null,id_token);
});

passport.deserializeUser((id_token, done) => {
    //console.log('deserializeUser', accessToken);
    done(null, id_token);
    
});

passport.use(
    new GoogleStrategy({
        // options for google strategy
        callbackURL: '/google-auth/auth',
        clientID: keys.google.clientID,
        clientSecret: keys.google.clientSecret
    }, (accessToken, refreshToken, X ,profile, done) => {
        // passport callback function
        console.log('X = ', X.id_token);
        done(null, X.id_token);

        // User.findOne({googleID: profile.id}).then((currentUser) => {
        //     //console.log(currentUser);
        //     if(currentUser){
        //         console.log(currentUser, 'has login');
        //         done(null, currentUser);
        //     } else {
        //         //console.log('email', profile.emails[0].value);
        //         new User({
        //             googleID: profile.id,
        //             email: profile.emails[0].value,
        //             status: 'Active'
        //         }).save().then((newUser) => {
        //             // console.log('User baru dibuat: ', newUser);
        //             done(null, newUser);
        //         });
        //     }
        // });
    })
);