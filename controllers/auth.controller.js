const jwt = require('jsonwebtoken');
const randomatic = require('randomatic');
const {OAuth2Client} = require('google-auth-library');
const User = require('../models/user.model.js');
const Token = require('../models/token.model');

const sendEmail = require('../utils/email/sendEmail');
const keys = require('../configs/keys');
const bcrypt = require('bcrypt');

const maxAge = 60 * 1; // a minute

const createToken = (id) => {
    return jwt.sign({
        id
    }, keys.bcrypt.secret_key, {
        expiresIn: maxAge
    });
};

const createPIN = async (userId, reqType) => {
  let resetToken = randomatic('0', 6);
  const hash = await bcrypt.hash(resetToken, keys.bcrypt.saltRound);

  await new Token({
    userId: userId,
    token: hash,
    requestType: reqType,
    createdAt: Date.now()
  }).save();

  return resetToken
};

const handdleErrors = (err) => {
    // Only handdle for register
    let errors = {
        email: '',
        password: ''
    };

    if (err.code === 11000) {
        if (err.message.includes('email')) {
            errors.email = 'Email already registered'
        }
    }

    if (err.message.includes('User validation failed')) {
        // console.log(err);
        Object.values(err.errors).forEach(({
            properties
        }) => {
            errors[properties.path] = properties.message;
        });
    }

    return errors;
}



const requestForgotPassword = async (email) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error('Email does not exist');

  let token = await Token.findOne({ userId: user._id });
  if (token) await token.deleteOne();

  const PIN = createPIN(user._id, 'Forgot');

  sendEmail(
    user.email,
    'Password Reset Request',
    {
      email: user.email,
      PIN: resetPIN,
    },
    './template/requestForgotPassword.ejs'
  );
  return resetPIN;
};

const resetPassword = async (userId, token, password) => {
  let passwordResetToken = await Token.findOne({ userId });

  if (!passwordResetToken) {
    throw new Error('Invalid or expired password reset token');
  }

  const isValid = await bcrypt.compare(token, passwordResetToken.token);

  if (!isValid) {
    throw new Error('Invalid or expired password reset token');
  }

  await User.updateOne(
    { _id: userId },
    { $set: { password: password } }
  );
  

  // send email notif to user
  // const user = await User.findById({ _id: userId });

  // sendEmail(
  //   user.email,
  //   'Password Reset Successfully',
  //   {
  //     email: user.email,
  //   },
  //   './template/resetPassword.handlebars'
  // );

  await passwordResetToken.deleteOne();

  return true;
};


const register_post = async (req, res) => {
    const {email, password} = req.body;

    try {
        const user = await User.create({
            email,
            password
        });

        const PIN = await createPIN(user._id, 'Register');
        /// console.log(PIN);

         sendEmail(
            user.email,
            'Register Request',
            {
              email: user.email,
              PIN: PIN,
            },
            './template/requestRegister.ejs'
        );

        res.render('inputPIN', {
            title: 'InputPIN',
            email: user.email,
            message: "Don't have any account?",
            other: 'Register',
            link:'/register',
            path: '/input-pin'
        });

        //res.json(user);

    } catch (err) {
        // statements
        const errors = handdleErrors(err);
        res.status(401).json({
            errors
        });
    }

};

const inputPIN_post = async (req, res) => {
    const {email, PIN} = req.body;
    
    const user = await User.findOne({email});

    try {
        const mPIN = await Token.verify(user._id, PIN);
        const token = createToken(user._id);
        res.cookie('jwt', token, {
            httpOnly: true,
            maxAge: maxAge * 1000
        });
        user.status = 'Active';
        await user.save();
        res.json({user});
        mPIN.deleteOne();

    } catch (err) {
        // console.log(err.message);
        res.status(401).json({errors : err.message});
    }
};

const login_post = async (req, res) => {
    let {email, password} = req.body;
    const handdleLoginError = (err) => {
        if (err.message.includes('email')) {
            return {success: false, msg: err.message}
        }
        if (err.message.includes('password')) {
            return {success: false, msg: err.message}
        }
    };

    try {
        const user = await User.login(email, password);
        const token = createToken(user._id);
        res.cookie('jwt', token, {
            httpOnly: true,
            maxAge: maxAge * 1000
        });
        res.status(200)
           .json({success: true, 
                  msg: 'Login success'});

    } catch (err) {
        res.status(401)
           .json(handdleLoginError(err));
    }
};

const login_with_google = async (req, res) => {
    let profile = req.body;
    let googleID = profile.id;
    const handdleLoginGoogleError = (err) => {
        if (err.message.includes('GoogleID')) {
            return {success: false, msg: err.message}
        }
    };

    try {
        const user = await User.loginGoogle(googleID);
        const token = createToken(user._id);
        res.cookie('jwt', token, {
            httpOnly: true,
            maxAge: maxAge * 1000
        });
        res.status(200)
           .json({success: true, 
                  msg: 'Login success'});

    } catch (err) {
        res.status(401)
           .json(handdleLoginError(err));
    }
};
const google_auth = async (req, res) => {
    //res.json(req.user);
    // user = req.user;

    // try {
    //     const token = createToken(user._id);
    //     // res.redirect('/blog');
    //     res.cookie('jwt', token, {
    //         httpOnly: true,
    //         maxAge: maxAge * 1000
    //     });
    //     res.json(user);

    // } catch (err) {
    //     // console.log(err.message);
    //     res.status(401).send(err.message);
    // }
    const token = req.user
    //console.log('req user = ',req.user)

    const CLIENT_ID = keys.google.clientID

    const client = new OAuth2Client(CLIENT_ID);
    try {
      const ticket = await client.verifyIdToken({
          idToken: token,
          audience: CLIENT_ID,  // Specify the CLIENT_ID of the app that accesses the backend
          // Or, if multiple clients access the backend:
          //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
      });
      const payload = ticket.getPayload();
      // const userid = payload['sub'];
      // console.log(payload);
      // res.json(payload);

      User.findOne({$or: [
                    {googleID: payload['sub']},
                    {email: payload['email']}
                ]}).then((currentUser) => {
            //console.log(currentUser);
            if(currentUser){
                //console.log(currentUser, 'has login');
                res.json(currentUser);
            } else {
                //console.log('email', profile.emails[0].value);

                new User({
                    googleID: payload['sub'],
                    email: payload['email'],
                    status: 'Active'
                }).save().then((newUser) => {
                    // console.log('User baru dibuat: ', newUser);
                    res.json(newUser);
                });
            }
        });

      // If request specified a G Suite domain:
      // const domain = payload['hd'];
    }
    catch{console.error};

    

};

const changePassword_post = async (req, res) => {
    let {email, password} = req.body;
    password = await bcrypt.hash(password, keys.bcrypt.saltRound);

    try {
        await User.updateOne(
            { email: email },
            { $set: { password: password } }
          );
        res.json({message: "Your password has been changed"})

    } catch (err) {
        res.status(401).json({errors : err.message});
    }
};

const resetPassword_post = async (req, res) => {
    const {email, PIN} = req.body;

    try {
        const user = await User.findOne({email});
        const mPIN = await Token.verify(user._id, PIN);
        res.render('resetPassword', {
            title: 'Reset Password',
            email: user.email,
            path: '/change-password'
        });
        mPIN.deleteOne();

    } catch (err) {
        // console.log(err.message);
        res.status(401).json({errors : err.message});
    }
};

const forgotPassword_post = async (req, res) => {
    const {email} = req.body;
    user = await User.findOne({email});

    if (user) {
        const PIN = await createPIN(user._id, 'Forgot');

        await sendEmail(
            user.email,
            'Reset Password Request',
            {
              email: user.email,
              PIN: PIN,
            },
            './template/requestForgotPassword.ejs'
        );

        res.render('inputPIN', {
            title: 'InputPIN',
            email: user.email,
            message: "Don't have any account?",
            other: 'Register',
            link:'/register',
            path: '/reset-password'
        });
    } else {
        throw Error('Email not registered');
    }
    
};

const logout_get = (req, res) => {
    res.cookie('jwt', '', {maxAge: 1});
    res.redirect('/');
};

const forgotPassword_get = (req, res) => {
    res.render('forgotAuth', {
        title: 'Forgot Password',
        message: "Don't have any account?",
        other: 'Register',
        link:'/register',
        path: '/forgot-password'
    });
};

const register_get = (req, res) => {
    res.render('auth', {
        title: 'Sign up',
        message: 'Have an account?',
        other: 'Sign in',
        link:'/login',
        path: '/register'
    });
};

const login_get = (req, res) => {
    res.render('auth', {
        title: 'Sign in',
        message: "Don't have any account?",
        other: 'Sign up',
        link:'/register',
        path: '/login'
    });
};

const inputPIN_get = (req, res) => {
    res.render('inputPIN', {
        title: 'InputPIN',
        message: "Don't have any account?",
        other: 'Register',
        link:'/register',
        path: '/input-pin'
    });
};

module.exports = {
    register_get,
    register_post,
    login_get,
    login_post,
    logout_get,
    google_auth,
    forgotPassword_get,
    forgotPassword_post,
    inputPIN_get,
    inputPIN_post,
    changePassword_post,
    resetPassword_post,
    login_with_google
};