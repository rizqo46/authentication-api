const router = require('express').Router();
const authController = require('../controllers/auth.controller');
const passport = require('passport');

router.get('/register', authController.register_get);
router.get('/login', authController.login_get);
router.post('/register', authController.register_post);
router.post('/login', authController.login_post);
router.get('/logout', authController.logout_get);
router.get('/google-auth', passport.authenticate('google', {
    scope: ['profile', 'email']
}));
router.post('/login/google', authController.login_with_google)
router.get('/google-auth/auth', 
	passport.authenticate('google'), 
	authController.google_auth);
router.get('/forgot-password', authController.forgotPassword_get);
router.post('/forgot-password', authController.forgotPassword_post);
router.post('/reset-password', authController.resetPassword_post);
router.post('/change-password', authController.changePassword_post);
router.get('/input-pin', authController.inputPIN_get);
router.post('/input-pin', authController.inputPIN_post);


module.exports = router;