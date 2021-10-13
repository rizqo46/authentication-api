const JWT = require('jsonwebtoken');

const User = require('../models/user.model');
const Token = require('../models/token.model');

const sendEmail = require('../utils/email/sendEmail');
const randomatic = require('randomatic');
const bcrypt = require('bcrypt');
const keys = require('../configs/keys');

const JWTSecret = keys.bcrypt.secret_key;
const saltRound = keys.bcrypt.saltRound;
const clientURL = process.env.CLIENT_URL;


const requestForgotPassword = async (email) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error('Email does not exist');

  let token = await Token.findOne({ userId: user._id });
  if (token) await token.deleteOne();

  let resetToken = randomatic('0', 6);
  const hash = await bcrypt.hash(resetToken, saltRound);

  await new Token({
    userId: user._id,
    token: hash,
    createdAt: Date.now(),
  }).save();

  // const link = `${clientURL}/passwordReset?token=${resetToken}&id=${user._id}`;

  sendEmail(
    user.email,
    'Password Reset Request',
    {
      name: user.email,
      link: resetToken,
    },
    './template/requestResetPassword.handlebars'
  );
  return resetToken;
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

  const hash = await bcrypt.hash(password, saltRound);

  await User.updateOne(
    { _id: userId },
    { $set: { password: hash } },
    { new: true }
  );

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

module.exports = {
  requestForgotPassword,
  resetPassword,
};