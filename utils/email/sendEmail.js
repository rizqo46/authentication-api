const nodemailer = require('nodemailer');
const ejs = require('ejs');
const fs = require('fs');
const path = require('path');
const keys = require('../../configs/keys');

const sendEmail = async (email, subject, payload, template) => {
  try {
    // create reusable transporter object using the default SMTP transport
    const transporter = nodemailer.createTransport({
     host: keys.email.host, 
     port: keys.email.port,
     auth: {
        user: keys.email.user,
        pass: keys.email.password, // naturally, replace both with your real credentials or an application-specific password
      },
    });

    const source = fs.readFileSync(path.join(__dirname, template), 'utf8');
    const compiledTemplate = ejs.compile(source);
    const options = () => {
      return {
        from: keys.email.user,
        to: email,
        subject: subject,
        html: compiledTemplate(payload),
      };
    };

    // Send email
    transporter.sendMail(options(), (error, info) => {
      if (error) {
        return error;
      } else {
        return res.status(200).json({
          success: true,
        });
      }
    });
  } catch (error) {
    return error;
  }
};

/*
Example:
sendEmail(
  'youremail@gmail.com,
  'Email subject',
  { name: 'Eze' },
  './templates/layouts/main.handlebars'
);
*/

module.exports = sendEmail;