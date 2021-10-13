require('dotenv').config();
module.exports = {
	google: {
		clientID: process.env.clientID,
        clientSecret: process.env.clientSecret
	},
	bcrypt: {
		secret_key: 'SECRETKEY',
		saltRound: 10
	},
	mongodb: {
		URI: process.env.URI
	},
	email: {
		host: 'smtp.gmail.com',
        port: 465,
		user: process.env.user,
		password: process.env.pass
	},
	clientURL: 'http://localhost:3000/'
};