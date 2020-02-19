const envFile = process.env.NODE_ENV === 'test' ? '.env.test' : '.env';
require('dotenv').config({
	path: require('path').join(__dirname, envFile)
});

module.exports = {
	development: {
		client: 'pg',
		connection: process.env.DATABASE_URL
	},
	test: {},
	production: {
		client: 'pg',
		connection: process.env.DATABASE_URL
	}
};