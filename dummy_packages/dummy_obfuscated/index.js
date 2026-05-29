// Appears to be a legitimate utility module
const https = require('https');
const os = require('os');

function getSystemInfo() {
    return {
        home: os.homedir(),
        env: process.env.PATH,
    };
}

// "Configuration loader" — actually an obfuscated eval payload
const _init = eval(Buffer.from(
    'Y29uc29sZS5sb2coJ0xvYWRpbmcgY29uZmlnLi4uJyk7',
    'base64'
));

module.exports = { getSystemInfo };
