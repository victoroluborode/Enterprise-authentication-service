const jwt = require('jsonwebtoken');

const decodeJwt = (token) => {
    try {
        const decoded = jwt.decode(token);
        return decoded
     } catch (err) {
        console.error("JWT decode error:", err.message);
        return null;
    }
}

module.exports = {
    decodeJwt
};