require("dotenv").config();
const errorHandler = (err, req, res, next) => {
    console.error(err.stack);


    const statusCode = err.statusCode || 500;
    const message = err.message || 'An unexpected error occured';

    res.status(statusCode).json({
        status: 'error',
        statusCode: statusCode,
        message: message,
        stack: process.env.NODE_ENV === 'production' ? null : err.stack,
    });
};

module.exports = { errorHandler };