const createDOMPurify = require("dompurify");
const { JSDOM } = require("jsdom");

const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);


const sanitizeFields = (fields) => {
    return (req, res, next) => {
        if (!req.body || typeof req.body !== 'object') {
            return next();
        }
    }

    fields.forEach(field => {
        if (req.body.hasOwnProperty(field) && typeof req.body[field] === 'string') {
            req.body[field] = DOMPurify.sanitize(req.body[field], {
                ALLOWED_TAGS: [],
                ALLOWED_ATTR: []
            });
        }
    });

    next();
};

module.exports = {sanitizeFields};