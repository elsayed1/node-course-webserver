const isEmpty = require('./isempty');
const validator = require('validator');
const postValidationErros = body => {
    let errors = {};
    if(isEmpty(body.text))
        errors.text = "post must have characters";
    else if(!validator.isLength(body.text, {min: 10, max: 300}))
        errors.text = "Text must be between 10 and 300 characters";
    return errors;
}

module.exports = postValidationErros;