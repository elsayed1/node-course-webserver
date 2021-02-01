const isEmpty = require('./isempty');
const validator = require('validator');
const isLoginValid = user =>{
    let errors = {};
    if(isEmpty(user.email)){
        errors.email = "Email field is required"
    }
    else if(!validator.isEmail(user.email)){
        errors.email = "This is not a valid email";
    }
    if(isEmpty(user.password)){
        errors.password = "Password filed is required";
    }
    return isEmpty(errors) ? false : errors;
}
module.exports = isLoginValid;