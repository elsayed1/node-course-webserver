const isEmpty = require('./isempty');
const validator = require('validator');
const isRegisterValid = user => {
    let errors = {};
    if(isEmpty(user.name))
        errors.name ='name field is required';
    else if(!validator.isLength(user.name, {min: 4, max: 30})){
        errors.name = "Name Must Be Between 4 and 30 Characters";
    }
    if(isEmpty(user.email)){
        errors.email = "Email Field is required"
    }
    else if(!validator.isEmail(user.email)){
        errors.email = "This is not a valid Email";
    } 
    if(isEmpty(user.password1)){
        errors.password1 = "password1 Field is required";
    }
    if(isEmpty(user.password2))
        errors.password2 = "password2 Field is required";
    else if(!isEmpty(user.password1)){
        if(!validator.equals(user.password1, user.password2))
            errors.password2 = "password 2 Must Match";
    }
    return errors;
}
module.exports = isRegisterValid;