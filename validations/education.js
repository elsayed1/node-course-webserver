const validator = require('validator');
const isEmpty = require('./isempty');
const educationValidationErrors = body =>{
    let errors = {};
    if(isEmpty(body.school))
        errors.school = "School is required";
    if(isEmpty(body.degree))
        errors.degree = "Degree is required";
    if(isEmpty(body.fieldOfStudy))
        errors.fieldOfStudy = "Field of study is required";
    if(isEmpty(body.from))
        errors.from = "Start Date is required";
    return errors;
}
module.exports = educationValidationErrors;