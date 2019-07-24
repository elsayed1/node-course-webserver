
const isEmpty = require('./isempty');
const experienceValidationErrors = (body) => {
    let errors = {};
    if(isEmpty(body.title))
        errors.title = "Title is required";
    if(isEmpty(body.company))
        errors.company = "Company is reqired";
    if(isEmpty(body.from))
        errors.from = "Start Date is required";
    return errors;
}
module.exports = experienceValidationErrors;