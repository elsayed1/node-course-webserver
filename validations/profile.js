
const validator = require('validator');
// Custom Function
const isEmpty = require('./isempty');
const profileValidationErrors = profile => {
    let errors = {};
    if(isEmpty(profile.handle))
        errors.handle = "Handle Must Be Exist";
    else if(!validator.isLength(profile.handle, {min: 4, max: 50}))
        errors.handle = "Handle must be between 4 and 50 characters";
    if(isEmpty(profile.skills))
        errors.skills = 'Skills Must Be Exist';
    if(!isEmpty(profile.company))
        if(!validator.isLength(profile.company,{min: 2, max: 100}))
            errors.company = "company name must be between 2 and 100 characters";
    if(isEmpty(profile.status))
        errors.status = "Status Must Be Exist";
    if(!isEmpty(profile.website))
        if(!validator.isURL(profile.website))
            errors.website = "website field is not a valid url";
    if(!isEmpty(profile.gmail))
        if(!validator.isURL(profile.gmail))
            errors.gmail = "gmail field is not a valid url";
    if(!isEmpty(profile.youtube))
        if(!validator.isURL(profile.youtube))
            errors.youtube = "youtube field is not a valid url";
    if(!isEmpty(profile.facebook))
        if(!validator.isURL(profile.facebook))
            errors.facebook = "facebook field is not a valid url";
    if(!isEmpty(profile.twitter))
        if(!validator.isURL(profile.twitter))
            errors.twitter = "twitter field is not a valid url";
    return errors;
}

module.exports = profileValidationErrors; 