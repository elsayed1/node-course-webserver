
const mongoose = require('mongoose'),
      bcryptjs = require('bcryptjs');

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email:{
        type: String,
        required: true
    },
    password:{
        type: String,
        required: true
    },
    date:{
        type: Date,
        default: Date.now
    }
});
userSchema.pre('save', function(next){
    const user = this;
    bcryptjs.genSalt(10, (err, salt) => {
        bcryptjs.hash(user.password, salt, (err, hashed) => {
            if(err) throw err;
            user.password = hashed;
            next();
        });
    });
})
const User = mongoose.model('users', userSchema);
module.exports = User;