

const JwtStrategy = require('passport-jwt').Strategy,
      ExtractJwt  = require('passport-jwt').ExtractJwt,
      mongoose    = require('mongoose'),
      User        = mongoose.model('users'),
      secret      = require('../config/keys').key,
      opts        = {};
opts.jwtFromRequest = ExtractJwt.fromHeader('auth');
opts.secretOrKey = secret;


module.exports = passport =>{
    passport.use(
        new JwtStrategy(opts, (jwt_payload, done) => {
            User.findById(jwt_payload.id).then(user => {
                if(user)
                    return done(null, user);
                return done(null, false);
            }).catch(err => console.log(err));
        })
    );
}