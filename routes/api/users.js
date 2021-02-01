const express = require('express');

const bcryptjs = require('bcryptjs');

const jwt = require('jsonwebtoken');
const passport = require('passport');

const router = express.Router();

// Custom Models
const User = require('../../models/User');

// Custom Validations
const isRegisterValid = require('../../validations/registervalid');
const isLoginValid = require('../../validations/loginvalid');

// Relative Path /api/users
router.get('/', (req, res) => res.json({ msg: 'Users Works' }));

// Public Route
router.post('/register', async (req, res) => {
  const errors = isRegisterValid(req.body);
  if (errors) { return res.status(400).send(errors); }
  const user = await User.findOne({ email: req.body.email });
  if (user) { return res.status(400).send({ email: 'Email already exist' }); }
  const newUser = new User({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password1,
  });
  newUser
    .save()
    .then((user) => res.send(user))
    .catch((err) => res.status(400).send(err));
});

// Public Route
router.post('/login', async (req, res) => {
  const errors = isLoginValid(req.body);
  if (errors) { return res.status(400).send(errors); }
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(400).send({
      email: 'email not found',
    });
  }

  bcryptjs.compare(req.body.password, user.password, (err, success) => {
    if (!success) {
      return res.status(400).send({
        password: 'Password is incorrect',
      });
    }
    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
    };
    jwt.sign(
      payload,
      require('../../config/keys').key,
      { expiresIn: 3600 },
      (err, token) => {
        if (err) console.log(err);
        res.send({
          success: true,
          token,
        });
      },
    );
  });
});

// Private Route
router.get(
  '/current',
  passport.authenticate('jwt', { session: false }),
  (req, res) => {
    res.send(req.user);
  },
);

module.exports = router;
