const express = require('express');
const passport = require('passport');

const router = express.Router();
// Custom Models
const Profile = require('../../models/Profile');
const User = require('../../models/User');
// Validation files
const profileValidationErrors = require('../../validations/profile');
const experienceValidationErrors = require('../../validations/experience');
const educatinoValidationErrors = require('../../validations/education');
// isEmpty File
const isEmpty = require('../../validations/isempty');
// @route get /api/profile/all
// @desc Get all profiles
// @access public
router.get('/all', (req, res) => {
  Profile
    .find().populate('user', ['name', 'email'])
    .then((profiles) => {
      res.send(profiles);
    })
    .catch((err) => res.status(400).send(err));
});
// @route GET /api/profile/handle/:handle
// @desc  Fetch a specific profile
// @access public
router.get('/handle/:handle', (req, res) => {
  Profile
    .findOne({ handle: req.params.handle })
    .populate('user', ['name', 'email'])
    .then((profile) => {
      if (profile) { res.send(profile); } else {
        res.status(404).send({
          notfound: 'This handle not found',
        });
      }
    })
    .catch((err) => res.status(400).send({ err }));
});
// @route GET /api/profile/handle/:handle
// @desc  Fetch a specific profile
// @access public
router.get('/user/:user_id', (req, res) => {
  Profile
    .findOne({ user: req.params.user_id })
    .populate('user', ['name', 'email'])
    .then((profile) => {
      if (profile) { res.send(profile); } else {
        res.status(404).send({
          notfound: 'There is not profile for this user',
        });
      }
    })
    .catch((err) => res.status(400).send({
      notfound: 'there is no user for this id',
    }));
});

// @route GET /api/profile
// @desc  Get Logged in user profile
// @access Private
router.get('/', passport.authenticate('jwt', { session: false }), (req, res) => {
  Profile
    .findOne({ user: req.user._id })
    .then((profile) => {
      if (profile) {
        res.send(profile);
      } else {
        res.status(404).send({
          noprofile: 'This user don\'t have a profile',
        });
      }
    })
    .catch((e) => res.status(400).send(e));
});

// @route POST /api/profile/createprofile
// @desc Create a new Profile
// @access Private
router.post('/createprofile', passport.authenticate('jwt', { session: false }), (req, res) => {
  const errors = profileValidationErrors(req.body);
  if (Object.entries(errors).length === 0) {
    const profileFields = {};
    profileFields.user = req.user._id;
    if (req.body.handle) { profileFields.handle = req.body.handle; }
    if (req.body.company) { profileFields.company = req.body.company; }
    if (req.body.website) { profileFields.website = req.body.website; }
    if (req.body.status) { profileFields.status = req.body.status; }
    if (req.body.website) { profileFields.website = req.body.website; }
    if (req.body.company) { profileFields.company = req.body.company; }
    // Skills split into elements
    if (typeof req.body.skills !== 'undefined') { profileFields.skills = req.body.skills.split(','); }
    // Social
    profileFields.social = {};
    if (req.body.gmail) { profileFields.social.gmail = req.body.gmail; }
    if (req.body.facebook) { profileFields.social.facebook = req.body.facebook; }
    if (req.body.twitter) { profileFields.social.twitter = req.body.twitter; }
    if (req.body.youtube) { profileFields.social.youtube = req.body.youtube; }
    if (req.body.bio) { profileFields.bio = req.body.bio; }
    if (req.body.githubusername) { profileFields.githubusername = req.body.githubusername; }
    if (req.body.social) { profileFields.social = req.body.social; }
    Profile
      .findOne({ user: req.user._id })
      .then((profile) => {
        if (profile) {
          // Updating
          Profile.findOne({ handle: profileFields.handle }).then((newprofile) => {
            if (newprofile && String(newprofile.user) !== String(req.user._id)) {
              res.status(400).send({
                handle: 'That handle already exists',
              });
            } else {
              Profile
                .findOneAndUpdate({ _id: profile.id }, profileFields, { new: true })
                .populate('user', ['name', 'email'])
                .then((updatedProfile) => {
                  res.send(updatedProfile);
                })
                .catch((err) => res.status(400).send(err));
            }
          });
        } else {
          const newProfile = new Profile(profileFields);
          newProfile.save().then((profile) => {
            res.send(profile);
          }).catch((err) => res.status(400).send(err));
        }
      })
      .catch((err) => res.status(400).send(err));
  } else {
    res.status(400).send(errors);
  }
});
// @router POST /api/profile/addexperience
// @desc Add Experience
// @access Private
router.post('/addexperience', passport.authenticate('jwt', { session: false }), (req, res) => {
  Profile
    .findOne({ user: req.user._id })
    .then((profile) => {
      if (profile) {
        const errors = experienceValidationErrors(req.body);
        const newexperience = {};
        if (Object.entries(errors).length === 0) {
          if (req.body.title) { newexperience.title = req.body.title; }
          if (req.body.company) { newexperience.company = req.body.company; }
          if (req.body.from) { newexperience.from = req.body.from; }
          if (!isEmpty(req.body.to)) { newexperience.to = req.body.to; }
          if (!isEmpty(req.body.current)) { newexperience.current = req.body.current; }
          if (req.body.location) { newexperience.location = req.body.location; }
          if (req.body.description) { newexperience.description = req.body.description; }
          profile.experience.unshift(newexperience);
          profile.save().then((profile) => res.send(profile))
            .catch((err) => res.status(400).send(err));
        } else {
          res.status(400).send(errors);
        }
      } else {
        res.status(404).send({
          noprofile: 'User do not have profile yet',
        });
      }
    });
});
// @route /api/profile/removeexperience
// @desc Remove Experience By Index
// @access GET
router.get('/removeexperience/:exp_id', passport.authenticate('jwt', { session: false }), (req, res) => {
  Profile.findOne({ user: req.user._id })
    .then((profile) => {
      if (profile) {
        const removedIndex = profile.experience.findIndex((item) => String(item._id) === req.params.exp_id);
        profile.experience.splice(removedIndex, 1);
        profile.save().then((profile) => res.send(profile))
          .catch((err) => res.status(404).send(err));
      } else {
        res.status(404).send({
          noprofile: 'This user do not have profile yet',
        });
      }
    });
});
// @route /api/profile/addeducation
// @desc  Add Education
// @access Private
router.post('/addeducation', passport.authenticate('jwt', { session: false }), (req, res) => {
  Profile.findOne({ user: req.user._id })
    .then((profile) => {
      if (profile) {
        const errors = educatinoValidationErrors(req.body);
        const newEducation = {};
        if (Object.entries(errors).length === 0) {
          if (req.body.school) { newEducation.school = req.body.school; }
          if (req.body.degree) { newEducation.degree = req.body.degree; }
          if (req.body.fieldOfStudy) { newEducation.fieldOfStudy = req.body.fieldOfStudy; }
          if (req.body.from) { newEducation.from = req.body.from; }
          if (!isEmpty(req.body.to)) { newEducation.to = req.body.to; }
          if (!isEmpty(req.body.current)) { newEducation.current = req.body.current; }
          if (req.body.description) { newEducation.description = req.body.description; }
          profile.education.unshift(newEducation);
          profile.save().then((profile) => res.send(profile))
            .catch((err) => res.status(400).send(err));
        } else {
          res.status(400).send(errors);
        }
      } else {
        res.status(404).send({
          noprofile: 'This user not have a profile yet',
        });
      }
    });
});
// @route /api/profile/removeexperience
// @desc Remove Experience By Index
// @access GET
router.get('/removeeducation/:edu_id', passport.authenticate('jwt', { session: false }), (req, res) => {
  Profile.findOne({ user: req.user._id })
    .then((profile) => {
      if (profile) {
        const removedIndex = profile.education.findIndex((item) => String(item._id) === req.params.edu_id);
        profile.education.splice(removedIndex, 1);
        profile.save().then((profile) => res.send(profile))
          .catch((err) => res.status(404).send(err));
      } else {
        res.status(404).send({
          noprofile: 'This user do not have profile yet',
        });
      }
    });
});
// @route /api/profile/delete
router.get('/delete', passport.authenticate('jwt', { session: false }), (req, res) => {
  Profile.findOneAndDelete({ user: req.user._id })
    .then((profile) => {
      User.findByIdAndDelete(req.user._id).then((user) => {
        res.send({
          msg: 'Successful Deleted',
        });
      }).catch((err) => res.status(404).send(err));
    })
    .catch((err) => res.status(404).send(err));
});
module.exports = router;
