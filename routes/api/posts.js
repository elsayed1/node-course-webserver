const express = require('express'),
      passport = require('passport');
      router  = express.Router();

// Custom Models
const User = require('../../models/User'),
      Post = require('../../models/Post');
// Validation Files
const postValidationErrors = require('../../validations/post');
// @route GET /api/posts
// @desc get all posts
// @access Public
router.get('/', (req, res) => {
    Post.find()
    .populate('user', ['name', 'email'])
    .populate({
        path: 'comments.user',
        select: ['name', 'email']
    })
    .sort({date: -1})
    .then(posts => {
        res.send(posts);
    }).catch(err => res.status(404).send(err));
})
// @route /api/posts/:id
// @desc Create new Post
// @access public
router.get('/:postid', (req, res) => {
    Post.findById(req.params.postid)
    .populate('user', ['name', 'email'])
    .populate({
        path: 'comments.user',
        select: ['name', 'email']
    })
    .then(post => {
        if(post){
            res.send(post)
        }else{
            res.status(404).send({
                nopost: 'There is no post with this id'
            })
        }
    }).catch(err => res.status(404).send({
        msg: 'There is not a valid id'
    }));
});
// @route /api/posts/createpost
// @desc Create new Post
// @access Private
router.post('/createpost', passport.authenticate('jwt', { session: false}), (req, res) => {
    const errors = postValidationErrors(req.body);
    if(Object.entries(errors).length === 0){
        const newPost = new Post({
            text: req.body.text,
            name: req.body.name,
            email: req.body.email,
            user : req.user._id
        });
        newPost.save().then(post => {
            res.send(post);
        });
    }else{
        res.status(400).send(errors);
    }
});
// @route DELETE /api/posts
// @desc Delete Specific post
// @access Private
router.delete('/:postid', passport.authenticate('jwt', { session: false}), (req, res) => {
    Post.findOneAndRemove({
        user: req.user._id,
        _id : req.params.postid
    }).then(post => {
        if(post){
            res.send({
                msg: 'post removed'
            })
        }
        else{
            res.status(404).send({
                nopost: 'There is no post in this id'
            })
        }
    }).catch(err => res.status(404).send({
        msg: 'Something error'
    }));
});
// @route POST /api/posts/like/:postid
// @desc Adding like
// @access Private
router.post('/like/:postid', passport.authenticate('jwt', { session: false}), (req, res) =>{
    Post.findById(req.params.postid)
    .populate('user', ['name', 'email'])
    .populate({
        path: 'comments.user',
        select: ['name', 'email']
    })
    .then(post => {
        if(post){
            if(!post.likes.find(like => String(like.user) === String(req.user._id))){
                post.likes.push({
                    user: req.user._id
                });
                post.save().then(post => res.send(post)).catch(err => res.status(404).send(err));
            }
            else
                res.send({
                    alreadyliked: 'user already like it'
                })
        }else{
            res.status(404).send({
                nopost: 'no post found for this id'
            })
        }
    }).catch( err => res.status(404).send(err));
});
// @route POST /api/posts/unlike/:postid
// @desc remove like
// @access Private
router.post('/unlike/:postid', passport.authenticate('jwt', { session: false}), (req, res) =>{
    Post.findById(req.params.postid)
    .populate('user', ['name', 'email'])
    .populate({
        path: 'comments.user',
        select: ['name', 'email']
    })
    .then(post => {
        if(post){
            const removedIndex = post.likes.findIndex(like => String(like.user) === String(req.user._id));
            if( removedIndex !== -1){
                post.likes.splice(removedIndex, 1);
                post.save().then(post => res.send(post)).catch(err => res.status(404).send(err));
            }
            else
                res.send({
                    alreadyliked: 'user already unlike it'
                })
        }else{
            res.status(404).send({
                nopost: 'no post found for this id'
            })
        }
    }).catch( err => res.status(404).send(err));
});
// @route GET /api/posts/comment/:postid
// @desc Add Comment
// @access Private
router.post('/comment/:postid', passport.authenticate('jwt', { session: false}), (req, res) => {
    Post.findById(req.params.postid)
    .then(post => {
        if(post){
            let newComment = {};
            if(req.body.text) newComment.text = req.body.text;
            else res.status(400).send({
                text: 'comment text is required'
            });
            newComment.user = req.user._id;
            post.comments.push(newComment);
            post.save()
            .then(post => {
                Post.findById(req.params.postid)
                .populate('user', ['name', 'email'])
                .populate({
                    path: 'comments.user',
                    select: ['name', 'email']
                }).then( post => res.send(post))
            })
            .catch(err => res.status(404).send(err));
        }else{
            res.status(404).send({
                nopost: 'no post found in this id'
            })
        }
    })
    .catch(err => res.status(400).send(err));
});
// @route GET /api/profile/comment/:postid
// @desc Delete Comment
// @access Private
router.delete('/comment/:postid/:comment_id', passport.authenticate('jwt', { session: false}), (req, res) => {
    Post.findById(req.params.postid)
    .populate('user', ['name', 'email'])
    .populate({
        path: 'comments.user',
        select: ['name', 'email']
    })
    .then(post => {
        if(post){
            const commentIndex = post.comments.findIndex(item => String(item._id) === req.params.comment_id);
            if(commentIndex !== -1){
                if(String(post.comments[commentIndex].user._id) === req.user.id ||
                   String(req.user.id) === String(post.user._id)){
                    post.comments.splice(commentIndex, 1);
                    post.save().then(post => res.send(post))
                    .catch(err => res.status(400).send(err));
                }else{
                    res.status(400).send({
                        auth: 'you are not authorized to this operation'
                    })
                }
                    
            }else{
                res.status(404).send({
                    nocomment: 'there is no comment in this id'
                })
            }
        }else{
            res.status(404).send({
                nopost: 'There is no post in this id'
            })
        }
    })
});
module.exports = router;