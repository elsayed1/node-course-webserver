
const mongoose = require('mongoose');


const postSchema = new mongoose.Schema({
    text: {
        type: String,
        required: true
    },
    name:{
        type: String
    },
    email:{
        type: String
    },
    likes:[
        {
            user:{
                type: mongoose.Schema.Types.ObjectId,
                ref: 'users'
            }
        }
    ],
    comments:[
        {
            user:{
                type: mongoose.Schema.Types.ObjectId,
                ref: 'users'
            },
            text:{
                type: String,
                required: true
            },
            date:{
                type: Date,
                default: Date.now
            }
        }
    ],
    date:{
        type: Date,
        default: Date.now
    },
    user:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'users'
    }
});

const Post = mongoose.model('posts', postSchema);
module.exports = Post;