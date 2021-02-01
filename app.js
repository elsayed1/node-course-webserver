// NPM Packages
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const passport = require('passport');

// Routes
const users = require('./routes/api/users');
const profile = require('./routes/api/profile');
const posts = require('./routes/api/posts');

// Default Settings
const app = express();
const port = process.env.PORT || 4000;
// mongodbURI = 'mongodb+srv://seko:seko@mernstackfronttoback-qiptm.mongodb.net/test?retryWrites=true';
const mongodbURI = require('./config/keys').MONGO_URI;
// mongodbURI = 'mongodb://localhost:27017/mernfronttoback'
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: false,
}));
app.use(cors());
mongoose
  .connect(mongodbURI, {
    useNewUrlParser: true,
  })
  .then(() => console.log('Mongodb connected'))
  .catch((err) => console.log(err));
app.use(passport.initialize());
require('./authentication/passport')(passport);
// Routes
app.use('/api/users', users);
app.use('/api/profile', profile);
app.use('/api/posts', posts);

if (process.env.NODE_ENV === 'production') {
  app.use(express.static('client/build'));
  const path = require('path');
  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
  });
}
app.listen(port, () => console.log(`listening on port ${port}`));
