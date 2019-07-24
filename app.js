// NPM Packages
const express = require("express"),
  mongoose = require("mongoose"),
  bodyParser = require("body-parser"),
  cors = require("cors"),
  passport = require("passport"),
  path = require("path");
// Routes
const users = require("./routes/api/users"),
  profile = require("./routes/api/profile"),
  posts = require("./routes/api/posts");
// Default Settings
const app = express(),
  port = process.env.PORT || 5000,
  //mongodbURI = 'mongodb+srv://seko:seko@mernstackfronttoback-qiptm.mongodb.net/test?retryWrites=true';
  mongodbURI = require("./config/keys").MONGO_URI;
//mongodbURI = 'mongodb://localhost:27017/mernfronttoback'
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());
mongoose
  .connect(mongodbURI, { useNewUrlParser: true })
  .then(() => console.log("Mongodb connected"))
  .catch(err => console.log(err));
app.use(passport.initialize());
require("./authentication/passport")(passport);
// Routes
app.use("/api/users", users);
app.use("/api/profile", profile);
app.use("/api/posts", posts);

if (process.env.NODE_ENV === "production") {
  app.use(express.static("client/build"));
  const path = require("path");
  app.get("*", (req, res) => {
    res.sendFile(path.resolve(__dirname, "client", "build", "index.html"));
  });
}

// serve static assets if in production
if (process.env.NODE_ENV === "production") {
  // set static folder
  express.static("client/build");
  app.get("*", (req, res) => {
    res.sendFile(path.resolve(__dirname, "client", "build", "index.html"));
  });
}
app.listen(port, () => console.log(`listening on port ${port}`));
