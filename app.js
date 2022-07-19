require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    if (err) {
      console.error(err);
      return res.redirect("/");
    }

    const newUser = new User({
      email: req.body.username,
      password: hash,
    });

    newUser.save((err) => {
      if (!err) {
        res.render("secrets");
      } else {
        res.send(err);
      }
    });
  });
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({ email: username }, (err, foundUser) => {
    if (!err) {
      bcrypt.compare(password, foundUser.password, function (err, result) {
        if (!err) {
          if (result) {
            res.render("secrets");
          } else {
            res.redirect("/login");
          }
        } else {
          console.error(err);
        }
      });
    } else {
      console.error(err);
    }
  });
});

app.get("/logout", (req, res) => {
  res.redirect("/");
});

app.listen(3000, () => {
  console.log("Server started on port 3000.");
});
