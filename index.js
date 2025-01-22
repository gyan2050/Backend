const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const jwt = require("jsonwebtoken");
const cookieparser = require("cookie-parser");
const bcrypt = require("bcrypt");

//creating a server
const app = express();

// setting up the view engine
app.set("view engine" , "ejs");

// middlewares
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieparser());

// creating a server
mongoose.connect("mongodb://localhost:27017/", {
    dbName : "Backend",
})
.then(() => { 
    console.log("Database Connected");
})
.catch((err) => {
    console.log("not Conneted", err);
});

// Schema for user
const UserSchema = new mongoose.Schema({
    name : String,
    email : String,
    password : String
});

// model
const user_info = mongoose.model("User_Info", UserSchema);

// express routes
app.get("/", (req, res) => {
    res.render("home");
});

app.get("/login", async (req,res) => {
    const {token} = req.cookies;
    
    if( token){
        const decoded = jwt.verify(token, "SECRET_KEY");

        req.user = await user_info.findById({_id: decoded._id});

        return res.render("logout", {name: req.user.name});
    }
    res.render("login", {message : null});
});

app.get("/register", (req,res) => {
    res.render("register");
});

app.get("/logout", (req,res) => {
    res.clearCookie("token");
    res.redirect("/login");
});

app.post("/login", async (req,res) => {
    const {email, password} = req.body;

    const user_check = await user_info.findOne({email});

    if(!user_check){
        return res.status(404).render("login", {message : "User Not Found!"});
    }

    const hash_pass_decoded = await bcrypt.compare(password, user_check.password);
    if( !hash_pass_decoded){
        return res.render("login", {message : "Invalid Credentials"});
    }

    const encoded_password = jwt.sign({_id : user_check._id}, "SECRET_KEY");
    res.cookie("token", encoded_password, {
        httpOnly : true,
    });

    res.render("logout", {name : user_check.name});

});

app.post("/register", async (req,res) => {
    const {name, email, password}  = req.body;

    const user = await user_info.findOne({email});
    
    if(user){
        return res.render("login", {message : "User already registered"});
    }

    const hashed_password = await bcrypt.hash(password, 10);
    await user_info.create({name, email, password : hashed_password});
    res.render("login", {message : "Registration Successful"});
});


const PORT = 3000;

app.listen(PORT, () => {
    console.log("server is working fine");
});