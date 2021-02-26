const express = require('express');
const session = require('express-session');
const hbs = require('express-handlebars');
const mongoose = require('mongoose');
const passport = require('passport');
const localStragey = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

const app = express();

// mongo connect 
mongoose.connect('mongodb://localhost:27017/auth', {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: true,
    useUnifiedTopology: true
}, (error) => console.log(error? error : 'done'));

// Model
const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});

const User = mongoose.model('User', UserSchema);

// Middleware
app.engine('hbs', hbs({extname: '.hbs'}));
app.set('view engine', 'hbs');
app.use(express.static(`${__dirname}/public`));
app.use(
    session({
        secret: 'thisissecret',
        resave: false,
        saveUninitialized: true,
    })
);
app.use(express.urlencoded({extended: false}));
app.use(express.json());

// Passport js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) =>{
    done(null, user.id);
});

passport.deserializeUser((id, done) =>{
    User.findById(id, (error, user) => {
        done(error, user);
    });
});

passport.use(new localStragey((username, password, done) => {
    User.findOne({username}, (error, user)=>{
        if(error) return done(error);
        if(!user) return done(null, false, {messgae: 'Incurrect username'});

        bcrypt.compare(password, user.password, (error, response) =>{
            if(error) return done(error);
            if(response === false) return done(null, false, {message: 'Incorrect password'});

            return done(null, user);
        });
    });
}));


const isLoggedIn = (req, res, next) =>{
    if(req.isAuthenticated()) return next();
    res.redirect('/login');
};

const isLoggedOut = (req, res, next) =>{
    if(!req.isAuthenticated()) return next();
    res.redirect('/');
};

//Routes
app.get('/', isLoggedIn, (req, res, next) =>{
    res.render("index", {title: 'Home'});
});

app.get('/login', isLoggedOut, (req, res, next) =>{
    let response = {
        title: "Login",
        error: req.query.error
    };

    res.render("login", response);
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login?error=true'
}));

app.get('/logout', (req, res, next) =>{
    req.logout();
    res.redirect('/');
});

//Setup our admin user
app.get('/setup', async(req, res) => {
    const exists = await User.exists({username: 'admin'});

    if(exists){
        res.redirect('/login');
        return;
    }

    bcrypt.genSalt(10, (error, salt) =>{
        if(error) return next(error);
        bcrypt.hash('mypassword', salt, (error, hash) =>{
            if(error) return next(error);
            const newAdmin = new User({
                username: 'admin',
                password: hash
            });

            newAdmin.save();

            res.redirect('/login');
        });
    });
});

// Listen
app.listen(4000, () => console.log('app listning'));