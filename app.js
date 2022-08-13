const express = require('express');
const app = express();
const mongoose = require('mongoose');
const ejs = require('ejs');
require('dotenv').config();
const bcrypt = require('bcrypt');
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.SECRET_KEY);
const cookieParser = require('cookie-parser')

app.set("view engine", 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser())
mongoose.connect("mongodb://localhost:27017/userDB2");

const schema = new mongoose.Schema({ username: { type: "string", required: true }, password: { type: "string", required: true } });


const User = mongoose.model('User', schema);

const sessionSchema = new mongoose.Schema({ username: { type: "string", required: true } });

const Session = mongoose.model('Session', sessionSchema);

//get routes
app.get("/", checkSession, (req, res) => {
    if (req.session) res.render('secrets')
    else res.render('home');
})
app.get('/login', checkSession, (req, res) => {
    if (req.session) res.render('secrets')
    else res.render('login');
})

app.get('/register', checkSession, (req, res) => {
    if (req.session) res.render('secrets')
    else res.render('register');
})
app.get('/logout', checkSession, (req, res) => {
    deleteSession(req.session);
    res.clearCookie('session');
    res.redirect('/');
})

//post routes
app.post("/register", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) res.send("both fields are required")
    User.findOne({ username: username }, (err, user) => {
        if (err) { console.log(err) }
        else {
            if (user) {
                res.send("username already exists")
            }
        }
    })
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) { console.log(err) }
        else {
            const newUser = new User({ username: username, password: hash });
            newUser.save(async err => {
                if (err) res.send(err)
                else {
                    let sessionKey = await createSession(username);

                    if (sessionKey) res.cookie('session', sessionKey, { maxAge: 86400000 });


                    res.render('secrets');
                }
            })
        }
    })
})

app.post('/login', (req, res) => {
    const { username, password } = req.body;


    if (!username || !password) res.send("both fields are required");
    User.findOne({ username: username }, (err, user) => {
        if (!err) {
            if (user) {
                bcrypt.compare(password, user.password, async (err, same) => {
                    if (same) {

                        let sessionKey = await createSession(username);

                        if (sessionKey) res.cookie('session', sessionKey, { maxAge: 86400000 });


                        res.render('secrets');
                    }
                    else res.send("incorrect password")
                })
            } else res.send("user not found")
        } else res.send(err)
    })


})



//create session
async function createSession(username) {
    const session = new Session({ username: username });

    try {
        const existingSession = await Session.findOne({ username: username });
        if (!existingSession) {
            let _session = await session.save()
            setTimeout(deleteSession.bind(null, _session._id), 86400000);
            return cryptr.encrypt("sessionID=" + _session._id + "&username=" + _session.username);
        } else return undefined;


    } catch {
        return undefined;
    }
}
const port = process.env.PORT || 3000;
app.listen(port)

//check session
function checkSession(req, res, next) {
    if (req.cookies.session) {
        const session = cryptr.decrypt(req.cookies.session);

        const sessionID = session?.split("&")[0].split("=")[1];
        const username = session?.split("&")[1].split("=")[1];
        Session.findOne({ _id: sessionID, username: username }, (err, session) => {

            if (!err) {
                if (session) {

                    req.session = session._id;
                    next()
                } next()
            } next()
        })
    } else next()


}

//destroy session
function deleteSession(sessionID) {

    Session.deleteOne({ _id: sessionID }, (err, res) => {
        console.log(err, res)
    })
}
