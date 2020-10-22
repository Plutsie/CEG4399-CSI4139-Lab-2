
//Creating and initializing the website server

//npm install ejs
//npm install the express module 
const express = require('express')
//npm install the body parser module 
var bodyParser = require('body-parser')
//npm install the mongoose module
const mongoose = require('mongoose')
// npm install bcrypt
const bcrypt = require('bcrypt');
// npm install express-session module
var session = require('express-session')
// install the MongoDB server first at : https://www.mongodb.com/try/download/community  
// and then download the MongoDB compass at: https://www.mongodb.com/try/download/compass?jmp=hero

// npm install connect-mongo module
const MongoStore = require('connect-mongo')(session)
const Schema = mongoose.Schema;

//message variables


//Establishing connection to the localhost at port
//creating an express application and assigning port
const app = express()
const port = 3000


app.use(session({
    secret: "secret",
    store: new MongoStore({
        mongooseConnection: mongoose.connection,
        autoRemove: 'native'
    }),
    name: "2FA Login",
    saveUninitialized: false,
    resave: true,
    rolling: true,
    cookie: {
        domain: "localhost",
        maxAge: 1000*60*60*24*365
    }
}))

// To use this take forms to be able to access in req 
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

// The mongoose database which was created to hold the accounts
mongoose.connect('mongodb://localhost:27017/lab2db', {useNewUrlParser: true, useUnifiedTopology: true})

const Account = new Schema({
    username: String,
    password: String,
    phonenumber: String
})

const AccModel = mongoose.model("Account", Account)

//The homepage
app.get('/', (req, res) => res.send('Welcome to homepage'))

//Sign up page
app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/signup.html')
})

app.post('/api/signup', async (req, res) => {
    var result = {success: false}

    try{
        //Searches if username is already in the database, and sends an error message if so 
        var foundDoc = await new Promise((resolve, reject) => {
            AccModel.findOne({username: req.body.username}, function(err, doc){
                if(err) reject(err)
                resolve(doc)
            })
        })
        //sends error if an input is missing aswell
        if(foundDoc) throw "Error: Account already exists with this username!"

        if(!req.body.username) throw "Username is missing"
        if(!req.body.password) throw "Password is missing"
        if(!req.body.phonenumber) throw "Phonenumber is missing"

        //Hash password using bcrypt
        var hashedPass = await bcrypt.hash(req.body.password, 10)

        //Prepare data to save
        var accDoc = new AccModel()
        accDoc.username = req.body.username
        accDoc.password = hashedPass
        accDoc.phonenumber = req.body.phonenumber
        
        //Save to database
        await new Promise((resolve, reject) => {
            accDoc.save(function(e){
                if(e) reject(e)
                resolve()
            })
        })

        result.success = true
    }
    catch(e){
        if(typeof e === "string") result.reason = e
        else {
            result.reason = "Error at the server"
            console.log(e)
        }
    }

    res.json(result)
})


//Login page
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/login.html')
})

app.post('/api/login', async (req, res) => {
    var result = {response: false}

    try{
        if(req.session.uid){
            throw "You have logged in."
        }
        

        //If one field is missing, appropriate messages are sent
        var username = req.body.username
        if(!username) throw "Username is missing!"

        var password = req.body.password
        if(!password) throw "Password is missing!"

        var accData = await new Promise((resolve, reject) => {
            AccModel.findOne({username: username}, function(err, doc){
                if(err) reject(err)
                resolve(doc)
            })
        })
        if(!accData) throw "No account exists with that username!"

        var accPas = accData.password

        var passwordMatched = await bcrypt.compare(password, accPas)
        if(!passwordMatched) throw "The password is incorrect!"

        req.session.uid = accData._id

        result.success = true
    }
    catch(e){
        if(typeof e === "string") result.reason = e
        else {
            result.reason = "Server error"
            console.log(e)
        }
    }

    res.json(result)
})


//Verification page -- Michelle adds messagesend/recieve here

app.get('/verification', (req, res) => {
    res.sendFile(__dirname + '/verification.html')
})
app.post('/api/verification', async (req, res) => {
    var result = {response: false}

    try{
        if(req.session.uid){
            throw "Your account has been verified!"
        }
        
        //If one field is missing, appropriate messages are sent
        var username = req.body.username
        if(!username) throw "Username is missing!"

        var password = req.body.password
        if(!password) throw "Password is missing!"

        //add one here for message

        var accData = await new Promise((resolve, reject) => {
            AccModel.findOne({username: username}, function(err, doc){
                if(err) reject(err)
                resolve(doc)
            })
        })
        if(!accData) throw "No account exists with that username!"

        var accPas = accData.password

        var passwordMatched = await bcrypt.compare(password, accPas)
        if(!passwordMatched) throw "The password is incorrect!"

        //maybe add for message sending error here
        req.session.uid = accData._id

        result.success = true
    }
    catch(e){
        if(typeof e === "string") result.reason = e
        else {
            result.reason = "Server error"
            console.log(e)
        }
    }

    res.json(result)
})


//Logout capabilities
app.get('/logout', (req, res) => {
    if(req.session.uid) req.session.destroy()
    res.redirect("/login")
})


app.listen(port, () => console.log(`App is listening on port ${port}`))