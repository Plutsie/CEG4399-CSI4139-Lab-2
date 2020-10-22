
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

const crypto = require('crypto');
const assert = require('assert');
const algo = 'aes-256-cbc'
const salt = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
var asn1 = require('asn1.js');
var BN = require('bn.js');
const { SSL_OP_TLS_BLOCK_PADDING_BUG } = require('constants');
const { generateKeyPairSync } = require('crypto');
const keyOptions = [{modulusLength: 4096}, {modulusLength: 2048}]
const [
    { publicKey: publicKeyAlice, privateKey: privateKeyAlice },
    { publicKey: publicKeyBob, privateKey: privateKeyBob }
] = keyOptions.map(options => generateKeyPairSync('rsa', options))
    
//STEP01
// Generate Alice's keys...
const alice = crypto.createDiffieHellman(1024);
const aliceKey = alice.generateKeys();
// Generate Bob's keys...
const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator());
//Bob looks up α, chooses (at random) a value b, and computes β = g b mod p
const bobKey = bob.generateKeys();
//bobKey is sent via email!!!
console.log('Alice private')
console.log(alice.getPrivateKey('hex'))
console.log('Alice public')
console.log(alice.getPublicKey('hex'))
console.log('Alice prime')
console.log(alice.getPrime().toString('hex'))
console.log('Bob private')
console.log(bob.getPrivateKey('hex'))
console.log('Bob public')
console.log(bob.getPublicKey('hex'))

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
    email: String
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
        if(!req.body.email) throw "Email is missing"

        //Hash password using bcrypt
        var hashedPass = await bcrypt.hash(req.body.password, 10)

        //Prepare data to save
        var accDoc = new AccModel()
        accDoc.username = req.body.username
        accDoc.password = hashedPass
        accDoc.email = req.body.email

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

        var nodemailer = require('nodemailer');

        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              user: 'ceg4399group21@gmail.com',
              pass: 'lab2ceg4399'
            }
        });

        console.log(bobKey.toString('hex'))
        var mailOptions= {
            from: 'ceg4399group21@gmail.com',
            to: 'bjohn084@uottawa.ca',
            subject: bobKey.toString('hex'),
            text: bobKey.toString('hex')
        };

        transporter.sendMail(mailOptions, function(error, info){
            if (error) {
              console.log(error);
            } else {
              console.log('Email sent: ' + info.response);
            }
        });

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
        //If one field is missing, appropriate messages are sent
        var username = req.body.username
        if(!username) throw "Username is missing!"

        var password = req.body.password
        if(!password) throw "Password is missing!"

        var message = req.body.message
        if(!message) throw "Message is missing!"

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

        const K_alice = alice.computeSecret(bobKey);
        //first n bits of K are k1;
        alice_K1 = K_alice.toString('hex').substring(0, K_alice.toString('hex').length/2); 
        //the next n bits of K are k2.
        alice_K2 = K_alice.toString('hex').substring(K_alice.toString('hex').length/2);
        //Let m = α || β
        var m = alice.getPrivateKey('hex') + bob.getPublicKey('hex');
        //MACk1(m)
        var mack1m = crypto.createHmac('sha256', m)
        .update(alice_K1)
        .digest('hex');
        //m1 = Ek2(m || MACk1(m)) 
        const algo = 'aes-256-cbc'
        const salt = crypto.randomBytes(32);
        const key_alice = crypto.scryptSync(alice_K2, salt, 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algo, key_alice, iv);
        let encrypted = cipher.update(m + mack1m, 'hex', 'hex')
        encrypted += cipher.final('hex');
        console.log('HERE')
        //Bob computes K = αb mod p
        var K_bob = bob.computeSecret(aliceKey);
        //K1 Bob
        bob_K1 = K_bob.toString('hex').substring(0, K_bob.toString('hex').length/2); 
        //K2 Bob
        bob_K2 = K_bob.toString('hex').substring(K_bob.toString('hex').length/2);
        //Validate m1
        function validate_m1(m1){
            var key_bob = crypto.scryptSync(bob_K2, salt, 32);
            var decipher = crypto.createDecipheriv(algo, key_bob, iv);
            let decrypted = decipher.update(m1, 'hex', 'hex')
            decrypted += decipher.final('hex');
            console.log(decrypted);

            var expected_m = alice.getPrivateKey('hex') + bob.getPublicKey('hex');
            var expedcted_mack1m = crypto.createHmac('sha256', m)
            .update(bob_K1)
            .digest('hex');

            return (expected_m+expedcted_mack1m == decrypted)
        }
        if(!validate_m1(encrypted)) throw "m1 was not validated"
        //compute m_prime
        var m_prime = bob.getPublicKey('hex') + alice.getPrivateKey('hex'); 
        //compute m2
        var mack1m_bob = crypto.createHmac('sha256', m_prime)
        .update(bob_K1)
        .digest('hex');
        var key_bob = crypto.scryptSync(bob_K2, salt, 32);
        var cipher_bob = crypto.createCipheriv(algo, key_bob, iv);
        let encrypted_bob = cipher_bob.update(m_prime + mack1m_bob, 'hex', 'hex')
        encrypted_bob += cipher_bob.final('hex');
        //signs m2 using its private key
        const signature = crypto.sign("sha256", Buffer.from(encrypted_bob), {
            key: privateKeyBob,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        })
        throw encrypted_bob.toString('hex')  + 'Signature: ' + signature.toString('hex')

        if(req.session.uid){
            throw "Your account has been verified!"
        }
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