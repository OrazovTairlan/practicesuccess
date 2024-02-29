const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.set('view engine', 'ejs');

const saltRounds = 10;

mongoose.connect("mongodb+srv://dimachine:VImvqU2005@cluster0.pir3qph.mongodb.net/?retryWrites=true&w=majority", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// JWT secret key
const JWT_SECRET = 'your_secret_key';

const bookSchema = new mongoose.Schema({
    title: String,
    author: String,
    genre: String,
    year: Number,
});

const authSchema = new mongoose.Schema({
    username: String,
    password: String
});

const Auth = mongoose.model("Auth", authSchema)
const BookModel = mongoose.model("Book", bookSchema);

// Function to generate JWT token
function generateToken(user) {
    return jwt.sign({id: user._id}, JWT_SECRET, {expiresIn: '1h'});
}

// Function to verify JWT token
function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET);
}

// Middleware to verify JWT token
function verifyTokenMiddleware(req, res, next) {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({message: "Unauthorized"});
    }

    try {
        const decoded = verifyToken(token);
        req.user = decoded;
        next();
    } catch (err) {
        console.error('Error verifying token:', err);
        return res.status(401).json({message: "Unauthorized"});
    }
}

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.json());
app.use(express.static("public"));

app.get("/add_book", async function (req, res) {
    try {
        res.render("add_book", {})
    } catch (err) {
        console.error('Error creating book:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Create a new book
app.post("/book", async function (req, res) {
    try {
        await BookModel.create(req.body);
        res.json("created");
    } catch (err) {
        console.error('Error creating book:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Delete a book
app.delete("/book/:id", async function (req, res) {
    try {
        await BookModel.deleteOne({_id: req.params.id});
        const result = await BookModel.find({}).lean();
        res.json(result);
    } catch (err) {
        console.error('Error deleting book:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Update a book
app.put("/book/:id", async function (req, res) {
    try {
        console.log(req.body)
        await BookModel.updateOne({_id: req.params.id}, req.body);
        res.json("edited");
    } catch (err) {
        console.error('Error updating book:', err);
        res.status(500).send('Internal Server Error');
    }
});


// Get all books with sorting, searching, filtering
app.get("/book/:id", async function (req, res) {
    try {


        let result = await BookModel.findOne({_id: req.params.id})
        res.json(result)
    } catch (err) {
        console.error('Error getting books:', err);
        res.status(500).send('Internal Server Error');
    }
});

app.get("/books", async function (req, res) {
    try {
        let query = {};

        // Filtering
        if (req.query.genre) {
            query.genre = req.query.genre;
        }

        // Sorting
        let sort = {};
        if (req.query.sort) {
            let sortParts = req.query.sort.split(':');
            sort[sortParts[0]] = sortParts[1] === 'asc' ? 1 : -1;
        }


        let page = parseInt(req.query.page) || 1;
        let limit = parseInt(req.query.limit) || 10;
        let startIndex = (page - 1) * limit;
        let endIndex = page * limit;

        let result = {}
        result.totalCount = await BookModel.countDocuments(query);
        if (endIndex < result.totalCount) {
            result.next = {
                page: page + 1,
                limit: limit
            };
        }

        if (startIndex > 0) {
            result.previous = {
                page: page - 1,
                limit: limit
            };
        }

        result.data = await BookModel.find(query).sort(sort).limit(limit).skip(startIndex).lean();
        console.log(result.data)
        res.render('books', {
            books: result.data, pagination: {
                ...result
            }
        });
    } catch (err) {
        console.error('Error getting books:', err);
        res.status(500).send('Internal Server Error');
    }
});









app.get("/auth", (req, res) => {
    res.render("auth")
})
// User registration
app.post("/register", async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
        const user = await Auth.create({
            username: req.body.username,
            password: hashedPassword,
        });
        const token = generateToken(user);
        res.json({token});
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).send('Internal Server Error');
    }
});

// User login
app.post("/login", async (req, res) => {
    try {
        const user = await Auth.findOne({username: req.body.username});
        if (!user) {
            return res.status(400).json({message: "User not found"});
        }

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(400).json({message: "Invalid password"});
        }

        const token = generateToken(user);
        res.json({token});
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).send('Internal Server Error');
    }
});

// Protected route example
app.get("/protected-route", verifyTokenMiddleware, (req, res) => {
    res.json({message: "Protected route accessed successfully"});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
    console.log(`Server is running on port ${PORT}`);
});