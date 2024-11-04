// npm init -y
// npm install express jsonwebtoken bcryptjs body-parser mongoose nodemon


// Import required modules
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

// Initialize Express app
const app = express();
app.use(bodyParser.json()); // Parse JSON bodies

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/jwtAuthDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Mongoose user schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Secret key for JWT signing and encryption
const SECRET_KEY = 'your_secret_key_here';

// Signup route
app.post('/signup', async (req, res) => {
  try {
    // Extract username and password from request body
    const { username, password } = req.body;

    // Simple validation
    if (!username || !password) {
      return res.status(400).send('Username and password are required');
    }

    // Check if user already exists
    const userExists = await User.findOne({ username });
    if (userExists) {
      return res.status(409).send('User already exists');
    }

    // Hash the password
    const hashedPassword = bcrypt.hashSync(password, 8);

    // Create a new user
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).send('User registered successfully');
  } catch (error) {
    res.status(500).send('There was a problem registering the user');
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    // Extract username and password from request body
    const { username, password } = req.body;

    // Find the user in the database
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send('User not found');
    }

    // Check if password matches
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send('Invalid password');
    }

    // Sign the JWT
    const token = jwt.sign({ username: user.username }, SECRET_KEY, {
      expiresIn: '24h', // Expires in 24 hours
    });

    // Return the token
    res.status(200).json({ auth: true, token });
  } catch (error) {
    res.status(500).send('There was a problem logging in');
  }
});

// Middleware to verify token
function verifyToken(req, res, next) {
  // Get token from Authorization header
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(403).send('No token provided');
  }

  // Extract token from Bearer scheme
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(403).send('No token provided');
  }

  // Verify token
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).send('Failed to authenticate token');
    }

    // Save username for use in other routes
    req.username = decoded.username;
    next();
  });
}

// Protected route
app.get('/protected', verifyToken, (req, res) => {
  res
    .status(200)
    .send(`Hello ${req.username}, you have access to this protected route.`);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
