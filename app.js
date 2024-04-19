const express = require('express');
const app = express();
const PORT = 3000;
const bcrypt = require('bcrypt');
const connectDB = require('./db.js');
const User = require('./models/user');
const jwt = require('jsonwebtoken');

app.use(express.json());
connectDB()
// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Register a new user
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    // Encrypt and hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create a new user
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'An error occurred while registering the user' });
  }
});



// User login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
     // Check if the user exists
     const user = await User.findOne({ email });
     if (!user) {
       return res.status(401).json({ error: 'Invalid email or password' });
     }    // Validate the password
     const isPasswordValid = await user.comparePassword(password); // Use correct method call
     if (!isPasswordValid) {
       return res.status(401).json({ error: 'Invalid email or password' });
     }    // Generate a JWT token
     const token = jwt.sign({ userId: user._id }, 'secretKey');
     
     res.status(200).json({ token });
   } catch (error) {
     console.error('Error logging in:', error);
     res.status(500).json({ error: 'An error occurred while logging in' });
   }
 });



 // Authentication middleware
const authenticateUser = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    
    // Verify the token
    const decodedToken = jwt.verify(token, 'secretKey');
    
    // Attach the user ID to the request object
    req.userId = decodedToken.userId;
    
    next();
  } catch (error) {
    console.error('Error authenticating user:', error);
    res.status(401).json({ error: 'Unauthorized' });
  }
};
// Apply authentication middleware to protected routes
app.get('/protected', authenticateUser, (req, res) => {
  // Handle protected route logic here
});


// Authorization middleware
const authorizeUser =  (requiredRole) => async(req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    
    if (user.role !== requiredRole) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    next();
  } catch (error) {
    console.error('Error authorizing user:', error);
    res.status(500).json({ error: 'An error occurred while authorizing the user' });
  }
};

// Apply authorization middleware to restricted routes
app.get('/admin', authenticateUser, authorizeUser('admin'), (req, res) => {
  // Handle admin-only route logic here
});


// Restrict access to a route 
app.get('/restricted', authenticateUser, (req, res) => {  });

// Generate a password reset token
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate a reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiration = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();
 res.status(200).json({ message: 'Password reset token sent' });
  } catch (error) {
    console.error('Error generating reset token:', error);
    res.status(500).json({ error: 'An error occurred while generating the reset token' });
  }
});

// Reset password using the reset token
app.post('/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;

    // Find the user with the provided reset token
    const user = await User.findOne({
      resetToken,
      resetTokenExpiration: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(401).json({ error: 'Invalid or expired reset token' });
    }

    // Encrypt and hash the new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update the user's password and reset token fields
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiration = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'An error occurred while resetting the password' });
  }
});