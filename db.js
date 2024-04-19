  const mongoose = require('mongoose');
  
  function connectDB(){
    mongoose.connect('mongodb://localhost/auth_demo', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
     .then(() => console.log('Connected to the database'))
     .catch((err) => console.error('Failed to connect to MongoDB', err));
  }
  module.exports = connectDB;