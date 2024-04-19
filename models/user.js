const mongoose = require('mongoose')
const bcrypt = require('bcrypt'); 

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        trim: true
    },
    email: {
        type: String,
        required : true,
        trim: true
    },
    password: {
        type: String,
        required : true
    },
    role: {
        type: String,
        enum : ['Admin', 'Student', 'Visitor']
    }
})

userSchema.methods.comparePassword = async function (candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw new Error(error);
    }
};

module.exports = mongoose.model('user', userSchema)
