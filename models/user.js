var mongoose = require('mongoose');

var userSchema = new mongoose.Schema({
    name : {
        type: String,
        required : true,
        trim: true
    },

    email : {
        type: String,
        required : true,
        trim: true,
        unique: true
    },

    password : {
        type : String,
        required : true
    },

    college : {
        type : String, 
        // required : true, 
        trim: true
    },

    department : {
        type : String, 
        // required : true, 
        trim: true
    },

    classes : {
        type: Array, 
        default : []
    }
}, {timestamps : true })

const User = mongoose.model('user', userSchema)

module.exports = User;