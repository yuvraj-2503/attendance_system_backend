var mongoose = require('mongoose');
const Schema = mongoose.Schema;
const Joi = require('joi');

var userSchema = new Schema({
    name : {
        type: String,
        min: 3, 
        max: 255,
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

    verified : {
        type: Boolean,
        default: false
    },

    role : {
        type : String,
        trim : true
    },

    classes : {
        type: Array, 
        default : []
    }
}, {timestamps : true })

const User = mongoose.model('user', userSchema);

const validate = (user) => {
    const schema = Joi.object({
        name: Joi.string().min(3).max(255).required(),
        email: Joi.string().email().required(),
        password: Joi.string().required()
    })

    return schema.validate(user);
}

module.exports = {
    User, validate
};