const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const otpSchema = new Schema({
    userId : {
        type : Schema.Types.ObjectId,
        ref: 'user',
        required: true,
        // unique: true
    },

    otp : {
        type: String,
        required: true
    },

    expiration_time : {
        type: Date,
        required: true
    }
});

const Otp = mongoose.model("otp", otpSchema);

module.exports = Otp;