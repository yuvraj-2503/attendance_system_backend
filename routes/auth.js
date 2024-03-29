var express = require("express");

var router = express.Router();
const { check } = require("express-validator");
const { signup, signout, signin, isSignedIn, sendVerificationEmail, verifyEmail,
    sendOtpToPhone, verifyPhoneOtp, sendOtp, verifyOtp, updatePhoneNumber } 
                    = require("../controllers/auth");

router.post(
    '/signup',
    [
        check('name', 'name must be of 3 characters.').isLength({min : 3}),
        check('email', 'valid email is required.').isEmail(),
        check('password', 'password must be of 3 characters.').isLength({ min : 3})
    ],
    signup
)

router.post(
    '/signin',
    [
        check('email', 'valid email is required.').isEmail(),
        check('password', 'password must be of 3 characters.').isLength({ min : 3})
    ],
    signin
)

router.get(
    '/signout',
    signout
)

router.post(
    '/sendVerificationEmail',
    [
        check('email', 'valid email is required.').isEmail(),
    ],
    sendVerificationEmail
)

router.post(
    '/otp/email',
    [
        check('email', 'valid email is required.').isEmail(),
    ],
    sendOtp
)

router.post(
    '/otp/email/verify', 
    verifyOtp
)

router.post(
    '/updatePhoneNumber',
    [
        check('phone', 'valid phone number is required.').isMobilePhone(),
    ],
    updatePhoneNumber
)

router.get(
    '/verifyEmail/:userId/:token',
    verifyEmail
)

router.post(
    '/otp/phone',
    [
        check('phone', 'valid phone number is required.').isMobilePhone(),
    ],
    sendOtpToPhone
)

router.post(
    '/otp/phone/verify',
    verifyPhoneOtp
)

module.exports = router;