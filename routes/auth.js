var express = require("express");

var router = express.Router();
const { check } = require("express-validator");
const { signup, signout, signin, isSignedIn, sendVerificationEmail, verifyEmail } = require("../controllers/auth");

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

router.get(
    '/verifyEmail/:userId/:token',
    verifyEmail
)

module.exports = router;