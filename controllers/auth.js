const { check, validationResult } = require("express-validator");
const {User, validate } = require('../models/user')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const nodemailer = require('nodemailer');
const Token = require('../models/token')
const crypto = require('crypto');
const otpGenerator = require('otp-generator');
const { generateOTP } = require('../services/otpService');
const Otp = require('../models/otp');
const { message } = require('../templates/sms_verification');
const AWS = require('aws-sdk');

exports.signup = async (req, res) =>{
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        })
    }
    
    const { name, email, password , college, department } = req.body;

    let u1 = User.findOne({email }).then(async (err, result) => {
        if(err || result){
            return res.status(400).json({
                "statusCode" : 400,
                "developerMessage" : "email already exists..login to continue" ,
                "result" : null
            })
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name : name,
            email: email,
            password: hashedPassword,
            college : college,
            department : department
        });

        user.save().then((result)=> {
        
            return res.status(200).json({
                "statusCode" : 200,
                "developerMessage": "user signed up successfully.",
                "result" : {
                    "id" : result._id,
                    "name" : result.name,
                    "email": result.email,
                }
            });
        }).catch((err) => {
            return res.status(400).json({
                "statusCode" : 400,
                "developerMessage" : "some error occurred." ,
                "result" : null
            })
        });
    });
}

exports.signin = (req, res) => {
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        })
    }
    
    const { email, password } = req.body;
    
    User.findOne({ email }, async (err, result) => {
        if(err || !result){
            return res.status(404).json({
                "statusCode" : 404,
                "developerMessage" : 'email does not exists...signup to continue',
                "result" : null
            })
        }

        const match = await bcrypt.compare(password, result.password);
        if(!match){
            return res.status(401).json({
                "statusCode" : 401,
                "developerMessage" : 'invalid password..please try again',
                "result" : null
            });
        }

        const token = jwt.sign({ id : result._id }, process.env.SECRET );
        
        res.cookie("token", token, { expire : new Date() + 1000 });

        return res.status(200).json({
            "statusCode" : 200,
            "developerMessage" : 'user logged in successfully.',
            "result" : {
                // "token" : token,
                "id" : result._id,
                "name" : result.name,
                "email": result.email,
            }
        })

    })
}

exports.signout = (req, res) => {
    res.clearCookie("token");
    res.status(200).json({
        "statusCode" : 200,
        "developerMessage" : 'user signed out successfully.',
        "result" : null
    });
}

exports.sendOtp = async (req, res) => {
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        });
    }

    const { name, email } = req.body;

    let user = await User.findOne({ email : email, verified : false }); 

    if(!user){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : "invalid user...try again..",
            "result" : null
        })
    }

    const otpGenerated = generateOTP();

    let otp = await new Otp({
        userId: user._id,
        otp : otpGenerated
    });

    otp.save();

    try{
        let transporter = nodemailer.createTransport({
            service : 'gmail',
            auth : {
                type: 'OAuth2',
                user: process.env.MAIL_USERNAME,
                pass: process.env.MAIL_PASSWORD,
                clientId: process.env.OAUTH_CLIENTID,
                clientSecret: process.env.OAUTH_CLIENT_SECRET,
                refreshToken: process.env.OAUTH_REFRESH_TOKEN
            }
        })

        let mailOptions = {
            from: `"Yuvraj Singh"<${process.env.MAIL_USERNAME}>`,
            to: user.email,
            subject: 'ePathshala - Email Verification',
            html: `<div
            class="container"
            style="max-width: 90%; margin: auto; padding-top: 20px">
            <h2>Dear ${user.name},</h2>
            <h4>You are officially In ✔</h4>
            <p style="margin-bottom: 30px;">Please verify your email by entering the otp: </p>
            <h1 style="font-size: 40px; letter-spacing: 2px; text-align:center;">${otpGenerated}</h1>
            </div>`
        };
    
        transporter.sendMail(mailOptions, (err, data) => {
            if(err){
                return res.status(400).json({
                    "statusCode" : 400,
                    "developerMessage" : err.message,
                    "result" : null
                });
            }
    
            return res.status(200).json({
                "statusCode" : 200,
                "developerMessage" : 'email sent successfully',
                "result" : null
            });
        })
    }catch(e){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : e,
            "result" : null
        });
    }

}

exports.verifyOtp = async (req, res) => {
    const { userId, otp } = req.body;

    let user = await User.findById(userId);
    if(!user){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : "user not found.",
            "result" : null
        });
    }

    if(user.verified){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : "user already verified.",
            "result" : null
        });
    }

    let otpModel = await Otp.findOne({userId : user._id, otp : otp });

    if(!otpModel){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : "invalid otp.",
            "result" : null
        });
    }

    await User.findByIdAndUpdate(user._id, {verified : true });

    return res.status(200).json({
        "statusCode" : 200,
        "developerMessage" : "otp verified successfully.",
        "result" : {
            "id" : user._id,
            "name" : user.name,
            "email" : user.email
        }
    });
}

exports.sendVerificationEmail = async (req, res) => {
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        });
    }

    const { name, email } = req.body;

    let user = await User.findOne({ email : email, verified : false }); 

    if(!user){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : "invalid user...try again..",
            "result" : null
        })
    }

    let token = await new Token({
        userId : user._id,
        token : crypto.randomBytes(32).toString('hex')
    });
    token.save();

    const link = `${process.env.BASE_URL}/api/verifyEmail/${token.userId}/${token.token}`;

    try{
        let transporter = nodemailer.createTransport({
            service : 'gmail',
            auth : {
                type: 'OAuth2',
                user: process.env.MAIL_USERNAME,
                pass: process.env.MAIL_PASSWORD,
                clientId: process.env.OAUTH_CLIENTID,
                clientSecret: process.env.OAUTH_CLIENT_SECRET,
                refreshToken: process.env.OAUTH_REFRESH_TOKEN
            }
        })

        let mailOptions = {
            from: `"Yuvraj Singh"<${process.env.MAIL_USERNAME}>`,
            to: user.email,
            subject: 'ePathshala - Email Verification',
            text: `Dear ${user.name},\r\n\r\nPlease verify your email by clicking the following link: \r\n\r\n${link}`
        };
    
        transporter.sendMail(mailOptions, (err, data) => {
            if(err){
                return res.status(400).json({
                    "statusCode" : 400,
                    "developerMessage" : err.message,
                    "result" : null
                });
            }
    
            return res.status(200).json({
                "statusCode" : 200,
                "developerMessage" : 'email sent successfully',
                "result" : null
            });
        })
    }catch(e){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : e,
            "result" : null
        });
    }
}

exports.verifyEmail = async (req, res)=> {
    const user = await User.findOne({ _id : req.params.userId , verified : false });

    if(!user){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : "invalid link..",
            "result" : null
        })
    }

    const token = await Token.findOne({
        userId : user._id,
        token: req.params.token
    });

    if(!token){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : "invalid link..",
            "result" : null
        });
    }

    await User.findByIdAndUpdate(user._id, {verified : true} );
    await Token.findOneAndRemove({ userId : user._id });

    return res.status(200).json({
        "statusCode" : 200,
        "developerMessage" : "email verified successfully.",
        "result" : {
            "id" : user._id,
            "name" : user.name,
            "email": user.email,
        }
    });
}

exports.updatePhoneNumber = async (req, res) => {
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        });
    }

    const { email, phone, password } = req.body;

    let u1 = await User.findOne({ email: email });
    if(!u1){
        return res.status(404).json({
            "statusCode" : 404,
            "developerMessage" : "user not found..try again..",
            "result" : null
        });
    }

    const match = await bcrypt.compare(password, u1.password);

    if(!match){
        return res.status(401).json({
            "statusCode" : 401,
            "developerMessage" : 'invalid password..you are not authorized to update..',
            "result" : null
        });
    }

    await User.findOneAndUpdate({ email: u1.email, password: u1.password }, {phone: phone }).then((result) => {
        // console.log(result);
        // console.log(err);
        // if(err){
        //     return res.status(400).json({
        //         "statusCode" : 400,
        //         "developerMessage" : "some error occurred.",
        //         "result" : null
        //     });
        // }

        return res.status(200).json({
            "statusCode" : 200,
            "developerMessage" : "phone number added successfully.",
            "result" : {
                "id" : result._id,
                "name" : result.name,
                "email" : result.email
            }
        });
    });
}

exports.sendOtpToPhone = async (req, res) => {
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        });
    }

    const { phone, email } = req.body;

    if(!phone){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : 'phone number not provided.',
            "result" : null
        });
    }

    if(!email){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : 'email not provided.',
            "result" : null
        });
    }

    let u1 = await User.findOne({email : email });
    if(!u1){
        return res.status(404).json({
            "statusCode" : 404,
            "developerMessage" : 'invalid user..try again..',
            "result" : null
        });
    }

    const otp = generateOTP();
    const now = new Date();
    const expiration_time = addMinutesToDate(now, 10);

    const otp_instance = await new Otp({
        userId : u1._id,
        otp : otp,
        expiration_time : expiration_time
    });

    otp_instance.save();

    const msg = message(otp);

    var params = {
        Message: msg,
        PhoneNumber: phone
    }

    AWS.config.update({
        region : process.env.REGION,
        accessKeyId : process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey : process.env.AWS_SECRET_ACCESS_KEY,
        apiVersion: '2010-03-31'
    })

    var publishTextPromise = new AWS.SNS({}).publish(params).promise();

    publishTextPromise.then((data) => {
        return res.status(200).json({
            "statusCode" : 200,
            "developerMessage" : 'otp sent to phone successfully.',
            "result" : {
                'id' : u1._id,
                'name' : u1.name,
                'email' : u1.email
            }
        });
    }).catch((err)=> {
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : 'otp sending failed.',
            "result" : null
        });
    })

}

addMinutesToDate = (date, minutes) => {
    return new Date(date.getTime() + minutes * 60000);
}