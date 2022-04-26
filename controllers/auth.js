const { check, validationResult } = require("express-validator");
const User = require('../models/user')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const expressJwt = require('express-jwt');
const nodemailer = require('nodemailer');

exports.signup = async (req, res) =>{
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        })
    }
    
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
        name : name,
        email: email,
        password: hashedPassword
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
            "developerMessage" : "email already exists..login to continue" ,
            "result" : null
        })
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

exports.sendVerificationEmail = (req, res) => {
    const errors = validationResult(req);
    if(errors.array().length>0){
        return res.status(400).json({
            "statusCode" : 400,
            "developerMessage" : errors.array()[0].msg,
            "result" : null
        });
    }

    const { email } = req.body;

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
            to: email,
            subject: 'ePathshala - Email Verification',
            text: `Dear User,\r\n\r\nPlease verify your email by entering the otp provided: \r\n\r\n`
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