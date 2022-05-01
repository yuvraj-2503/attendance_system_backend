const message = (otp) => {
    return `Dear user,\n\n` 
        + `${otp} is your OTP for phone number verification with ePathshala. ` 
        + `Please enter the OTP to verify your phone number.\n\n`
        + `Regards\n`
        + 'ePathshala'
};

module.exports.message = message;