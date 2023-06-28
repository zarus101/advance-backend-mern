const jwt= require("jsonwebtoken")
const crypto= require("crypto")
/////function for the generating of the token
const generateToken= (id)=>{
    return jwt.sign({id}, process.env.JWT_SECRET, {expiresIn:"1d"})
}


/////function to hashthe token
const hashToken= (token)=>{
    return crypto.createHash("sha256").update(token.toString()).digest("hex")
}


// exporting the functions
module.exports={generateToken, hashToken}