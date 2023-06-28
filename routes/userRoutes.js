const express= require("express")
const { registerUser, loginUser, verifyUser, sendLoginCode, loginWithCode, sendVerificationEmail, logout, loginStatus, resetPassword, forgetPassword, getUser, loginWithGoogle } = require("../controllers/userController")
const { checkUserAuth } = require("../middlewares/authHandler")
const router= express.Router()


////main route path of the user functions
router.post("/register", registerUser)
router.post("/login", loginUser)
router.get("/logout", logout)
router.get("/loginstatus", loginStatus)
router.get("/getuser", checkUserAuth, getUser)


router.patch("/verifyuser/:verificationToken",checkUserAuth, verifyUser)
router.post("/sendlogincode/:email", sendLoginCode)
router.post("/loginwithcode/:email", loginWithCode)
router.patch("/resetpassword/:resetToken", resetPassword)
router.post("/forgetpassword", forgetPassword)

router.post("/sendVerificationEmail", checkUserAuth, sendVerificationEmail);


router.post("/google/callback", loginWithGoogle)



////exporting the router
module.exports= router