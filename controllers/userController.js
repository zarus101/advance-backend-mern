const asyncHandler = require("express-async-handler");
const User = require("../modals/userModel");
var parser = require("ua-parser-js");
const { generateToken, hashToken } = require("../utils/tokenFunctions");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../modals/toknModel");
const sendEmail = require("../utils/sendEmail");
const { OAuth2Client } = require("google-auth-library");

const cryptr = new Cryptr(process.env.CRYPTR_KEY);

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/////function for the registration of the user
const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, password } = req.body;

  // Validation
  if (!fullName || !email || !password) {
    res.status(400);
    throw new Error("Please fill in all the required fields.");
  }

  if (password.length < 6) {
    res.status(400);
    throw new Error("Password must be up to 6 characters.");
  }

  // Check if user exists
  const userExists = await User.findOne({ email });

  if (userExists) {
    res.status(400);
    throw new Error("Email already in use.");
  }

  // Get UserAgent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  //   Create new user
  const user = await User.create({
    fullName,
    email,
    password,
    userAgent,
  });

  // Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: "None",
    secure: true,
  });

  if (user) {
    const { _id, fullName, email, bio, role, isVerified } = user;

    res.status(201).json({
      _id,
      fullName,
      email,
      bio,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid user data");
  }
});

////function of the login of the user
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  console.log(req.body);
  /////validation for the fiels
  if (!email || !password) {
    res.status(400);
    throw new Error("email and password is required");
  }

  /////checking the user in database
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User not found.please register first");
  }

  /////validating the password
  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    res.status(400);
    throw new Error("Password is incorrect");
  }

  /////2-factor authentication for the unknown devices
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent = ua.ua;
  console.log(thisUserAgent);

  const allowedUserAgent = user.userAgent.includes(thisUserAgent);

  if (!allowedUserAgent) {
    // generating the login code if user agent is not listed
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    console.log(loginCode);

    /////encryptio o fthe code before adding to the DB
    const encryptedCode = cryptr.encrypt(loginCode.toString());

    ///deleting the token if exist in the DB
    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    /////saving the token in the databse after deleting the existing token
    await new Token({
      userId: user._id,
      loginToken: encryptedCode,
      expiresAt: Date.now() + 60 * (60 * 1000), ////expires in 60 mins
    }).save();

    res.status(400);
    throw new Error("New Browser or device detected");
  }
  ////generating the token
  const token = generateToken(user._id);
  console.log(token);
  console.log(user);
  console.log(passwordIsCorrect);
  if (user && passwordIsCorrect) {
    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "None",
      secure: true,
    });

    const { _id, fullName, email, bio, role, isVerified } = user;

    res.status(200).json({
      _id,
      fullName,
      email,
      bio,
      role,
      isVerified,
      token,
    });
  } else {
    res.status(500);
    throw new Error("Something went wrong, please try again");
  }
});

///function for loggindg out
const logout = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });

  return res.status(200).json({ message: "Logout Successfully" });
});

///getting the loginstatus
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  // console.log(token);
  if (!token) {
    return res.json(false);
  }

  ////verifying the token
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  if (verified) {
    return res.json(true);
  }

  return res.json(false);
});

/////function for sending the logn code to the email
const sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });
  console.log(user);

  if (!user) {
    res.status(404);
    throw new Error("user not found");
  }

  ////finding the user token in the database
  const userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });

  console.log(userToken);

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid or expired token, please login again");
  }

  const loginCode = userToken.loginToken;
  const decryptedCode = cryptr.decrypt(loginCode);

  /////senging the login code in email
  const subject = "Login Access Code - SURAZ";
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@suraj.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedCode;

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);

    res.status(200).json({ message: `AccessCode sent to ${email}` });
  } catch (error) {
    res.status(500);
    console.log(error);
    throw new Error("Email not sent, try again");
  }
});

/////logging eith the code
const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;
  console.log(loginCode);
  console.log(email);

  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("User not found");
  }

  ////finding the token by user id
  const userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(400);
    throw new Error("invalid token or expired token, please login again");
  }

  const decryptedLoginCode = cryptr.decrypt(userToken.loginToken);
  console.log(decryptedLoginCode);

  if (loginCode !== decryptedLoginCode) {
    res.status(400);
    throw new Error("incorrect code, try again");
  } else {
    //////adding the userAgent
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    console.log(thisUserAgent);
    await user.save();

    ////generating the token
    const token = generateToken(user._id);

    ///////////
    res.cookie("token", token, {
      path: "/",
      sameSite: "none",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400),
      secure: true,
    });
    const { _id, fullName, email, bio, role, isVerified } = user;

    res.status(200).json({
      _id,
      fullName,
      email,
      bio,
      role,
      isVerified,
      token,
    });
  }
});

//////function to send the verification email
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    res.status(404);
    throw new Error("User not found");
  }

  if (user.isVerified) {
    res.status(400);
    throw new Error("User already verified");
  }

  // Delete Token if it exists in DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  //   Create Verification Token and Save
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(verificationToken);

  // Hash token and save
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    verifyToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
  }).save();

  // Construct Verification URL
  const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;

  // Send Email
  const subject = "Verify Your Test  Account-suraj";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@suraj.com";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
    res.status(200).json({ message: "Verification Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

///////function for the verifiactikon of the user
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  const hashedToken = hashToken(verificationToken);

  // finding the token details
  const userToken = await Token.findOne({
    verifyToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(400);
    throw new Error("Invalid token or expired token");
  }

  ////finding the user from token
  const user = await User.findOne({ _id: userToken.userId });

  if (user.isVerified) {
    res.status(400);
    throw new Error("User is already verified");
  }

  ////now verifying the user
  user.isVerified = true;
  await user.save();
  res.status(200).json({ message: "Account Verification Successfull" });
});

////function for forget password
const forgetPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  ////finding the user from the email
  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error("No user found with this email");
  }

  ///delete the token if it exist in the db
  let token = await Token.findOne({ userId: user._id });

  if (token) {
    await token.deleteOne();
  }

  ///create reset token and save
  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;
  console.log(resetToken);

  ///hasing rthe token and saving
  const hasnToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    resetToken: hasnToken,
    expiresAt: Date.now() + 60 * (60 * 1000),
  }).save();

  // Construct Reset URL
  const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

  // Send Email
  const subject = "Password Reset Request ";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@suraj.com";
  const template = "forgetPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
    res.status(200).json({ message: "Password Reset Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, please try again");
  }
});

////function fro reserring the pasword
const resetPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { password } = req.body;

  const hashedToken = hashToken(resetToken);

  const userToken = await Token.findOne({
    resetToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(400);
    throw new Error("Invalid or expxired token");
  }

  ///fincding the user
  const user = await User.findOne({ _id: userToken.userId });

  ///now reset the password
  user.password = password;
  await user.save();
  res.status(200).json({ message: "Password Reset Successful" });
});

////function for getting the uset
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, fullName, email, bio, role, isVerified } = user;

    res.status(200).json({
      _id,
      fullName,
      email,
      bio,
      role,
      isVerified,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

////function for  login with google
const loginWithGoogle = asyncHandler(async (req, res) => {
  const { userToken } = req.body;

  console.log(userToken);
  console.log(client);

  const ticket = await client.verifyIdToken({
    idToken: userToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  console.log(ticket);

  const payload = ticket.getPayload();
  const { name, email, picture, sub } = payload;

  /////getting the user ahent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];

  ////checking tf the user exists
  const user = await User.findOne({ email });

  if (!user) {
    ////creating the use user
    const newUser = await User.create({
      fullName: name,
      email,
      isVerified: true,
      userAgent,
    });

    if (newUser) {
      ////generating the token
      const token = generateToken(newUser._id);

      ////sending the cooekie
      res.cookie("token", token, {
        path: "/",
        sameSite: "none",
        httpOnly: true,
        expiresAt: new Date(Date.now(+1000 * 86400)),
        secure: true,
      });
      const { _id, fullName, email, bio, role, isVerified } = newUser;

      res.status(201).json({
        _id,
        fullName,
        email,
        bio,
        role,
        isVerified,
        token,
      });
    }
  }
  // User exists, login
  if (user) {
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 day
      sameSite: "none",
      secure: true,
    });

    const { _id, fullName, email, bio, role, isVerified } = user;

    res.status(201).json({
      _id,
      fullName,
      email,
      bio,
      role,
      isVerified,
      token,
    });
  }
});

module.exports = { registerUser, loginWithGoogle, getUser, sendLoginCode, loginUser, logout, loginStatus, verifyUser, loginWithCode, sendVerificationEmail, forgetPassword, resetPassword };
