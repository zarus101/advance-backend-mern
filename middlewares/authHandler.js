const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");
const User = require("../modals/userModel");

const checkUserAuth = asyncHandler(async (req, res, next) => {
  console.log("helllo to my world")
  try {
    const token = req.cookies.token;
    console.log(token);
    if (!token) {
      res.status(401);
      throw new Error("Not authorized, please login");
    }

    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    // Get user id from token
    const user = await User.findById(verified.id).select("-password");
    console.log(user)

    if (!user) {
      res.status(404);
      throw new Error("User not found");
    }
    if (user.role === "suspended") {
      res.status(400);
      throw new Error("User suspended, please contact support");
    }

    req.user = user;
    console.log(user)
    next();
  } catch (error) {
    res.status(401);
    throw new Error("Not authorized, please login");
  }
});


module.exports= {checkUserAuth}
