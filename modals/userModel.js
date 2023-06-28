const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = mongoose.Schema(
  {
    //////full name of the user
    fullName: {
      type: String, ///setting the datatype as String
      required: [true, "full name is required"], ////this checks if it is provided or not...if not user will not be registered
    },

    ////email of the user
    email: {
      type: String,
      required: [true, "email is required"],
      unique: true,
      trim: true,
      match: [/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, "Please enter a valid email"],
    },

    ///password of the user
    password: {
      type: String,
      require: [true, "password is required"],
    },

    ///bio of the user
    bio: {
      type: "String",
      default: "bio",
    },

    ////role of the user.....user will have multipple roles like admin, user with respectives functionality
    role: {
      type: String,
      required: true,
      default: "user",
    },

    ////check if the user email is verified or not
    isVerified: {
      type: Boolean,
      default: false,
    },

    /////information of user browser or operating system
    userAgent:{
      type: Array,
      required: true,
      default: []

    }
  },
  {
    timestamps: true,
  }
);

//////enctryption of the password before adding to the database
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  /////hashiing the password if it is not hashed
  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(this.password, salt);
  this.password = hashPassword;
  next();
});

const User = mongoose.model("User", UserSchema);
module.exports = User;
