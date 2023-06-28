const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();
app.use(express.json());
app.use(cookieParser());


app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  })
);
app.use(bodyParser.json());

////routes
const userRoutes = require("./routes/userRoutes");
const errorHandler = require("./middlewares/errorHandler");

///declaring the port
const PORT = process.env.PORT || 5000;
///connnecting to the mongoose server
mongoose
  .connect(process.env.DATABASE_URL)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server connected to ${PORT}`);
    });
  })
  .catch((error) => {
    console.log(error);
  });

///middlewares routes
app.use("/v1/users", userRoutes);

///error handling
app.use(errorHandler);

///routes
app.get("/", (req, res) => {
  res.send("Welcome to vedu education homepage");
});
