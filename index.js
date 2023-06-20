import * as dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import database from './db/connect.js';
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose';
import nodemailer from 'nodemailer'
import bcrypt from 'bcrypt'
import { MongoClient } from 'mongodb'

dotenv.config();
const app = express();
const PORT = process.env.PORT;
const MONGO_URL = process.env.MONGO_URL;
const client = new MongoClient(MONGO_URL);
await client.connect();
app.use(express.urlencoded());
app.use(express.json());
app.use(cors());
database();

app.get("/", function (request, response) {
  response.send("Welcome to forgot password");
});

app.get("/", cors(), (request, response) => {

});


//Signup Model
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    require: true
  },
  email: {
    type: String,
    require: true,
    unique: true
  },
  password: {
    type: String,
    require: true
  },
})
const User = new mongoose.model("FotgotPassword", userSchema)


app.post("/signup", async (request, response) => {

  const { name, email, password } = request.body;

  console.log(request.body);
  try {
    const emailexist = await User.findOne({ email: email })
    if (emailexist) {
      return response.status(400).json("Email alredy Exist")
    }
    const hash = await bcrypt.hash(password, 10)

    const user = new User({
      name: request.body.name,
      email: request.body.email,
      password: hash
    });

    const data = await user.save();
    response.json(data);
  } catch (err) {
    response.status(400).json(err)
  }
})


app.post("/login", async (request, response) => {

  try {
    const userData = await User.findOne({ email: request.body.email })
    if (!userData) {
      return response.status(400).json("email not Exist");
    }

    const validpwd = await bcrypt.compare(request.body.password, userData.password);

    if (!validpwd) {
      return response.status(400).json("Invalid credentials");
    }

    const userToken = jwt.sign({ email: userData.email }, process.env.SECRECT_KEY);

    response.header('auth', userToken).json(userToken)
  } catch (err) {
    response.status(400).json(err)
  }
})


app.post("/sendpasswordlink", async (req, res) => {
  console.log(req.body)

  const { email } = req.body;

  if (!email) {
    res.status(401).json({ status: 401, message: "Enter Your Email" })
  }

  try {
    const userfind = await User.findOne({ email: email });

    // token generate for reset password
    const token = jwt.sign({ _id: userfind._id }, process.env.SECRECT_KEY, {
      expiresIn: "1h"
    });


    const setusertoken = await User.findByIdAndUpdate({ _id: userfind._id }, { verifytoken: token }, { new: true });
    console.log(setusertoken)

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });

    if (setusertoken) {
      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: "Sending Email For password Reset",
        text: `This Link Valid For 2 MINUTES http://localhost:3000/forgotpassword/${userfind.id}/${token}`
      }

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log("error", error);
          res.status(401).json({ status: 401, message: "email not send" })
        } else {
          console.log("Email sent", info.response);
          res.status(201).json({ status: 201, message: "Email sent Succsfully" })
        }
      })

    }

  } catch (error) {
    res.status(401).json({ status: 401, message: "invalid user" })
  }

});

// verify user for forgot password time
app.get("/forgotpassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;

  try {
    const validuser = await User.find({ _id: id, verifytoken: token });

    const verifyToken = jwt.verify(token, process.env.SECRECT_KEY);


    if (validuser && verifyToken._id) {
      res.status(201).json({ status: 201, validuser })
    } else {
      res.status(401).json({ status: 401, message: "user not found" })
    }

  } catch (error) {
    res.status(401).json({ status: 401, error })
  }
});


// change password

app.post("/:id/:token", async (req, res) => {
  const { id, token } = req.params;

  const { password } = req.body;

  try {
    const validuser = await User.find({ _id: id, verifytoken: token });

    const verifyToken = jwt.verify(token, process.env.SECRECT_KEY);

    if (validuser && verifyToken._id) {
      const newpassword = await bcrypt.hash(password, 12);

      const setnewuserpass = await User.findByIdAndUpdate({ _id: id }, { password: newpassword });

      setnewuserpass.save();
      res.status(201).json({ status: 201, message: "Password changed", setnewuserpass })
      console.log(newpassword);

    } else {
      res.status(401).json({ status: 401, message: "user not exist" })
    }
  } catch (error) {
    res.status(401).json({ status: 401, error })
  }
})



app.listen(PORT, () => console.log(`The server started in: ${PORT} ✨✨`));


