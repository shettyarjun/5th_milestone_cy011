import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import multer from "multer";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import session from "express-session";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import fetch from "node-fetch"; 
import { User, Food, Order } from "./model.js";
dotenv.config();

mongoose.connect("mongodb+srv://s09082003:hsshreyas00@cluster0.umllk4h.mongodb.net/FoodApp");

const db = mongoose.connection;

db.on("error", console.error.bind(console, "MongoDB connection error"));

db.once("open", () => {
  console.log("MongoDB connected");
});

const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET || "arjun",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());

// Routes

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async function (req, res) {
  try {
    let foundUsers = await User.find({ secret: { $ne: null } });
    if (foundUsers) {
      console.log(foundUsers);
      res.render("secrets.ejs", { usersWithSecrets: foundUsers });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  const role = req.body.role;

  try {
    const user = await User.findOne({ email });
    if (user) {
      res.redirect("/login");
    } else {
      const hash = await bcrypt.hash(
        password,
        Number(process.env.SALTROUNDS) || 10
      );
      const newUser = new User({
        _id: new mongoose.Types.ObjectId(),
        email,
        password: hash,
        role,
      });
      await newUser.save();
      req.login(newUser, (err) => {
        if (err) {
          console.error("Error during login:", err);
        } else {
          res.redirect("/secrets");
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/submit", function (req, res) {
  console.log(req.user, "submitUser");
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async function (req, res) {
  if (req.isAuthenticated()) {
    console.log(req.body);
    console.log(req.user, "user");
    console.log(req.body.secret, "secret");

    try {
      if (req.body && req.body.secret) {
        let updatedUser = await User.findOneAndUpdate(
          { googleId: req.user.googleId },
          { $set: { feedback: req.body.secret } },
          { new: true }
        );
        console.log(updatedUser, "updatedUser");
        res.send("feedback updated");
      } else {
        res
          .status(400)
          .json({ error: "Bad Request. Missing secret in request body." });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
});

passport.use(
  "local",
  new LocalStrategy(async function verify(email, password, cb) {
    try {
      const user = await User.findOne({ email: email });

      if (user) {
        const storedHashedPassword = user.password;
        const valid = await bcrypt.compare(password, storedHashedPassword);

        if (valid) {
          return cb(null, user);
        } else {
          return cb(null, false);
        }
      } else {
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      console.log(err, "local error");
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(accessToken);
        console.log(profile);
        const user = await User.findOne({ email: profile.email });

        if (!user) {
          const newUser = new User({
            email: profile.email,
            googleId: profile.id,
          });
          await newUser.save();
          return cb(null, newUser);
        } else {
          return cb(null, user);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, String(user._id));
});

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await User.findById(id);
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

// Handle the POST request to add food
app.post("/add-food", async (req, res) => {
  try {
    const { id, name, description, price, image, category } = req.body;
    if (req.body) {
      const newfood = new Food({
        id,
        name,
        description,
        price,
        image,
        category,
      });
      await newfood.save();
      res.json({
        success: true,
        message: "Food added successfully",
       });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Handle the GET request to get all food
app.get("/get-food", async (req, res) => {
  try {
    const foods = await Food.find();
    res.json(foods);
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Mock Payment Endpoint
app.post("/mock-payment", async (req, res) => {
  try {
    // Perform mock payment processing (replace this with actual payment processing code)
    const paymentDetails = {
      paymentStatus: "success",
      transactionId: "mock_transaction_id",
    };

    res.json(paymentDetails);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Handle the POST request to add order
app.post("/add-order", async (req, res) => {
  try {
    const { foodId, userId, userAddressId, paymentMode } = req.body;

    // Mock payment processing (replace this with actual payment processing code)
    const paymentDetailsResponse = await fetch("http://localhost:3000/mock-payment", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });

    const paymentDetails = await paymentDetailsResponse.json();

    // Create a new order
    const order = new Order({
      foodId,
      userId,
      status: "pending", // Set the initial status as pending
      userAddressId,
      paymentMode,
      invoiceId: paymentDetails.transactionId, // Store invoice ID from payment gateway
      paymentDetails,
    });

    // Save the order to the database
    await order.save();

    res.json({ success: true, message: "Order added successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Handle the PUT request for updating order status
app.put("/update-order/:orderId", async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const { status } = req.body;

    const updatedOrder = await Order.findOneAndUpdate(
      { orderId },
      { $set: { status }, $currentDate: { updatedAt: true } },
      { new: true }
    );

    if (!updatedOrder) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.json(updatedOrder);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Handle the GET request to search for food
app.get("/search-food", async (req, res) => {
  try {
    const { keyword } = req.query;
    const regex = new RegExp(keyword, "i");

    const foundFoods = await Food.find({
      $or: [{ name: { $regex: regex } }, { description: { $regex: regex } }],
    });

    res.json(foundFoods);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Handle the GET request to filter food by category
app.get("/filter-food", async (req, res) => {
  try {
    const { category } = req.query;

    const foundFoods = await Food.find({ category });

    res.json(foundFoods);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Implement auto-recommendations based on entered letters. 
app.get("/auto-recommendation", async (req, res) => {
  try {
    const { keyword } = req.query;
    const regex = new RegExp(keyword, "i");

    const foundFoods = await Food.find({
      name: { $regex: regex },
    });

    res.json(foundFoods);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.post("/submit", upload.single("image"), async function (req, res) {

    try {
      if (req.body) {
        const feedback = parseInt(req.body.feedback, 10); // Assuming feedback is a number

        // Save image to the order collection (adjust based on your storage preference)
        const image = req.file ? req.file.buffer.toString("base64") : null;

        // Save text file data to the order collection
        const textData = req.file ? req.file.buffer.toString("utf-8") : null;

        let updatedUser = await User.findOneAndUpdate(
          { googleId: req.user.googleId },
          {
            $set: {
              feedback: req.body.secret,
              image: image,
              textData: textData,
            },
          },
          { new: true }
        );

        console.log(updatedUser, "updatedUser");
        res.send("Feedback updated");
      } else {
        res
          .status(400)
          .json({ error: "Bad Request. Missing secret in the request body." });
      }
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
