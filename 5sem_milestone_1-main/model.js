import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  role: { type: String, enum: ["user", "admin", "superuser"], default: "user" },
}, { timestamps: true });

const foodSchema = new mongoose.Schema({
  id: String,
  name: String,
  description: String,
  price: Number,
  image: String,
  category: { type: String, enum: ["veg", "non-veg", "dessert"], default: "non-veg"},
}, { timestamps: true });

const orderSchema = new mongoose.Schema({
  foodId: String,
  userId: String,
  orderId: String,
  status: String,
  userAddressId: String,
  paymentMode: { type: String, enum: ["cash", "card", "upi"], default: "cash"},
  feedback: {
    type: Number,
    min: 1,
    max: 5,
  },
  image: {
    type: String,
  },
  textData: {
    type: String,
  },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Food = mongoose.model("Food", foodSchema);
const Order = mongoose.model("Order", orderSchema);

// Exporting as an object
export { User, Food, Order };
