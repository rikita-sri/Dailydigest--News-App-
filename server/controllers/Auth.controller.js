import { handleError } from "../helpers/handleError.js";
import User from "../models/user.model.js";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
export const Register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    // Check if the user already exists
    const checkuser = await User.findOne({ email });
    if (checkuser) {
      return next(handleError(409, "User already registered."));
    }

    // Count number of users in the database
    const userCount = await User.countDocuments();

    // Determine role based on whether this is the first user
    const role = userCount === 0 ? "admin" : "user";

    const hashedPassword = bcryptjs.hashSync(password);

    // Register the new user with assigned role
    const user = new User({
      name,
      email,
      password: hashedPassword,
      role, // new role field
    });

    await user.save();

    res.status(200).json({
      success: true,
      message: "Registration successful.",
    });
  } catch (error) {
    next(handleError(500, error.message));
  }
};

export const Login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      next(handleError(404, "Invalid login credentials."));
    }
    const hashedPassword = user.password;

    const comparePassword = bcryptjs.compare(password, hashedPassword);
    if (!comparePassword) {
      next(handleError(404, "Invalid login credentials."));
    }

    const token = jwt.sign(
      {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
      },
      process.env.JWT_SECRET
    );

    res.cookie("access_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "Lax" : "strict",
      path: "/",
    });

    const newUser = user.toObject({ getters: true });
    delete newUser.password;
    res.status(200).json({
      success: true,
      user: newUser,
      message: "Login successful.",
    });
  } catch (error) {
    next(handleError(500, error.message));
  }
};

export const GoogleLogin = async (req, res, next) => {
  try {
    const { name, email, avatar } = req.body;
    let user;
    user = await User.findOne({ email });
    if (!user) {
      //  create new user
      const password = Math.random().toString();
      const hashedPassword = bcryptjs.hashSync(password);
      const newUser = new User({
        name,
        email,
        password: hashedPassword,
        avatar,
      });

      user = await newUser.save();
    }

    const token = jwt.sign(
      {
        _id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
      },
      process.env.JWT_SECRET
    );

    res.cookie("access_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      path: "/",
    });

    const newUser = user.toObject({ getters: true });
    delete newUser.password;
    res.status(200).json({
      success: true,
      user: newUser,
      message: "Login successful.",
    });
  } catch (error) {
    next(handleError(500, error.message));
  }
};

export const Logout = async (req, res, next) => {
  try {
    res.clearCookie("access_token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      path: "/",
    });

    res.status(200).json({
      success: true,
      message: "Logout successful.",
    });
  } catch (error) {
    next(handleError(500, error.message));
  }
};
