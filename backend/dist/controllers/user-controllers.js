import User from "../models/User.js";
import { hash, compare } from 'bcrypt';
import { createToken } from '../utils/token-manager.js';
import { COOKIE_NAME } from '../utils/constants.js';

export const getAllUsers = async (req, res, next) => {
    try {
        const users = await User.find();
        return res.status(200).json({ message: "OK", users });
    } catch (error) {
        console.error(error); // Use console.error for logging errors
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
};

export const userSignup = async (req, res, next) => {
    try {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(401).send("User already registered");

        const hashedPassword = await hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });

        await user.save();

        // Clear previous cookie
        res.clearCookie(COOKIE_NAME, {
            domain: ".vercel.app",
            signed: true,
            path: "/",
            secure: true // Ensure this is set if using HTTPS
        });

        const token = createToken(user._id.toString(), user.email, "7d");

        const expires = new Date();
        expires.setDate(expires.getDate() + 7);

        res.cookie(COOKIE_NAME, token, {
            path: "/",
            domain: ".vercel.app",
            expires,
            signed: true,
            secure: true // Ensure this is set if using HTTPS
        });

        return res.status(201).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.error(error); // Use console.error for logging errors
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
};

export const userLogin = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) return res.status(401).send("User not Registered");

        const isPasswordCorrect = await compare(password, user.password);
        if (!isPasswordCorrect) return res.status(403).send("Incorrect Password");

        // Clear previous cookie
        res.clearCookie(COOKIE_NAME, {
            domain: ".vercel.app",
            signed: true,
            path: "/",
            secure: true // Ensure this is set if using HTTPS
        });

        const token = createToken(user._id.toString(), user.email, "7d");

        const expires = new Date();
        expires.setDate(expires.getDate() + 7);

        res.cookie(COOKIE_NAME, token, {
            path: "/",
            domain: ".vercel.app",
            expires,
            signed: true,
            secure: true // Ensure this is set if using HTTPS
        });

        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.error(error); // Use console.error for logging errors
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
};

export const verifyUser = async (req, res, next) => {
    try {
        const userId = res.locals.jwtData?.id; // Ensure this is set correctly
        const user = await User.findById(userId);
        if (!user) return res.status(401).send("User not Registered or Token malfunction");

        if (user._id.toString() !== userId) return res.status(401).send("Permissions do not match");

        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.error(error); // Use console.error for logging errors
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
};

export const userLogout = async (req, res, next) => {
    try {
        const userId = res.locals.jwtData?.id; // Ensure this is set correctly
        const user = await User.findById(userId);
        if (!user) return res.status(401).send("User not Registered or Token malfunction");

        if (user._id.toString() !== userId) return res.status(401).send("Permissions do not match");

        // Clear previous cookie
        res.clearCookie(COOKIE_NAME, {
            domain: ".vercel.app",
            signed: true,
            path: "/",
            secure: true // Ensure this is set if using HTTPS
        });

        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.error(error); // Use console.error for logging errors
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
};
