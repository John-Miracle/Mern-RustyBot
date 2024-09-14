import { Response, Request, NextFunction } from 'express';
import User from "../models/User.js";
import { hash, compare } from 'bcrypt';
import { createToken } from '../utils/token-manager.js';
import { COOKIE_NAME } from '../utils/constants.js';

export const getAllUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const users = await User.find();
        return res.status(200).json({ message: "OK", users });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
}

export const userSignup = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(401).send("User already registered");

        const hashedPassword = await hash(password, 10);
        const user = new User({ name, email, password: hashedPassword });

        await user.save();

        // Clear previous cookie
        res.clearCookie(COOKIE_NAME, {
            httpOnly: true,
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
            httpOnly: true,
            signed: true,
            secure: true // Ensure this is set if using HTTPS
        });

        return res.status(201).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
}

export const userLogin = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).send("User not Registered");
        }

        const isPasswordCorrect = await compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(403).send("Incorrect Password");
        }

        // Clear previous cookie
        res.clearCookie(COOKIE_NAME, {
            httpOnly: true,
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
            httpOnly: true,
            signed: true,
            secure: true // Ensure this is set if using HTTPS
        });

        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
}

export const verifyUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const userId = res.locals.jwtData?.id; // Ensure this is set correctly
        const user = await User.findById(userId);
        if (!user) {
            return res.status(401).send("User not Registered or Token malfunction");
        }

        if (user._id.toString() !== userId) {
            return res.status(401).send("Permissions do not match");
        }

        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
}

export const userLogout = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const userId = res.locals.jwtData?.id; // Ensure this is set correctly
        const user = await User.findById(userId);
        if (!user) {
            return res.status(401).send("User not Registered or Token malfunction");
        }

        if (user._id.toString() !== userId) {
            return res.status(401).send("Permissions do not match");
        }

        res.clearCookie(COOKIE_NAME, {
            httpOnly: true,
            domain: ".vercel.app",
            signed: true,
            path: "/",
            secure: true // Ensure this is set if using HTTPS
        });

        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "ERROR", cause: error.message });
    }
}

// HTTP Status Codes
// 200: OK
// 201: Created
// 401: Unauthorized
// 403: Forbidden
// 500: Internal Server Error
