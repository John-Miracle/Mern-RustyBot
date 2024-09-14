import User from "../models/User.js";
import { hash, compare } from 'bcrypt';
import { createToken } from '../utils/token-manager.js';
import { COOKIE_NAME } from '../utils/constants.js';
export const getAllUsers = async (req, res, next) => {
    //get all users
    try {
        const users = await User.find();
        return res.status(200).json({ message: "OK", users });
    }
    catch (error) {
        console.log(error);
        return res.status(200).json({ message: "ERROR", cause: error.message });
    }
};
export const userSignup = async (req, res, next) => {
    //user Signup
    try {
        //Taking the values from the body and assigning it to different variables
        const { name, email, password } = req.body;
        //Check if the user already exists 
        const existingUser = await User.findOne({ email });
        if (existingUser)
            return res.status(401).send("User already registered");
        //Creating a hashed password 
        const hashedPassword = await hash(password, 10);
        //Creating a new User 
        const user = new User({ name, email, password: hashedPassword });
        //save record in the database
        await user.save();
        //Remove previous Cookies of the user and create new cookie
        res.clearCookie(COOKIE_NAME, {
            httpOnly: true,
            domain: ".vercel.app",
            signed: true,
            path: "/",
        });
        //Creating token for user 
        const token = createToken(user._id.toString(), user.email, "7d");
        //Creation and Storage of Expiration date object
        const expires = new Date();
        expires.setDate(expires.getDate() + 7);
        //Sending cookie from backend to frontend
        res.cookie(COOKIE_NAME, token, {
            path: "/",
            domain: ".vercel.app",
            expires, httpOnly: true,
            signed: true
        });
        //id stored in object format hence has to be converted into a string before being displayed as a response
        return res.status(201).json({ message: "OK", name: user.name, email: user.email });
    }
    catch (error) {
        console.log(error);
        return res.status(200).json({ message: "ERROR", cause: error.message });
    }
};
export const userLogin = async (req, res, next) => {
    //user Signup
    try {
        const { email, password } = req.body;
        //Queries the database to find a user with the matching email 
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).send("User not Registered");
        }
        //Checking if the given password is valid
        const isPasswordCorrect = await compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(403).send("Incorrect Password");
        }
        //Remove previous Cookies of the user and create new cookie
        res.clearCookie(COOKIE_NAME, {
            httpOnly: true,
            domain: ".vercel.app",
            signed: true,
            path: "/",
        });
        //Creating token for user 
        const token = createToken(user._id.toString(), user.email, "7d");
        //Creation and Storage of Expiration date object
        const expires = new Date();
        expires.setDate(expires.getDate() + 7);
        //Sending cookie from backend to frontend
        res.cookie(COOKIE_NAME, token, {
            path: "/",
            domain: ".vercel.app",
            expires, httpOnly: true,
            signed: true
        });
        //console.log("I think Sign in is not working but not fully"); 
        //id stored in object format hence has to be converted into a string before being displayed as a response
        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    }
    catch (error) {
        console.log(error);
        return res.status(200).json({ message: "ERROR", cause: error.message });
    }
};
export const verifyUser = async (req, res, next) => {
    try {
        const user = await User.findById(res.locals.jwtData.id);
        if (!user) {
            return res.status(401).send("User not Registered or Token malfunction");
        }
        console.log(user._id.toString(), res.locals.jwtData.id);
        if (user._id.toString() !== res.locals.jwtData.id) {
            return res.status(401).send("Permissions do not match");
        }
        //console.log("I think Sign in is not working but not fully"); 
        //id stored in object format hence has to be converted into a string before being displayed as a response
        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    }
    catch (error) {
        console.log(error);
        return res.status(200).json({ message: "ERROR", cause: error.message });
    }
};
export const userLogout = async (req, res, next) => {
    try {
        const user = await User.findById(res.locals.jwtData.id);
        if (!user) {
            return res.status(401).send("User not Registered or Token malfunction");
        }
        console.log(user._id.toString(), res.locals.jwtData.id);
        if (user._id.toString() !== res.locals.jwtData.id) {
            return res.status(401).send("Permissions do not match");
        }
        //Remove previous Cookies of the user and create new cookie
        res.clearCookie(COOKIE_NAME, {
            httpOnly: true,
            domain: ".vercel.app",
            signed: true,
            path: "/",
        });
        //id stored in object format hence has to be converted into a string before being displayed as a response
        return res.status(200).json({ message: "OK", name: user.name, email: user.email });
    }
    catch (error) {
        console.log(error);
        return res.status(200).json({ message: "ERROR", cause: error.message });
    }
};
//200: OK
//201: Created
//403: Forbidden
//422: Unprocessable Entity
//# sourceMappingURL=user-controllers.js.map
