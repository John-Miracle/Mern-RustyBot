import {Router} from 'express';
import { getAllUsers, userSignup, userLogin, verifyUser, userLogout } from '../controllers/user-controllers.js';
import { loginValidator, signupValidator, validate } from '../utils/validators.js';
import { verifyToken } from '../utils/token-manager.js';

//Creating Router 
const userRoutes = Router();

//Get all users
userRoutes.get("/",getAllUsers);

//User SignUp
userRoutes.post("/signup",validate(signupValidator),userSignup);

//User Login
userRoutes.post("/login",validate(loginValidator),userLogin);
export default userRoutes;

//An middleware function to verify the token
userRoutes.get("/auth-status", verifyToken, verifyUser); 

//Logout
userRoutes.get("/logout",verifyToken,userLogout);

// Middleware are functions that gets executed before the request is processed 
//Can be used to check JSON body validations, Tokens, Cookies Validations, Params Validation

