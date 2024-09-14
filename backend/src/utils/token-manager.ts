import { Request,Response,NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { COOKIE_NAME } from './constants.js';

//Create a fucntion that creates a token
export const createToken = (id:string,email:string,expiresIn) => {
    const payload = {id,email};
    //Encryting the payload to create a jwt token
    const token = jwt.sign(payload,process.env.JWT_SECRET,{
        expiresIn,
    });
    return token;
}

//A function to verify the token
export const verifyToken = async (req:Request,res:Response,next:NextFunction) => {
    const token = req.signedCookies[`${COOKIE_NAME}`];
    if (!token || token.trim() === ""){
        return res.status(401).json({message: "Token not Received"});
    }
    console.log(token) //it is an object that can contain the data contained in the cookies
    return new Promise<void>((resolve,reject) => {
        return jwt.verify(token,process.env.JWT_SECRET,(err,success)=>{
            if(err){
                reject(err.message);
                return res.status(401).json({message:"Token Expired"});
            }else{
                console.log("Token Verification Successful");
                resolve();
                res.locals.jwtData = success; //Set some local variables which can be used in the next middleware
                return next();//Go to the next middleware
            }
        })
    })
}


//cookie parser: used to send cookies from backend to frontend
