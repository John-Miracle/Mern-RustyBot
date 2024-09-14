import { Request,Response,NextFunction } from "express";
import OpenAI from "openai";
import User from "../models/User.js";

export const generateChatCompletion = async (req: Request,res: Response, next:NextFunction) => {
    const {message} =req.body;
    // const user = await User.findById(res.locals.jwtData.id);
    // if(!user) return res.status(401).json({message:"User not Registered or Token malfunction"});
    try {
        const user = await User.findById(res.locals.jwtData.id);
        if (!user) {
            return res.status(401).json({ message: "User is not registered or Token malfunctioned" });
        }

        //Grab all chats of the user 
        const openAIConversations = user.chats.map(({ role, content }) => ({role,content,})) as OpenAI.Chat.CreateChatCompletionRequestMessage[];
        openAIConversations.push({ content: message, role: "user" }); //Push the latest message to the chat
        user.chats.push({ content: message, role: "user" }); //Push the messages of the user to the main database
        
        //Configure OpenAI
        const openai = new OpenAI({
        apiKey: process.env.OPEN_AI_SECRET,
        organization: process.env.OPENAI_ORGANIZATION_ID,
        });

        // Send all the chats to OpenAI API
        const chatResponse = await openai.chat.completions.create({
            model: "gpt-3.5-turbo",
            messages: openAIConversations,
        });
        console.log(chatResponse.choices[0].message.content);
        
        // Update user chats with the AI response
        user.chats.push(chatResponse.choices[0].message);

        // Save user with updated chats
        await user.save();

        return res.status(200).json({ chats: user.chats });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Something went wrong!" });
    }
};

export const sendChatsToUser = async (req: Request,res: Response, next:NextFunction) => {
    try{
        const user = await User.findById(res.locals.jwtData.id);
        if (!user){
            return res.status(401).send("User not Registered or Token malfunction");
        }

        console.log(user._id.toString(),res.locals.jwtData.id);

        if (user._id.toString() !== res.locals.jwtData.id){
            return res.status(401).send("Permissions do not match");
        }
        //console.log("I think Sign in is not working but not fully"); 
        //id stored in object format hence has to be converted into a string before being displayed as a response
        return res.status(200).json({message: "OK",chats: user.chats});
    }
    catch(error){
        console.log(error);
         
        return res.status(200).json({message:"ERROR",cause:error.message});
    }
}

export const deleteChats = async (req: Request,res: Response, next:NextFunction) => {
    try{
        const user = await User.findById(res.locals.jwtData.id);
        if (!user){
            return res.status(401).send("User not Registered or Token malfunction");
        }

        console.log(user._id.toString(),res.locals.jwtData.id);

        if (user._id.toString() !== res.locals.jwtData.id){
            return res.status(401).send("Permissions do not match");
        }
        //@ts-ignore
        //Deleting the chats of the user 
        user.chats = [];
        user.save();
        
        //console.log("I think Sign in is not working but not fully"); 
        //id stored in object format hence has to be converted into a string before being displayed as a response
        return res.status(200).json({message: "OK"});
    }
    catch(error){
        console.log(error);
         
        return res.status(200).json({message:"ERROR",cause:error.message});
    }
}