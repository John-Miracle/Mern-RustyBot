import axios from "axios";

//Create functions for communication with backend
export const loginUser = async (email:string,password:string) => {
    const res = await axios.post("/users/login",{ email,password });
    console.log("Hello",res.status);
    if(res.status !== 200){
        console.log("Hello I think you might be wrong");
        throw new Error("Unable to login");
    }
    const data = res.data;
    return data;
};

//Function to check status of token already in browswer
export const checkAuthStatus = async () => {
    const res = await axios.get("/users/auth-status");
    console.log("Hello",res.status);
    if(res.status !== 200){
        throw new Error("Unable to authenticate");
    }
    const data = res.data;
    return data;
};

//Function to check status of token already in browswer
export const sendChatRequest = async (message:string) => {
    const res = await axios.post("/chat/new",{message});
    console.log("Hello",res.status);
    if(res.status !== 200){
        throw new Error("Unable to send message");
    }
    const data = res.data;
    return data;
};

//Function to get all the chats of the user from the database
export const getUserChats = async () => {
    const res = await axios.get("/chat/all-chats");
    console.log("Hello",res.status);
    if(res.status !== 200){
        throw new Error("Unable to get user chat");
    }
    const data = res.data;
    return data;
};

//Function to delete the chats of all users
export const deleteUserChats = async () => {
    const res = await axios.delete("/chat/delete");
    console.log("Hello",res.status);
    if(res.status !== 200){
        throw new Error("Unable to delete the chats");
    }
    const data = res.data;
    return data;
};

//Functio to logout the user
export const logoutUser = async () => {
    const res = await axios.get("/users/logout");
    console.log("Hello",res.status);
    if(res.status !== 200){
        throw new Error("Unable to logout the user");
    }
    const data = res.data;
    return data;
};

export const signupUser = async (name:string,email:string,password:string) => {
    const res = await axios.post("/users/signup",{ name,email,password });
    if(res.status !== 201){
        throw new Error("Unable to SignUp");
    }
    const data = res.data;
    return data;
};