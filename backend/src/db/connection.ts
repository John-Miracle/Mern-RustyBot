import { connect, disconnect } from "mongoose";

async function connectToDatabase() {
    try{
        await connect(process.env.MONGODB_URL);
    }
    catch(error){
        console.log("Error");
        throw new Error("Cannot connect to Database");
    }
}

async function disconnetFromDatabase() {
    try{
        await disconnect();
    }
    catch(error){
        throw new Error("Could not disconnect from the Database");
    }
}

export {connectToDatabase, disconnetFromDatabase};