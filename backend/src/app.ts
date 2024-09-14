import express from "express";
import { config } from 'dotenv';
import morgan from 'morgan';
import appRouter from "./routes/index.js";
import cookieParser from "cookie-parser";
import cors from "cors";
config();

const app = express();

//Read the sent data
//It tells the app that we'll be using JSON format for incoming and outgoing data and will forwared sent data to JSON
//MiddleWare
app.use(cors({origin:"http://localhost:5173",credentials:true})); //We can access this server only from this domain
app.use(express.json());   
app.use(cookieParser(process.env.COOKIE_SECRET));

//Remove after production
app.use(morgan("dev"));

app.use("/api/v1",appRouter);

export default app;