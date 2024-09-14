import express, { Request, Response, NextFunction } from 'express';
import { config } from 'dotenv';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import appRouter from './routes/index'; // Adjust import according to your file structure

// Load environment variables
config();

const app = express();

// Define allowed origins
const allowedOrigins = [
  "http://localhost:5173",
  "https://mern-rusty-bot-ptu8-qxv03ihxe-john-linus-miracles-projects.vercel.app"
];

// Configure CORS
app.use(cors({
  origin: (origin, callback) => {
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Middleware
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || ''));

// Remove after production
app.use(morgan("dev"));

// Routes
app.use("/api/v1", appRouter);

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  res.status(500).json({ error: err.message });
});

export default app;
