import app from "./app.js";
import { connectToDatabase,disconnetFromDatabase } from "./db/connection.js";

//Connections and Listeners
const PORT = process.env.PORT || 5000;
connectToDatabase().then(()=> {
    app.listen(PORT, () => console.log("Server Open and Connected to Database"));
}).catch(err=>console.log(err));







































//Get - Get some data from backend
//Put - Update or modify some data in the backend
//Post - Send some data
//Delete - Delete some data
//Middleware are functions that handle the requests

//Routes
// app.get("/hello",(req,res,next) => {
//   return res.send("Hello");
// });

// app.post("/respond", (req,res,next) => {
//   console.log(req.body.NAME);   //Output shown in terminal
//   return res.send("Hi");        //Response shown in website
// });

// app.put("/p", (req,res,next) => {
//   console.log(req.body.NAME);   //Output shown in terminal
//   return res.send("Hi");        //Response shown in website
// });

// app.delete("/d", (req,res,next) => {
//   console.log(req.body.NAME);   //Output shown in terminal
//   return res.send("Hi");        //Response shown in website
// });

//Dynamic Routing
// app.delete("/user/:id", (req,res,next) => {
//   console.log(req.params.id);   //Output shown in terminal
//   return res.send("Hi");        //Response shown in website
// });
