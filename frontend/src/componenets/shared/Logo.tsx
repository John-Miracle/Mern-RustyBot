import { Typography } from "@mui/material";
//import React from "react";
import {Link} from "react-router-dom";
const Logo = () =>{
    return <div style={{
        display:"flex",
        marginRight:"auto",
        alignItems: "center",
        gap: "15px"
    }}
    >
        <Link to = {"/"}>
            <img src="Chatbot.gif" 
            alt="openai" 
            width={"45px"} 
            height={"45px"}
            //className="image-inverted"
            style={{borderRadius:50,marginTop:7}}
            />
        </Link>
        <Typography sx={{
                display:{md:"block",sm:"none",xs:"none"},
                mr: "auto",
                fontWeight:"800",
                textShadow: "2px 2px 20px #000"
                }}>
                    <span style={{fontSize:"24px",color:"yellow"}}>Rusty</span><span style={{fontSize:"25px"}}>BOT</span>
        </Typography>
    </div>;
};

export default Logo;