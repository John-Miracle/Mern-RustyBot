//import React from "react";

import { Box} from "@mui/material";
// import { Box, useMediaQuery, useTheme } from "@mui/material";
import TypingAnim from "../componenets/typer/TypingAnim";
// import { Footer } from "../componenets/footer/Footer";

const Home= () =>{
    // const theme = useTheme();
    // const isBelowMd = useMediaQuery(theme.breakpoints.down("md"));

    return <Box width={"100%"} height={'100%'}>
        <Box sx={{display:"flex",width:"100%",flexDirection:'column',alignItems:'center',mt:7,gap:4}}>
            <Box sx={{display:"flex",width:"100%"}}>
                <img src="Home Page.gif" alt="chatbot" style={{display:'flex',margin:'auto',width:"60%",borderRadius:20,boxShadow:"-5px -5px 50px #64f3d5",marginTop:20,marginBottom:20}}/>
            </Box>
            <Box sx={{display:"flex"}}><TypingAnim /></Box>
        </Box>
    </Box>
};

export default Home;