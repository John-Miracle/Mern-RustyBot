import { Avatar, Box, Typography } from "@mui/material"
import { useAuth } from "../../context/Auth-Context";
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { coldarkDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

function extractCodeFromString(message:string) {
    if(typeof message === "string" && message.includes("```")) {
        const blocks = message.split("```").filter(block => block.trim() !== '');
        console.log(blocks);
        return blocks;
    }
}

//Check if the given string in a block is a code block or not 
function isCodeBlock(str:string) {
    if(str.includes("=") || str.includes(";") || str.includes("[") || str.includes("]") || str.includes("{") || str.includes("}") || str.includes("#") || str.includes("//")){
        return true;
    }
    return false;
}

export const ChatItem = ({content,role}:{content:string,role:"user" | "assistant"}) => {
    const auth = useAuth();
    const messageBlocks = extractCodeFromString(content);
    return role === "assistant" ? (
    <Box sx={{display:"flex",p:1,bgcolor:"#004d5612",m:1,gap:2,borderRadius:5,wordBreak: "break-word",overflowWrap: "break-word"}}>
        {/* <Avatar sx={{ml:"0",height:"45px",width:"45px"}}> */}
        <img src="Chatbot.gif" 
            alt="openai" 
            width={"45px"} 
            height={"45px"}
            //className="image-inverted"
            style={{borderRadius:50,marginTop:7}}
            />
        {/* </Avatar> */}
        <Box style={{overflowX:"auto",alignContent:"center"}}>
            {/* <Typography fontSize={"20px"}>{content}</Typography> */}
            {!messageBlocks && (<Typography sx={{ whiteSpace:"pre-wrap"}} fontSize={"15px"}>{content}</Typography>)}
            {messageBlocks &&  
                messageBlocks.length && 
                messageBlocks.map((block) => isCodeBlock(block) ? 
                <SyntaxHighlighter style={coldarkDark} language="javascript">
                    {block}
                </SyntaxHighlighter> 
                : <Typography sx={{ whiteSpace:"pre-wrap"}}fontSize={"15px"}>{block}</Typography>)}
        </Box>  
    </Box> 
    ):(
        <Box sx={{display:"flex",p:1,bgcolor:"#004d56",m:1,gap:2,borderRadius:"10px",wordBreak: "break-word",overflowWrap: "break-word"}}>
            <Avatar sx={{ml:"0",bgcolor:'black',color:'white',height:"30px",width:"30px",fontSize:"15px"}}>
                {auth?.user?.name[0]}
            </Avatar>
            <Box style={{alignContent:"center"}}>
                {!messageBlocks && (<Typography sx={{ whiteSpace:"pre-wrap"}} fontSize={"15px"}>{content}</Typography>)}
                {messageBlocks &&  messageBlocks.length && messageBlocks.map((block) => isCodeBlock(block) ? 
                    (<SyntaxHighlighter style={coldarkDark} language="javascript">
                        {block}
                    </SyntaxHighlighter> 
                    ): (<Typography sx={{ whiteSpace:"pre-wrap"}} fontSize={"15px"}>{block}</Typography>))}
            </Box>
    </Box>)
}