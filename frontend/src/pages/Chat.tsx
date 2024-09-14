// //import React from "react";

import { Box, Button, Dialog, DialogActions, DialogContent, IconButton, Typography } from "@mui/material"
import { useAuth } from "../context/Auth-Context";
import { red } from "@mui/material/colors";
import { ChatItem } from "../componenets/chat/ChatItem";
import {IoMdMenu, IoMdSend} from 'react-icons/io';
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { deleteUserChats, getUserChats, sendChatRequest } from "../helpers/api-communicator";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import { TypeAnimation } from "react-type-animation";




// const chatMessages = [
//     { role: "user", content: "Hello! How are you?" },
//     { role: "assistant", content: "I'm an AI, so I don't have feelings, but I'm here to help you!" },
//     { role: "user", content: "Can you help me with my homework?" },
//     { role: "assistant", content: "Of course! What subject do you need help with?" },
//     { role: "user", content: "Math, specifically algebra." },
//     { role: "assistant", content: "Great! Do you need help solving equations or understanding concepts?" },
//     { role: "user", content: "I'm struggling with solving equations." },
//     { role: "assistant", content: "No problem! Let's start with a simple example. Solve for x: 2x + 5 = 13." }
// ];

type Messages ={
    role:"user"|"assistant";
    content: string | JSX.Element;
}

const Chat = () =>{
    const navigate = useNavigate();
    const inputRef = useRef<HTMLTextAreaElement | null>(null)
    const auth = useAuth();
    const [chatMessages, setChatMessages] = useState<Messages[]>([]);
    const chatEndRef = useRef<HTMLDivElement | null>(null);
     
    // Function to scroll to the bottom
    const scrollToBottom = () => {
        chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };
    

    //Sending the user request or sending the message 
    const handleSubmit = async() => {
        const content = inputRef.current?.value as string;
        if (!content) {
            return; // Prevents sending empty or whitespace messages
          }
        if(inputRef && inputRef.current) {
            inputRef.current.value = "";
            inputRef.current.style.height = "auto";
        }
        const newMessage: Messages = {role:"user",content}
        setChatMessages((prev) => [...prev, newMessage]);
        
        console.log(inputRef.current?.value);

        // // After adding the user's message, add the bot's response
        // const botMessage: Messages = { role: "assistant", content:<><span style={{ color: "yellow" }}>Rusty</span><span>BOT is under maintenance 🛠️</span></> };

        // // Update the chatMessages state with the bot's response
        // setChatMessages((prev) => [...prev, botMessage]);

        //Send chat 
        const chatData = await sendChatRequest(content);
        setChatMessages([...chatData.chats]);
        scrollToBottom();
    }

    //Deleting the chats 
    const handleDeleteChats = async () => {
        try{
            toast.loading("Clearing Chats",{id:"deletechats"});
            await deleteUserChats();
            setChatMessages([]);
            toast.success("Chats Successfully Cleared",{id:"deletechats"});
        }
        catch(error){
            console.log(error);
            toast.error("Failed to clear Chats",{id:"deletechats"});
        }
    };

    //Runs before rendered on UI 
    //Used to fetch the chats of the user of the current session automatically
    useLayoutEffect(()=> {
        if(auth?.isLoggedIn && auth.user) {
            toast.loading("Loading Chats",{id:"loadchats"});
            getUserChats().then((data)=>{
                setChatMessages([...data.chats])
                toast.success("Chats Successfully Loaded",{id:"loadchats"});
            }).catch(err=>{
                console.log(err);
                toast.error("Failed to Load Chats",{id:"loadchats"});
            });
           
        }
    }, [auth]) //Creating dependency on auth
    
    //Protecting the routes in the frontend
    //Preventing UnAuthorised access to the Chat page 
    useEffect(()=>{
        if(!auth?.user){
            return navigate("/login") //Navigates the user to the login page if the user is not logged in 
        }
    })

    // Update the scroll position whenever chatMessages changes
    useEffect(() => {
        scrollToBottom(); // Automatically scroll when a new message is added
    }, [chatMessages]);

    //Hand the key press
    const handleKeyPress = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            handleSubmit(); // Call the submit function when Enter key is pressed
        }
    };
    const [openOverlay, setOpenOverlay] = useState(false);

    const handleMenuClick = () => {
         setOpenOverlay(true);
    };
 
    const handleCloseOverlay = () => {
        setOpenOverlay(false);
    };
 
    

    const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        const textarea = e.target;
    
        // Reset height to auto to calculate scrollHeight
        textarea.style.height = 'auto';
    
        // Calculate new height
        const newHeight = Math.min(textarea.scrollHeight, 150); // Maximum height
    
        // Only update height if it's greater than current height
        if (newHeight > textarea.clientHeight) {
            textarea.style.height = `${newHeight}px`;
        }
    };
    

    return <Box sx={{
                    display:"flex",
                    flexDirection:"row",
                    flex:1,
                    width:"100%",
                    height:"100%",
                    mt: 1,
                    justifyContent:'center',
    }}>                   
        <Box sx = {{display:{md:"flex",xs:"none",sm:"none"},flex:1,height:{xl:"86.5vh",lg:"83.8vh",md:"83.3vh",sm:"80vh"},width:"100%",justifyContent:"center",alignItems:"center",mx:3,ml:5,mt:"4vh"}}>
            <Box sx={{display:"flex",width:"100%",height:"100%",bgcolor:"rgb(17,29,39)",borderRadius:5,flexDirection:"column",m:"auto",overflow:"auto",alignItems:'center',gap:3}}>
                <Box style={{display:"flex",flexDirection:"row",alignItems:"center",gap:"7px",padding:"20px 20px 0px 20px",marginTop:1}}>
                    <TypeAnimation 
                        sequence={[
                            // Same substring at the start will only be typed once, initially
                            `Hello ${auth?.user?.name}...`,
                            1000,
                            `Hello ${auth?.user?.name}`,
                            1500
                        ]}
                        speed={10}
                        style={{ fontSize: '18px',color: "white",display:"inline-block",textShadow:"1px 1px 20px #000",fontWeight:600}}
                        repeat={Infinity}
                        />
                </Box>
                <Box style-={{alignContent:"center"}}>
                    <img src="Robo.gif" alt="Bot" width="220px" style={{borderRadius:"10px"}}/>
                </Box>
                <Box style={{display:"flex",padding:"0px 10px",justifyContent:"center",flexDirection:"column",flex:1,alignItems:'center',gap:"10px"}}>
                        <Typography style={{ fontSize: '18px',color: "white",display:"inline-block",textShadow:"1px 1px 20px #000",textAlign:"center",fontWeight:600,margin:"7px 10px"}}>
                            Welcome to <span style={{color:"yellow"}}>Rusty</span>BOT <br />
                        </Typography>
                        <Typography style={{ fontSize: '15px',color: "white",display:"inline-block",textShadow:"1px 1px 20px #000",textAlign:"left",flex:1,width:"270px",marginLeft:13}}>
                        I'm here to assist with any questions or tasks you have. Whether you need information, help solving a problem, or just a quick chat, feel free to ask anything—I'm always ready to help!
                        </Typography>
                </Box>
                <Box sx={{bgcolor:"grey",padding:1,width:"80%",justifyContent:"center",borderRadius:2}}>
                    <Typography style={{ fontSize: '16px',color: "white",display:"inline-block",textShadow:"1px 1px 20px #000",flex:1,textAlign:"center",width:"100%",fontWeight:600}}>
                        Model : GPT-3.5 Turbo
                    </Typography>
                </Box>
                <div style={{display:"flex",flex:0.2}}>
                <Button onClick={handleDeleteChats} sx={{width:'250px', color:'white',fontWeight:600,borderRadius:1,mx:'auto',outline: '2px solid red',outlineColor:red[400],":hover":{bgcolor:red.A400},my:2,fontSize:"15px",flex:"flex-end",mb:3}}>
                    Clear Chat
                </Button>
                </div>
            </Box>
        </Box>
        <Box sx={{display:"flex",flexGrow: 4,flexDirection:'column',gap:"5px",width:"100%",mx:3,mt:"4vh"}}>
            {/* <Typography sx={{textAlign:'center',fontSize:"20px",color:"white",mb:2,mx:"auto",fontWeight:"600"}}>
                Model - GPT 3.5 Turbo
            </Typography> */}
            <Box sx={{
                width:"100%",
                height:{xl:"80vh",lg:"76vh",md:"75vh",sm:"76vh",xs:"80vh"},
                borderRadius:3,
                mx:"3 1 3 2",
                display:'flex',
                flexDirection:"column",
                overflow:"scroll",
                overflowX: "hidden",
                overflowY:'auto', 
                scrollBehavior:"smooth",
                "::-webkit-scrollbar": {
                    display: "none",
                },
                /* Hide scrollbar for Firefox */
                scrollbarWidth: "none",
                /* Hide scrollbar for IE, Edge */
                "-ms-overflow-style": "none",
                bgcolor: "#05101c",
   
            }}>
                
                {chatMessages.map((chat, index)=> (
                    //@ts-ignore
                    <ChatItem content={chat.content} role={chat.role} key={index} 
                />))}
                <div ref={chatEndRef} />
            </Box>
            <Box className="Boxman"
                sx={{
                    display:"flex",
                    flexDirection:"row",
                    position:"relative",
                    bottom: 2, // Stick to the bottom of the viewport
                    width: "100%", // Responsive width
                    zIndex: 1000, // Ensure it appears above other elements
                    borderRadius: "10px", // Rounded corners to match modern design
                }} >
                <IconButton
                    sx={{
                        display: { xs: "flex", sm: "flex", md: "none" },
                        color: "white",
                        height: "40px",
                        width: "40px",
                        ml: "3px",
                        
                    }}
                    onClick={handleMenuClick}
                >
                    <IoMdMenu />
                </IconButton>

                <Box
                    sx={{
                        display: "flex",
                        width: "100%",
                        backgroundColor: "rgb(17,27,39)",
                        padding: "0.5% 0.7%",
                        borderRadius: "8px",
                        marginRight: "10px",
                        marginLeft:"1%",
                        overflow: "auto",
                    }}>
                    <textarea
                        placeholder="Send Message..."
                        ref={inputRef}
                        style={{
                            width: "100%",
                            backgroundColor: "transparent",
                            padding: "10px",
                            border: "none",
                            outline: "none",
                            color: "white",
                            fontSize: "15px",
                            resize: "none", // Prevent manual resizing
                            maxHeight: "150px",
                            overflow: "auto", // Limit max height for multiline input
                        }}
                        rows={1}
                        onKeyDown={handleKeyPress}
                        onInput={handleInput}
                    />
                    <IconButton
                        onClick={handleSubmit}
                        sx={{
                            marginLeft: "auto",
                            color: "white",
                            height: "35px",
                            width: "35px",
                        }}>
                        <IoMdSend />
                    </IconButton>
                </Box>
            </Box>


        </Box>
        {/* Overlay Window */}
        <Dialog
                open={openOverlay}
                onClose={handleCloseOverlay}
                sx={{
                    "& .MuiDialog-paper": {
                        width: "90%",
                        maxWidth: "600px",
                        height: "77%",
                        bgcolor: "#05101c",
                        color: "white",
                        borderRadius:5
                    },
                }}
            >
                <DialogContent dividers>
                    <Box sx={{
                        display: "flex",
                        flexDirection: "column",
                        height: "100%",
                        width:"100%",
                        justifyContent: "center",
                        alignItems: "center",
                        overflow: "auto",
                        gap:"30px"
                    }}>
                        <Box sx={{
                            display: "flex",
                            flexDirection: "column",
                            bgcolor: "rgb(17,29,39)",
                            borderRadius: 5,
                            width: "84%",
                            height: "100%",
                            p: 3,
                            gap: 3,
                            alignItems: "center",
                            overflow:"hidden",
                            overflowY:"auto",
                        }}>
                            <TypeAnimation
                                sequence={[
                                    `Hello ${auth?.user?.name}...`,
                                    1000,
                                    `Hello ${auth?.user?.name}`,
                                    1500
                                ]}
                                speed={10}
                                style={{
                                    fontSize: '18px',
                                    color: "white",
                                    textShadow: "1px 1px 20px #000",
                                    fontWeight: 600,
                                    textAlign: "center",
                                }}
                                repeat={Infinity}
                            />
                            <img src="Robo.gif" alt="Bot" width="80%" style={{ borderRadius: "10px" }} />
                            <Box sx={{
                                display: "flex",
                                flexDirection: "column",
                                alignItems: "center",
                                textAlign: "center",
                                gap: 2,
                                width:"90%"
                            }}>
                                <Typography variant="h6" sx={{
                                    color: "white",
                                    textShadow: "1px 1px 20px #000",
                                    fontWeight: 600,
                                    width:"100%",
                                    fontSize:"110%"
                                }}>
                                    Welcome to <span style={{ color: "yellow" }}>Rusty</span>BOT
                                </Typography>
                                <Typography sx={{
                                    fontSize: '80%',
                                    color: "white",
                                    textShadow: "1px 1px 20px #000",
                                    width: "100%",
                                    textAlign:"left",

                                }}>
                                    I'm here to help with any questions or tasks. Whether you need information or just a quick chat, feel free to ask—I'm ready to assist!
                                </Typography>
                            </Box>
                            <Box sx={{bgcolor:"grey",padding:1,width:"80%",justifyContent:"center",borderRadius:2}}>
                                <Typography style={{ fontSize: '16px',color: "white",display:"inline-block",textShadow:"1px 1px 20px #000",flex:1,textAlign:"center",width:"100%",fontWeight:600}}>
                                    Model : GPT-3.5 Turbo
                                </Typography>
                            </Box>
                            <Button
                                onClick={handleDeleteChats}
                                sx={{
                                    width:"80%",
                                    color: 'white',
                                    fontWeight: 600,
                                    borderRadius: 1,
                                    outline: '2px solid red',
                                    outlineColor: red[400],
                                    ":hover": { bgcolor: red.A400 },
                                    my: 2,
                                    fontSize: "80%",
                                }}
                            >
                                Clear Chat
                            </Button>
                        </Box>
                    </Box>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseOverlay} sx={{color:"white",outline:"1px solid",padding:"2px",my:1,mr:2.5,fontSize:"70%"}}>
                        Close
                    </Button>
                </DialogActions>
            </Dialog>
    </Box>;
};

export default Chat;

//import React from "react";
// import { Box, Avatar, Typography, Button, IconButton } from "@mui/material";
// import { useAuth } from "../context/Auth-Context";
// import { red } from "@mui/material/colors";
// import { ChatItem } from "../componenets/chat/ChatItem";
// import { IoMdSend } from "react-icons/io";
// import { useEffect, useLayoutEffect, useRef, useState } from "react";
// import { deleteUserChats, getUserChats, sendChatRequest } from "../helpers/api-communicator";
// import toast from "react-hot-toast";
// import { useNavigate } from "react-router-dom";

// type Messages = {
//   role: "user" | "assistant";
//   content: string | JSX.Element;
// };

// const Chat = () => {
//   const navigate = useNavigate();
//   const inputRef = useRef<HTMLTextAreaElement | null>(null);
//   const auth = useAuth();
//   const [chatMessages, setChatMessages] = useState<Messages[]>([]);
//   const chatEndRef = useRef<HTMLDivElement | null>(null);

//   const scrollToBottom = () => {
//     chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
//   };

//   const handleSubmit = async () => {
//     const content = inputRef.current?.value as string;
//     if (!content.trim()) {
//       return; // Prevent sending empty or whitespace messages
//     }
//     if (inputRef.current) {
//       inputRef.current.value = "";
//       inputRef.current.style.height = "auto";
//     }
//     const newMessage: Messages = { role: "user", content };
//     setChatMessages((prev) => [...prev, newMessage]);

//     const chatData = await sendChatRequest(content);
//     setChatMessages([...chatData.chats]);
//     scrollToBottom();
//   };

//   const handleDeleteChats = async () => {
//     try {
//       toast.loading("Clearing Chats", { id: "deletechats" });
//       await deleteUserChats();
//       setChatMessages([]);
//       toast.success("Chats Successfully Cleared", { id: "deletechats" });
//     } catch (error) {
//       console.log(error);
//       toast.error("Failed to clear Chats", { id: "deletechats" });
//     }
//   };

//   useLayoutEffect(() => {
//     if (auth?.isLoggedIn && auth.user) {
//       toast.loading("Loading Chats", { id: "loadchats" });
//       getUserChats()
//         .then((data) => {
//           setChatMessages([...data.chats]);
//           toast.success("Chats Successfully Loaded", { id: "loadchats" });
//         })
//         .catch((err) => {
//           console.log(err);
//           toast.error("Failed to Load Chats", { id: "loadchats" });
//         });
//     }
//   }, [auth]);

//   useEffect(() => {
//     if (!auth?.user) {
//       navigate("/login"); // Redirect to login if not logged in
//     }
//   }, [auth, navigate]);

//   useEffect(() => {
//     scrollToBottom(); // Automatically scroll when a new message is added
//   }, [chatMessages]);

//   const handleKeyPress = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
//     if (e.key === "Enter" && !e.shiftKey) {
//       e.preventDefault(); // Prevent new line
//       handleSubmit();
//     }
//   };

//   const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
//     e.target.style.height = 'auto'; // Reset height to auto to calculate new height
//     // e.target.style.height = `${e.target.scrollHeight}px`; // Set height based on scrollHeight
//     };

//   return (
//     <Box
//       sx={{
//         display: "flex",
//         flexDirection: "row",
//         flex: 1,
//         width: "100%",
//         height: "100%",
//         mt: 1,
//         gap: 5,
//         justifyContent: "center",
//         alignItems: "center",
//       }}
//     >
//       <Box
//         sx={{
//           display: { md: "flex", xs: "none", sm: "none" },
//           flex: { md: 0.2, xs: "none", xm: "none" },
//           height: "100%",
//           width: "100%",
//           justifyContent: "center",
//           alignItems: "center",
//           mx: 3,
//         }}
//       >
//         <Box
//           sx={{
//             display: "flex",
//             width: "100%",
//             height: "auto",
//             bgcolor: "rgb(17,29,39)",
//             borderRadius: 5,
//             flexDirection: "column",
//             m: "auto",
//             overflow: "auto",
//           }}
//         >
//           <Avatar sx={{ mx: "auto", my: 2, bgcolor: "white", color: "black", fontWeight: 700 }}>
//             {auth?.user?.name[0]}
//           </Avatar>
//           <Typography sx={{ mx: "auto", fontFamily: "work sans" }}>
//             You are talking to a Chatbot
//           </Typography>
//           <Typography sx={{ mx: "auto", fontFamily: "work sans", my: 4, padding: 3 }}>
//             You are welcome to ask any question !!
//           </Typography>
//           <Button
//             onClick={handleDeleteChats}
//             sx={{
//               width: "200px",
//               my: "auto",
//               color: "white",
//               fontWeight: 700,
//               borderRadius: 3,
//               mx: "auto",
//               bgcolor: red[300],
//               ":hover": { bgcolor: red.A400 },
//             }}
//           >
//             Clear Conversation
//           </Button>
//         </Box>
//       </Box>
//       <Box sx={{ display: "flex", flex: { md: 0.8, sm: 1, xs: 1 }, flexDirection: "column", gap: "5px", width: "100%", mx: 3 }}>
//         <Typography sx={{ textAlign: "center", fontSize: "20px", color: "white", mb: 2, mx: "auto", fontWeight: "600" }}>
//           Model - GPT 3.5 Turbo
//         </Typography>
//         <Box
//           sx={{
//             width: "100%",
//             height: "70vh",
//             borderRadius: 3,
//             display: "flex",
//             flexDirection: "column",
//             overflowY: "auto",
//             bgcolor: "#05101c",
//             scrollbarWidth: "none",
//             "-ms-overflow-style": "none",
//             "::-webkit-scrollbar": { display: "none" },
//           }}
//         >
//           {chatMessages.map((chat, index) => (
//              //@ts-ignore
//             <ChatItem content={chat.content} role={chat.role} key={index} />
//           ))}
//           <div ref={chatEndRef} />
//         </Box>
//         <div
//           style={{
//             position: "fixed",
//             bottom: 0,
//             left: 0,
//             width: "100%",
//             padding: "0.5% 0.7%",
//             display: "flex",
//             alignItems: "center",
//           }}
//         >
//           <div style={{ width: "100%", padding: "0.5% 0.1% 0.5% 0.7%", borderRadius: 8, backgroundColor: "rgb(17,27,39)", display: "flex" }}>
//             <textarea
//               placeholder="Enter your message...."
//               ref={inputRef}
//               style={{
//                 width: "100%",
//                 backgroundColor: "transparent",
//                 padding: "10px",
//                 border: "none",
//                 outline: "none",
//                 color: "white",
//                 fontSize: "15px",
//                 resize: "none", // Prevent manual resizing
//                 overflow: "hidden", // Hide the scrollbar
//               }}
//               rows={1} // Minimum number of rows
//               onKeyDown={handleKeyPress}
//               onInput={handleInput}
//             />
//             <IconButton onClick={handleSubmit} sx={{ marginLeft: "auto", color: "white", height: "35px", width: "35px" }}>
//               <IoMdSend />
//             </IconButton>
//           </div>
//         </div>
//       </Box>
//     </Box>
//   );
// };

// export default Chat;

// import React, { useState, useRef, useLayoutEffect, useEffect } from "react";
// import { Box, Button, IconButton, Typography, Dialog, DialogTitle, DialogContent, DialogActions } from "@mui/material";
// import { useAuth } from "../context/Auth-Context";
// import { red } from "@mui/material/colors";
// import { ChatItem } from "../componenets/chat/ChatItem";
// import { IoMdSend, IoMdMenu } from 'react-icons/io';
// import { deleteUserChats, getUserChats, sendChatRequest } from "../helpers/api-communicator";
// import toast from "react-hot-toast";
// import { useNavigate } from "react-router-dom";
// import { TypeAnimation } from "react-type-animation";

// type Messages = {
//     role: "user" | "assistant";
//     content: string | JSX.Element;
// }

// const Chat = () => {
//     const navigate = useNavigate();
//     const inputRef = useRef<HTMLTextAreaElement | null>(null)
//     const auth = useAuth();
//     const [chatMessages, setChatMessages] = useState<Messages[]>([]);
//     const chatEndRef = useRef<HTMLDivElement | null>(null);
//     const [openOverlay, setOpenOverlay] = useState(false);

//     const scrollToBottom = () => {
//         chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
//     };

//     const handleSubmit = async () => {
//         const content = inputRef.current?.value as string;
//         if (!content) return;

//         if (inputRef.current) {
//             inputRef.current.value = "";
//             inputRef.current.style.height = "auto";
//         }

//         const newMessage: Messages = { role: "user", content };
//         setChatMessages(prev => [...prev, newMessage]);

//         const chatData = await sendChatRequest(content);
//         setChatMessages([...chatData.chats]);
//         scrollToBottom();
//     }

//     const handleDeleteChats = async () => {
//         try {
//             toast.loading("Clearing Chats", { id: "deletechats" });
//             await deleteUserChats();
//             setChatMessages([]);
//             toast.success("Chats Successfully Cleared", { id: "deletechats" });
//         } catch (error) {
//             console.log(error);
//             toast.error("Failed to clear Chats", { id: "deletechats" });
//         }
//     };

//     useLayoutEffect(() => {
//         if (auth?.isLoggedIn && auth.user) {
//             toast.loading("Loading Chats", { id: "loadchats" });
//             getUserChats().then((data) => {
//                 setChatMessages([...data.chats])
//                 toast.success("Chats Successfully Loaded", { id: "loadchats" });
//             }).catch(err => {
//                 console.log(err);
//                 toast.error("Failed to Load Chats", { id: "loadchats" });
//             });
//         }
//     }, [auth])

//     useEffect(() => {
//         if (!auth?.user) {
//             return navigate("/login")
//         }
//     })

//     useEffect(() => {
//         scrollToBottom();
//     }, [chatMessages]);

//     const handleKeyPress = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
//         if (e.key === "Enter" && !e.shiftKey) {
//             e.preventDefault();
//             handleSubmit();
//         }
//     };

//     const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
//         const textarea = e.target;

//         textarea.style.height = 'auto';

//         const newHeight = Math.min(textarea.scrollHeight, 150);

//         if (newHeight > textarea.clientHeight) {
//             textarea.style.height = `${newHeight}px`;
//         }
//     };

//     const handleMenuClick = () => {
//         setOpenOverlay(true);
//     };

//     const handleCloseOverlay = () => {
//         setOpenOverlay(false);
//     };

//     return (
//         <Box sx={{
//             display: "flex",
//             flexDirection: "row",
//             flex: 1,
//             width: "100%",
//             height: "100%",
//             mt: 1,
//             justifyContent: 'center',
//         }}>
//             <Box sx={{ display: { md: "flex", xs: "none", sm: "none" }, flex: { md: 0.2, xs: "none", xm: "none" }, height: { xl: "86.5vh", lg: "83.8vh", md: "83.3vh", sm: "80vh" }, width: "100%", justifyContent: "center", alignItems: "center", mx: 3, ml: 5, mt: "4vh" }}>
//                 <Box sx={{ display: "flex", width: "100%", height: "100%", bgcolor: "rgb(17,29,39)", borderRadius: 5, flexDirection: "column", m: "auto", overflow: "auto", alignItems: 'center', minWidth: "43vh", gap: 3 }}>
//                     <Box style={{ display: "flex", flexDirection: "row", alignItems: "center", gap: "7px", padding: "20px 20px 0px 20px" }}>
//                         <TypeAnimation
//                             sequence={[
//                                 `Hello ${auth?.user?.name}...`,
//                                 1000,
//                                 `Hello ${auth?.user?.name}`,
//                                 1500
//                             ]}
//                             speed={10}
//                             style={{ fontSize: '18px', color: "white", display: "inline-block", textShadow: "1px 1px 20px #000", fontWeight: 600 }}
//                             repeat={Infinity}
//                         />
//                     </Box>
//                     <Box style={{ alignContent: "center" }}>
//                         <img src="chat-bot.gif" alt="Bot" width="270px" style={{ borderRadius: "10px" }} />
//                     </Box>
//                     <Box style={{ display: "flex", padding: "10px", justifyContent: "center", flexDirection: "column", flex: 1, alignItems: 'center', gap: "10px" }}>
//                         <Typography style={{ fontSize: '18px', color: "white", display: "inline-block", textShadow: "1px 1px 20px #000", textAlign: "center", fontWeight: 600, margin: "10px" }}>
//                             Welcome to <span style={{ color: "yellow" }}>Rusty</span>BOT <br />
//                         </Typography>
//                         <Typography style={{ fontSize: '15px', color: "white", display: "inline-block", textShadow: "1px 1px 20px #000", textAlign: "left", flex: 1, width: "270px", marginLeft: 13 }}>
//                             I'm here to assist with any questions or tasks you have. Whether you need information, help solving a problem, or just a quick chat, feel free to ask anything—I'm always ready to help!
//                         </Typography>
//                     </Box>
//                     <div style={{ display: "flex", flex: 0.2 }}>
//                         <Button onClick={handleDeleteChats} sx={{ width: '250px', color: 'white', fontWeight: 600, borderRadius: 1, mx: 'auto', outline: '2px solid red', outlineColor: red[400], ":hover": { bgcolor: red.A400 }, my: 2, fontSize: "15px", flex: "flex-end" }}>
//                             Clear Chat
//                         </Button>
//                     </div>
//                 </Box>
//             </Box>
//             <Box sx={{ display: "flex", flex: { md: 0.8, sm: 1, xs: 1 }, flexDirection: 'column', gap: "5px", width: "100%", mx: 3, mt: "4vh" }}>
//                 <Box sx={{
//                     width: "100%",
//                     height: { xl: "80vh", lg: "76vh", md: "75vh", sm: "78vh", xs: "82vh", pixel: "200vh",ipad:"80vh" },
//                     borderRadius: 3,
//                     mx: "3 1 3 2",
//                     display: 'flex',
//                     flexDirection: "column",
//                     overflow: "scroll",
//                     overflowX: "hidden",
//                     overflowY: 'auto',
//                     scrollBehavior: "smooth",
//                     "::-webkit-scrollbar": {
//                         display: "none",
//                     },
//                     scrollbarWidth: "none",
//                     "-ms-overflow-style": "none",
//                     bgcolor: "#05101c",
//                     mb:"-20px"
//                 }}>
//                     {chatMessages.map((chat, index) => (
//                         //@ts-ignore
//                         <ChatItem content={chat.content} role={chat.role} key={index} />
//                     ))}
//                     <div ref={chatEndRef} />
//                 </Box>
//                 <div
//                     style={{
//                         padding: "0.5% 0.7%",
//                         display: "flex",
//                         alignItems: "center",
//                         margin: 3,
//                         borderRadius: "15px",
//                     }}>
//                     {/* Menu icon for small and extra-small screens */}
//                     <IconButton
//                         sx={{ display: { xs: "flex", sm: "flex", md: "none" }, color: "white", height: "40px", width: "40px",ml:"-10px" }}
//                         onClick={handleMenuClick}
//                     >
//                         <IoMdMenu />
//                     </IconButton>
//                     <div style={{ width: "100%", padding: "0.5% 0.1% 0.5% 0.7%", borderRadius: 8, backgroundColor: "rgb(17,27,39)", display: "flex", flex: 1 }}>
//                         <textarea
//                             placeholder="Send Message..."
//                             ref={inputRef}
//                             style={{
//                                 width: "100%",
//                                 backgroundColor: "transparent",
//                                 padding: '10px',
//                                 border: "none",
//                                 outline: "none",
//                                 color: "white",
//                                 fontSize: "15px",
//                                 resize: "none",
//                                 overflow: "hidden",
//                                 maxHeight: "150px",
//                                 overflowY: "auto"
//                             }}
//                             rows={1} // Minimum number of rows
//                             onKeyDown={handleKeyPress}
//                             onInput={handleInput}
//                         />
//                         <IconButton onClick={handleSubmit} sx={{ marginLeft: "auto", color: "white", height: "35px", width: "35px" }}>
//                             <IoMdSend />
//                         </IconButton>
//                     </div>
//                 </div>
//             </Box>

//             {/* Overlay Window */}
//             <Dialog
//                 open={openOverlay}
//                 onClose={handleCloseOverlay}
//                 sx={{
//                     "& .MuiDialog-paper": {
//                         width: "90%",
//                         maxWidth: "600px",
//                         height: "77%",
//                         bgcolor: "#05101c",
//                         color: "white",
//                         borderRadius:5
//                     },
//                 }}
//             >
//                 <DialogContent dividers>
//                     <Box sx={{
//                         display: "flex",
//                         flexDirection: "column",
//                         height: "100%",
//                         width:"100%",
//                         justifyContent: "center",
//                         alignItems: "center",
//                         overflow: "auto",
//                     }}>
//                         <Box sx={{
//                             display: "flex",
//                             flexDirection: "column",
//                             bgcolor: "rgb(17,29,39)",
//                             borderRadius: 5,
//                             width: "84%",
//                             height: "100%",
//                             p: 3,
//                             gap: 3,
//                             alignItems: "center",
//                             overflow:"hidden",
//                             overflowY:"auto",
//                         }}>
//                             <TypeAnimation
//                                 sequence={[
//                                     `Hello ${auth?.user?.name}...`,
//                                     1000,
//                                     `Hello ${auth?.user?.name}`,
//                                     1500
//                                 ]}
//                                 speed={10}
//                                 style={{
//                                     fontSize: '18px',
//                                     color: "white",
//                                     textShadow: "1px 1px 20px #000",
//                                     fontWeight: 600,
//                                     textAlign: "center",
//                                 }}
//                                 repeat={Infinity}
//                             />
//                             <img src="chat-bot.gif" alt="Bot" width="80%" style={{ borderRadius: "10px" }} />
//                             <Box sx={{
//                                 display: "flex",
//                                 flexDirection: "column",
//                                 alignItems: "center",
//                                 textAlign: "center",
//                                 gap: 2,
//                                 width:"90%"
//                             }}>
//                                 <Typography variant="h6" sx={{
//                                     color: "white",
//                                     textShadow: "1px 1px 20px #000",
//                                     fontWeight: 600,
//                                     width:"100%",
//                                     fontSize:"110%"
//                                 }}>
//                                     Welcome to <span style={{ color: "yellow" }}>Rusty</span>BOT
//                                 </Typography>
//                                 <Typography sx={{
//                                     fontSize: '80%',
//                                     color: "white",
//                                     textShadow: "1px 1px 20px #000",
//                                     width: "100%",
//                                     textAlign:"left",

//                                 }}>
//                                     I'm here to help with any questions or tasks. Whether you need information or just a quick chat, feel free to ask—I'm ready to assist!
//                                 </Typography>
//                             </Box>
//                             <Button
//                                 onClick={handleDeleteChats}
//                                 sx={{
//                                     width: '100%',
//                                     color: 'white',
//                                     fontWeight: 600,
//                                     borderRadius: 1,
//                                     outline: '2px solid red',
//                                     outlineColor: red[400],
//                                     ":hover": { bgcolor: red.A400 },
//                                     my: 2,
//                                     fontSize: "80%",
//                                 }}
//                             >
//                                 Clear Chat
//                             </Button>
//                         </Box>
//                     </Box>
//                 </DialogContent>
//                 <DialogActions>
//                     <Button onClick={handleCloseOverlay} sx={{color:"white",outline:"1px solid",padding:"2px",my:1,mr:2.5,fontSize:"70%"}}>
//                         Close
//                     </Button>
//                 </DialogActions>
//             </Dialog>
//         </Box>
//     );
// };

// export default Chat;
