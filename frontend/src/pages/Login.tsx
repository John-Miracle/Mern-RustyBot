// import React, { useEffect } from "react";
// import { Box, Button, Typography } from "@mui/material";
// import CustomizedInput from "../componenets/shared/CustomizedInput";
// import { IoIosLogIn } from "react-icons/io";
// import { useAuth } from "../context/Auth-Context";
// import toast from "react-hot-toast";
// import { useNavigate } from "react-router-dom";


// const Login = () =>{
//     const auth = useAuth();
//     const navigate = useNavigate();
//     const handleSubmit = async (e:React.FormEvent<HTMLFormElement>) => {
//         e.preventDefault();
//         const formData = new FormData(e.currentTarget);
//         const email = formData.get("email") as string;
//         const password = formData.get("password") as string;
//         try{
//             toast.loading("Signing In",{id:"login"})
//             await auth?.login(email,password);
//             toast.success("Signing In Successfully",{id:"login"});
//         }catch(error){
//             console.log(error);
//             toast.error("Sign In Failed",{id:"login"});

//         }
//         console.log(email,password);
//     }

//     //Runs everytime the Auth changes 
//     useEffect(()=>{
//         if(auth?.user){
//             return navigate("/chat")
//         }
//     });

//     return <Box width={"100%"} height={"100%"} display={"flex"}>
//         <Box padding={8} mt={8} display={{md:"flex",sm:"none",xs:"none"}}>
//             <img src="AIBot.gif" alt="Robot" style={{width:"400px"}}/>
//         </Box>
//         <Box display={"flex"} 
//              flex={{xs:1,md:0.5}} 
//              justifyContent={'center'} 
//              alignItems={'center'} 
//              padding={2} 
//              ml={"auto"} 
//              mt={16}>

//                 <form  onSubmit={handleSubmit} style={{margin: 'auto', padding: '30px', boxShadow: '10px 10px 20px #000', borderRadius: '10px'}}>
//                     <Box sx={{display:'flex',flexDirection:"column",justifyContent: "center"}}>
//                         <Typography variant="h4" textAlign="center" padding={2} fontWeight={600}>
//                             Login
//                         </Typography>
//                         <CustomizedInput type="email" name="email" label="Email"/>
//                         <CustomizedInput type="password" name="password" label="Password"/>
//                         <Button type="submit" 
//                             sx={{
//                                 px:2, py:1, mt:2, width: "400px",
//                                 borderRadius:2,
//                                 bgcolor:"#00fffc", 
//                                 ":hover":{
//                                     bgcolor: "white",
//                                     color: "black",
//                                 }
//                             }}
//                             endIcon={<IoIosLogIn />}>
//                         Login</Button>
//                     </Box>
//                 </form>
//         </Box>
//     </Box>
// };

// export default Login;


import React, { useEffect } from "react";
import { Box, Button, Typography } from "@mui/material";
import CustomizedInput from "../componenets/shared/CustomizedInput";
import { IoIosLogIn } from "react-icons/io";
import { useAuth } from "../context/Auth-Context";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";

const Login = () => {
  const auth = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    const email = formData.get("email") as string;
    const password = formData.get("password") as string;

    try {
      toast.loading("Signing In", { id: "login" });
      await auth?.login(email, password);
      toast.success("Signing In Successfully", { id: "login" });
    } catch (error) {
      console.log(error);
      toast.error("Sign In Failed", { id: "login" });
    }
  };

  // Runs everytime the Auth changes
  useEffect(() => {
    if (auth?.user) {
      return navigate("/chat");
    }
  }, [auth?.user, navigate]);

  return (
    <Box width="100%" height="90vh" display="flex" flexDirection="row" gap='0'>
      <Box
        display={{ md: "flex", sm: "none", xs: "none" }}
        flex = {0.5}
        justifyContent={'center'}
        alignItems={'center'}
      >
        <img src="Robo.gif" alt="Robot" style={{ height:"400px",width:"400px",borderRadius:10,outline:"10px solid yellow"}} />
      </Box>
      <Box
        display="flex"
        flex={{ xs: 1, md: 0.5}}
        justifyContent="center"
        alignContent="center"
        ml="auto"
        p={1}
      >
        <form
          onSubmit={handleSubmit}
          style={{
            margin:"auto",
            padding: "30px 30px 15px 30px",
            boxShadow: "10px 10px 10px #000",
            borderRadius: "10px",
            height:"80%",
            width:"80%",
            maxWidth: "420px",
            maxHeight: "300px",
            backgroundColor:"rgb(17,29,39)",
            alignItems:"center"
            }}
            >
          <Box
            sx={{
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
            }}
          >
            <Typography
              variant="h4"
              textAlign="center"
              paddingBottom={2}
              fontSize={"23px"}
              fontWeight={600}
              letterSpacing={2}
            >
              LOGIN
            </Typography>
            <CustomizedInput type="email" name="email" label="Email" />
            <CustomizedInput type="password" name="password" label="Password" />
            <Button
              type="submit"
              sx={{
                px: 2,
                py: 1,
                mt: 2,
                width: "100%",
                color:'black',
                fontWeight:600,
                letterSpacing:1, // Make the button 100% width for better responsiveness
                borderRadius: 2,
                bgcolor: "#00fffc",
                ":hover": {
                  bgcolor: "white",
                  color: "black",
                },
              }}
              endIcon={<IoIosLogIn />}
            >
              Login
            </Button>
          </Box>
        </form>
      </Box>
    </Box>
  );
};

export default Login;