import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import './index.css'
import { createTheme,ThemeProvider } from '@mui/material'
import { BrowserRouter } from "react-router-dom";
import { AuthProvider } from './context/Auth-Context.tsx'
import axios from "axios";
import { Toaster } from "react-hot-toast";

axios.defaults.baseURL = "https://mern-rusty-bot.vercel.app";
axios.defaults.withCredentials = true; //It will allow setting and exchanging cookies with backend

//Creating a customized theme
const theme = createTheme({typography:{
  fontFamily:"Roboto Slab,serif",
  allVariants: {color: 'white'}}
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <BrowserRouter>
        <Toaster position="top-center"/>
        <ThemeProvider theme={theme}>
          <App />
        </ThemeProvider>
      </BrowserRouter>
    </AuthProvider>
    
    
    
  </StrictMode>,
)
