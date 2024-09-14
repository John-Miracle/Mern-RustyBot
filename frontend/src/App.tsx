import Header from "./componenets/Header"
import {Routes,Route} from "react-router-dom";
import Home from "./pages/Home";
import Chat from "./pages/Chat";
import Signup from "./pages/Signup";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";
import { useAuth } from "./context/Auth-Context";
//Routes: Container of all Routes 
//Route: To enter and register each route

function App() {
  const auth = useAuth();
  console.log(useAuth()?.isLoggedIn);
  console.log(useAuth()?.user);
  return (
    <main>
      <Header />
      <Routes>
        <Route path="/" element={<Home />}/>
        <Route path="/login" element={<Login />}/>
        <Route path="/signup" element={<Signup />}/>
        {auth?.isLoggedIn && auth.user && <Route path="/chat" element={<Chat />}/>}
        <Route path="*" element={<NotFound />}/>
      </Routes>
    </main>
  )
}

export default App
