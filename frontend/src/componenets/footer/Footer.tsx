import { Link } from "react-router-dom"

export const Footer = () =>{
    return (
        <footer>
            <div 
            style={{
                width:"100%",
                padding:20,
                minHeight: "20vh",
                maxHeight: "30vh",
                marginTop:50
            }}>
                <p style={{ fontSize: "30px", textAlign:"center" }}>
                    Built by<span><Link style={{color:"white"}}className="nav-link" to={'https://github.com/John-Miracle'}>John Miracle</Link></span>
                </p>
            </div>
        </footer>
    )
}