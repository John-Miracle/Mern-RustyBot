import { TypeAnimation } from "react-type-animation";

const TypingAnim = () =>{
    return (
            <TypeAnimation
            sequence={[
                // Same substring at the start will only be typed once, initially
                'WELCOME TO RUSTYBOT',
                1000,
                'BUILT WITH OPENAI 🤖',
                1000,
                'POWERED BY GPT 3.5 TURBO',
                1500,
            ]}
            speed={15}
            style={{fontWeight:600, fontStyle:"uppercase", fontSize: '20px',color: "white",display:"inline-block",textShadow:"1px 1px 20px #000"}}
            repeat={Infinity}
            />
    );
};

export default TypingAnim;