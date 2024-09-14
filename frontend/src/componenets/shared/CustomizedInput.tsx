import { TextField } from "@mui/material";
type Props ={
    name: string;
    type: string;
    label: string;
}

const CustomizedInput = (props: Props) => {
    return <TextField 
        margin="normal"
        InputLabelProps={{style:{color:'white'}}} 
        InputProps={{style:{width: "100%", borderRadius: 10, color: 'white',padding: 4 }}}
        name={props.name} label={props.label} type={props.type}/>
}



export default CustomizedInput;