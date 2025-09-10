import express, { request } from 'express';
import mysql from 'mysql2';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"Sagar@123",
    database:"foodDelivery"
})

const initializeDBAndServer = () =>{
    db.connect((error)=>{
        if(error){
            console.log(error);
            process.exit(1);
        }else{
            app.listen(5051,()=>{
                console.log("Server is running on port 5051");
            })
        }
    })
}
initializeDBAndServer();

const authToken = (request, response, next) => {
    const authHeader = request.headers["authorization"]; 
    if (!authHeader) {
        return response.status(401).send("Unauthorized: No Token Provided");
    }
    const token = authHeader.split(" ")[1]; 
    if (!token) {
        return response.status(401).send("Unauthorized: Invalid Token");
    }
    jwt.verify(token, "token", (error, payload) => {
        if (error) {
            return response.status(401).send("Unauthorized: Invalid Token");
        }
        request.email = payload.email; 
        next();
    });
};


app.post("/signup",async(request,response)=>{
    const {username,name,email,password} = request.body
    console.log(username,name,email,password);
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password,saltRounds);
    const insertUserQuery = `INSERT INTO signup (username,name,email,password) VALUES (?,?,?,?)`;
    db.query(insertUserQuery,[username,name,email,hashedPassword],(error,results)=>{
        if(error){
            response.status(400)
            .send("User Registration Failed");
        }else{
            response.status(200)
            .send("User Registered Successfully");
        }
    })
});


app.post("/login", (request, response) => {
    const { email, password } = request.body;
    console.log(email, password);
    const selectUserQuery = `SELECT * FROM signup WHERE email = ?`;
    db.query(selectUserQuery, [email], async (error, results) => {
        if (error) {
            console.error("DB Error:", error);
            return response.status(500).send("Login Failed");
        }
        if (results.length === 0) {
            return response.status(404).send("User Not Found");
        }
        try {
            const user = results[0];
            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (isPasswordValid) {
                const payload = { email: user.email };
                const token = jwt.sign(payload, "token", { expiresIn: "5h" });
                return response.status(200).json({ message: "Login Successful", token });
            } else {
                return response.status(401).json({ message: "Invalid Password" });
            }
        } catch (err) {
            console.error("Error comparing passwords:", err);
            response.status(500).send("Internal Server Error");
        }
    });
});

app.get("/account",authToken,(request,response)=>{
    const accountQuery = `SELECT * FROM signup WHERE email=?`;
    db.query(accountQuery,[request.email],(error,results)=>{
        if (error){
            response.status(500).send("Internal Server Error");
        }else{
            response.status(200).json(results);
        }
    });
})

app.post("/address",authToken,(request,response)=>{
    const {fullname,phonenumber,email,flat,area,landmark,pincode,city,address} = request.body
    console.log(fullname,phonenumber,email,flat,area,landmark,pincode,city,address);
    const insertAddressQuery = `INSERT INTO address 
              (fullname,phonenumber,email,flat,area,landmark,pincode,city,address) 
                VALUES (?,?,?,?,?,?,?,?,?)`;
    db.query(insertAddressQuery,[fullname,phonenumber,email,flat,area,landmark,pincode,city,address],(error,results)=>{
            if (error) {
                console.error("SQL Error:", error);  // Add this
                response.status(400).send("Address Registration Failed");
        } 
        else{
            response.status(200)
            .send("Address Registered Successfully");
        } 
    })
});

app.get("/address", authToken, (request, response) => {
  const Query = `SELECT * FROM address WHERE email=?`;
  db.query(Query, [request.email], (error, results) => {
    if (error) {
      response.status(500).send("Internal Server Error");
    } else {
      response.status(200).json(results);
    }
  });
});
