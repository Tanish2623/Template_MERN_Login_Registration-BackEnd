const router = require('express').Router();
const User = require("../models/userModel");
const bcrypt = require('bcryptjs')
const jwt = require("jsonwebtoken");
const { countDocuments } = require('../models/userModel');
const auth = require('../middleware/auth')
router.post("/register", async (req,res) => {
    try{
         const { email , password, passwordCheck, displayName}  = req.body;
        // validate
        if(!email || !password || !passwordCheck){
            return res.status(400).json({msg : "Not all the field are there"});
        }
        if(password.length < 5){
            return res.status(400).json({msg : "password needs to be 5 character long"});
        }
        if(password!==passwordCheck){
            return res.status(400).json({msg : "Enter same password"});
        }
        const existingUser = await User.findOne({email : email});
        if(existingUser){
            return res.status(400).json({msg : "Account already exists"});
        }
        if(!displayName)
            displayName=email;

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password,salt);

        const newUser = new User({
            email,
            password : passwordHash,
            displayName
        })
        const savedUser = await newUser.save();
        res.json(savedUser);
    
        console.log(passwordHash)

    } catch(err){
        res.status(500).json({error : err.message})
    }

});

router.post("/login", async (req,res) => {
    try{
        const { email, password} =req.body;
        if(!email|| !password){
            return res.status(400).json({msg : "Not all the field are there"});
        }
        const user = await User.findOne({email : email});
        if(!user){
            return res.status(400).json({msg : "No account with this email"});
        }
        const isMatch = await bcrypt.compare(password,user.password);
        if(!isMatch){
            return res.status(400).json({msg : "Invalid credentials"});
        }
        const token = jwt.sign({id : user._id},process.env.JWT_SECRET);
        res.json({
            token,
            user : {
              id : user._id,
              displayName : user.displayName
            }
        })
    }catch (err){
        res.status(500).json({error : err.message})
    }
})

router.delete("/delete", auth,async (req,res) => {
   try{
        const deleteUser = await User.findByIdAndDelete(req.user);
        res.json(deleteUser)
   }catch(err){
    res.status(500).json({error : err.message})
   }
})

router.post('/tokenIsValid',async (req,res) => {
    try{
        const token = req.header('x-auth-token');
        if(!token)
            return res.json(false);
        const verified = jwt(token,process.env.JWT_SECRET)
        if(!verified)
            return res.json(false);

        const user = await User.findById(verified.id);
        if(!user)
            return res.json(false);

        return res.json(true)
    }catch(err){
        res.status(500).json({error : err.message})
    }
})

router.get("/",auth,async(req,res) => {
    const user= await User.findById(req.user);
    res.json({
        displayName : user.displayName,
        id : user._id
    });
})
module.exports = router;