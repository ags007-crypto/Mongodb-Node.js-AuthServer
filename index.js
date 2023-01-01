const express = require('express')
const bodyParser=require('body-parser')
const mongoose=require('mongoose')

const app =express()
const PORT=3000

const {mogoUrl}=require('./keys')

require('./models/User');

const requireToken=require('./middleware/requireToken')
const authRoutes = require('./routes/authRoutes')

app.use(bodyParser.json())
app.use(authRoutes)

mongoose.set('strictQuery',true);
mongoose.connect(mogoUrl)

mongoose.connection.on('connected',()=>{
    console.log("connected to mongo")
})

mongoose.connection.on('error',(err)=>{
    console.log("There is an error")
})


app.get('/',requireToken,(req,res)=>{
    res.send({email:req.user.email})
})


app.listen(PORT,()=>{
    console.log("server running now at "+ PORT)
})