const mongoose= require("mongoose")


const tokenSchema= mongoose.Schema({
    userId:{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "User"
    }, 
    loginToken:{
        type: String,
        default: ""
    },
    verifyToken:{
        type: String,
        default: ""
    },
    resetToken:{
        type: String,
        default:""
    },
    expiresAt:{
        type: Date,
        required: true
    }
},{
    timestamps: true
})

const Token= mongoose.model("Token", tokenSchema)
module.exports= Token