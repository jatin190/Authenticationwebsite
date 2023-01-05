import jwt from 'jsonwebtoken';
import UserModel from '../models/User.js'

var checkUserAuth = async (req,res,next) => {
    let token 
    const {authorization } = req.headers;
    if(authorization && authorization.startsWith('Bearer')){
        try{
            //get token from header
            token = authorization.split(' ')[1]
            //console.log(token);
            //console.log(authorization);
            
            // verify token 
            const {userId} = jwt.verify(token,process.env.JWT_SECRET_KEY)
            //console.log(userId);
            //console.log(req.user._id);
            // get user from token  
            req.user = await UserModel.findById(userId).select(`-password`)
            //console.log(req.user);
            next()
        }catch(error){
            console.log(error)
            res.status(401).send({"status": "failed", "message":"Unarthorized User"})
        }
    }
    if(!token){
        res.status(401).send({"status": "failed", "message":"Unauthorized User, NO Token"})
    }
}

export default checkUserAuth;