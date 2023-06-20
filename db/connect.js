import mongoose from "mongoose";

const database = async () => {

    try{
        await mongoose.connect(`${process.env.MONGO_URL}`,{
            useNewUrlParser : true,
            useUnifiedTopology : true
        });
        console.log('DB Connection Established...');
    }catch(error){
        console.log('Connection Error: ', error);
    }
}

export default database;