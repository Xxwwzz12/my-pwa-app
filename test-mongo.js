import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();

async function testMongo() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");
    
    const result = await mongoose.connection.db.collection('pushsubscriptions').insertOne({
      endpoint: "direct_test",
      keys: { auth: "test", p256dh: "test" },
      createdAt: new Date()
    });
    
    console.log("Insert result:", result);
    process.exit(0);
  } catch (error) {
    console.error("MongoDB error:", error);
    process.exit(1);
  }
}

testMongo();