// test-push-subscription.js
import mongoose from 'mongoose';
import PushSubscription from './models/PushSubscription.js';
import dotenv from 'dotenv';

dotenv.config();

async function test() {
  await mongoose.connect(process.env.MONGO_URI);
  
  const sub = new PushSubscription({
    endpoint: "https://fcm.googleapis.com/fcm/send/test",
    keys: {
      auth: "test_auth_key",
      p256dh: "test_p256dh_key"
    }
  });
  
  await sub.save();
  console.log("✅ Подписка сохранена!");
  process.exit();
}

test().catch(err => {
  console.error("❌ Ошибка:", err);
  process.exit(1);
});