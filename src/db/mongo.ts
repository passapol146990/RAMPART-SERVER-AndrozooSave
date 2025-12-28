import * as mongoose from 'mongoose';

const MONGODB_USERNAME = process.env.MONGO_USERNAME;
const MONGODB_PASSWORD = process.env.MONGO_PASSWORD;
const MONGODB_HOST = process.env.MONGO_HOST;
const MONGODB_PORT = process.env.MONGO_PORT;
const URI = `mongodb://${MONGODB_USERNAME}:${MONGODB_PASSWORD}@${MONGODB_HOST}:${MONGODB_PORT}/androzoo?authSource=admin`;

const conn = mongoose.createConnection(URI);

conn.on('connected', () => {
  console.log("✅ Connected db successfuly.");
});
conn.on('error', err => {
  console.error("❌ MongoDB connection error:", err);
});

conn.on('disconnected', () => {
  console.warn("⚠️ MongoDB disconnected. Retrying...");
});

export default conn;