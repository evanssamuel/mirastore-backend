process.on('unhandledRejection', (err) => console.error('ERROR:', err));
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const MONGO_URI = 'mongodb+srv://samuelevans569_db_user:9YxvCFZKu4N9V6z9@mirastore.lxljk0v.mongodb.net/?appName=mirastore';

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: String,
  mustChangePassword: Boolean,
  joinedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

async function seed() {
  await mongoose.connect(MONGO_URI);
  console.log('Connected to MongoDB...');

  // Delete existing admin if any
  await User.deleteOne({ email: 'admin@mirastore.ng' });

  const hashed = await bcrypt.hash('MiraAdmin@2025!', 12);
  
  await User.create({
    name: 'Admin',
    email: 'admin@mirastore.ng',
    password: hashed,
    role: 'admin',
    mustChangePassword: false
  });

  console.log('✅ Admin account created!');
  console.log('Email: admin@mirastore.ng');
  console.log('Password: MiraAdmin@2025!');
  console.log('CHANGE THIS PASSWORD after first login!');
  
  await mongoose.disconnect();
  process.exit(0);
}

seed().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});