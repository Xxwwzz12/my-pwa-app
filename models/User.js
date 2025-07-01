const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  googleId: { type: String, unique: true },
  email: { type: String, required: true, unique: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  gender: { 
    type: String, 
    enum: ['male', 'female', 'other'], 
    required: true 
  },
  age: { 
    type: Number, 
    min: 1, 
    max: 120, 
    required: true 
  },
  role: { 
    type: String, 
    enum: ['senior_parent', 'parent', 'child', 'relative', 'grandparent'], 
    required: true 
  },
  avatar: { type: String },
  familyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Family' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
