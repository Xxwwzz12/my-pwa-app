const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  googleId: { 
    type: String, 
    unique: true,
    sparse: true,
    index: true
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Некорректный email']
  },
  firstName: { 
    type: String, 
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 30
  },
  lastName: { 
    type: String, 
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 30
  },
  gender: { 
    type: String, 
    enum: ['male', 'female', 'other'], 
    default: 'other'
  },
  age: { 
    type: Number, 
    min: 1, 
    max: 120,
    default: 25
  },
  role: { 
    type: String, 
    enum: ['senior_parent', 'parent', 'child', 'relative', 'grandparent'], 
    default: 'parent'
  },
  avatar: { 
    type: String,
    default: null
  },
  familyId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Family',
    default: null
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    immutable: true
  },
  lastActive: {
    type: Date,
    default: Date.now
  },
  notificationSettings: {
    messages: { type: Boolean, default: true },
    events: { type: Boolean, default: true },
    tasks: { type: Boolean, default: true },
    wishlist: { type: Boolean, default: true }
  }
});

// Автоматическое обновление lastActive при сохранении
userSchema.pre('save', function(next) {
  if (this.isModified()) {
    this.lastActive = new Date();
  }
  next();
});

// Виртуальное поле для полного имени
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Преобразование в JSON
userSchema.set('toJSON', {
  virtuals: true,
  transform: (doc, ret) => {
    delete ret.__v;
    delete ret.googleId;
    ret.id = ret._id;
    delete ret._id;
    return ret;
  }
});

module.exports = mongoose.model('User', userSchema);