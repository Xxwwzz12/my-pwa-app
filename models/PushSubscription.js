import mongoose from 'mongoose';

const pushSubscriptionSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  endpoint: { 
    type: String, 
    required: true,
    unique: true
  },
  keys: {
    p256dh: { 
      type: String, 
      required: true 
    },
    auth: { 
      type: String, 
      required: true 
    }
  },
  expirationTime: { 
    type: Number, 
    default: null 
  },
  userAgent: {
    type: String,
    default: ''
  },
  device: {
    type: String,
    enum: ['desktop', 'mobile', 'tablet', 'other'],
    default: 'other'
  }
}, { 
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform: function(doc, ret) {
      delete ret._id;
      delete ret.__v;
      delete ret.keys;
      return ret;
    }
  }
});

// Индекс для быстрого поиска по пользователю и endpoint
pushSubscriptionSchema.index({ userId: 1, endpoint: 1 }, { unique: true });

// Виртуальное поле для возраста подписки
pushSubscriptionSchema.virtual('age').get(function() {
  if (!this.createdAt) return 0;
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Статистика по устройствам пользователя
pushSubscriptionSchema.statics.getDeviceStats = async function(userId) {
  const stats = await this.aggregate([
    { $match: { userId: mongoose.Types.ObjectId(userId) } },
    { $group: { 
        _id: '$device', 
        count: { $sum: 1 },
        lastUsed: { $max: '$updatedAt' }
    } }
  ]);
  
  return stats.reduce((acc, item) => {
    acc[item._id] = {
      count: item.count,
      lastUsed: item.lastUsed
    };
    return acc;
  }, {});
};

const PushSubscription = mongoose.model('PushSubscription', pushSubscriptionSchema);

export default PushSubscription;
