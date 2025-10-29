import { model, Schema } from 'mongoose';

const userSchema = new Schema(
  {
    username: { type: String, required: false, trim: true },
    email: { type: String, unique: true, required: true, trim: true },
    password: { type: String, required: true },
    avatar: { 
      type: String, 
      required: false, 
      default: 'https://res.cloudinary.com/demo/image/upload/v1312461204/sample.jpg' 
    },
  },
  { timestamps: true, versionKey: false },
);

userSchema.pre('save', function (next) {
  if (!this.username) {
    this.username = this.email;
  }
  next();
});

userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  return obj;
};

export const User = model('User', userSchema);