import mongoose from "mongoose";
export interface IUser {
  google_id: string;
  wallet_address: string;
  email: string;
  name: string;
  password: string;
  nonce: number;
  email_verified: boolean;
  code: string;
  createAt: Date,
  updatedAt: Date,
}

export interface IUserResponse extends Omit<IUser, 'password' | 'code'> { }

export interface UserDocument extends IUser, mongoose.Document {}

const userSchema = new mongoose.Schema(
  {
    google_id: { type: String, },
    wallet_address: { type: String, },  
    email: { type: String, },
    name: { type: String },
    password: { type: String },
    nonce: { type: Number },
    email_verified: { type: Boolean, default: false },
    code: { type: String }
  },
  {
    timestamps: true,
  }
);

const userModel = mongoose.model<UserDocument>("User", userSchema);

export default userModel;