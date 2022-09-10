import mongoose from "mongoose";

export interface IVerify {
  email: string;
  token: string;
  createdAt: Date;
}

export interface VerifyDocument extends IVerify, mongoose.Document {
}

const verifySchema = new mongoose.Schema(
  {
    email: { type: String },
    code: { type: String }
  },
  {
    timestamps: true,
  }
);

const verifyModel = mongoose.model<VerifyDocument>("Verify", verifySchema);

export default verifyModel;