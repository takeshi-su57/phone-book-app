import * as bcrypt from 'bcrypt';
import { OAuth2Client } from "google-auth-library";
import * as ethUtil from "ethereumjs-util";
import * as cryptoRandomString from 'crypto-random-string';
import { omit } from "lodash";
import UserWithThatEmailAlreadyExistsException from '../exceptions/UserWithThatEmailAlreadyExistsException';
import WrongSignatureException from '../exceptions/WrongSignatureException';
import UserWalletNotExistsException from "../exceptions/UserWalletNotExist"
import UserEmailNotExistsException from "../exceptions/UserEmailNotExist";
import VerifyCodeInvalidException from "../exceptions/VerifyCodeInvalid";
import TokenDataWithUser from '../interfaces/tokenDataWithUser.interface';
import { CreateUserInput } from '../schemas/user.schema';
import userModel, { IUserResponse } from "../models/user.model";
import verifyModel from "../models/verify.model";
import { createToken } from "../utils/jwt";
import settings from '../config/settings';
import { sendResetPasswordEmail, sendVerifyEmail } from "../utils/mail";
import TokenExpiredException from '../exceptions/TokenExpired';
import TokenNotExistException from '../exceptions/TokenNotExistException';
import WrongCredentialsException from '../exceptions/WrongCredentialsException';

const client = new OAuth2Client(settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET);

class AuthenticationService {
  public user = userModel;

  public async register(userData: CreateUserInput["body"], host: string): Promise<TokenDataWithUser> {
    let user = await this.user.findOne({ email: userData.email, })
    if (user) {
      throw new UserWithThatEmailAlreadyExistsException(userData.email);
    }

    const code = cryptoRandomString({ length: 4, type: 'numeric' });
    const token = cryptoRandomString({ length: 16, type: 'url-safe' });

    const hashedPassword = await bcrypt.hash(userData.password, 10);
    user = await this.user.create({
      code,
      ...userData,
      email_verified: false,
      password: hashedPassword,
    });
    sendVerifyEmail(userData.email, code, token, host);
    const userObj = omit(user.toJSON(), ["password", "code"]);

    return {
      ...createToken(user),
      user: userObj as IUserResponse,
    }
  }

  public async login(email: string, password: string): Promise<TokenDataWithUser> {
    const user = await userModel.findOne({ email, });
    if (user) {

      const isPasswordMatching = await bcrypt.compare(
        password,
        user.get('password', null, { getters: false }),
      );
      if (isPasswordMatching) {
        
        return {
          ...createToken(user),
          user: omit(user.toJSON(), 'password') as IUserResponse
        }
      } else {
        throw new WrongCredentialsException();
      }
    } else {
      throw new WrongCredentialsException();
    }
  }

  public async googleLogin(token: string): Promise<TokenDataWithUser> {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: settings.GOOGLE_CLIENT_ID
    });
    const google_id = ticket.getUserId();
    let user = await this.user.findOne({ google_id, });
    if (!user) {
      user = await this.user.create({
        google_id,
      });
    }
    return {
      ...createToken(user),
      user: omit(user.toJSON(), ["password"]) as IUserResponse
    }
  }

  public async getNonce(wallet_address: string): Promise<number> {
    let user = await this.user.findOne({ wallet_address, });
    if (!user) {
      user = await this.user.create({
        wallet_address,
        nonce: Math.floor(Math.random() * 1000000),
      });
    }
    return user.nonce;
  }

  public async web3Login(wallet_address: string, signature: string): Promise<TokenDataWithUser> {
    try {
      let user = await this.user.findOne({ wallet_address, });
      if (user) {
        const msg = `Nonce: ${user.nonce}`;
        // Convert msg to hex string
        const msgHex = ethUtil.bufferToHex(Buffer.from(msg));

        // Check if signature is valid
        const msgBuffer = ethUtil.toBuffer(msgHex);
        const msgHash = ethUtil.hashPersonalMessage(msgBuffer);
        const signatureParams = ethUtil.fromRpcSig(signature);
        const publicKey = ethUtil.ecrecover(
          msgHash,
          signatureParams.v,
          signatureParams.r,
          signatureParams.s
        );
        const addresBuffer = ethUtil.publicToAddress(publicKey);
        const address = ethUtil.bufferToHex(addresBuffer);

        // Check if address matches
        if (address.toLowerCase() === wallet_address.toLowerCase()) {
          // Change user nonce
          const nonce = Math.floor(Math.random() * 1000000);
          user = await this.user.findOneAndUpdate({ wallet_address, }, { nonce, });
          // Set jwt token
          return {
            ...createToken(user),
            user: omit(user.toJSON(), "password") as IUserResponse
          }
        } else {
          // User is not authenticated
          throw new WrongSignatureException();
        }
      } else {
        throw new UserWalletNotExistsException(wallet_address);
      }
    } catch (err) {
      throw err;
    }
  }

  public async verifyCode(email: string, code: string) {
    let user = await this.user.findOne({ email, })
    if (!user) {
      throw new UserEmailNotExistsException(email);
    }
    if (user.code !== code) {
      throw new VerifyCodeInvalidException(email, code);
    }
    await this.user.findOneAndUpdate({ email, }, { email_verified: true });
  }

  public async forgotPassword(email: string, host: string) {
    let user = await this.user.findOne({ email, })
    if (!user) {
      throw new UserEmailNotExistsException(email);
    }
    const token = cryptoRandomString({ length: 16, type: 'url-safe' });

    await verifyModel.create({
      email,
      token,
    });

    sendResetPasswordEmail(email, token, host);
  }

  public async verifyToken(token: string) {
    const verify = await verifyModel.findOne({ token, });

    if (!verify) throw new TokenNotExistException(token);
    const diff = (new Date(verify.createdAt).getTime() - new Date().getTime()) / 1000;

    if (diff > Number(settings.EXPIRES)) {
      throw new TokenExpiredException(verify.email, verify.token);
    }
    await this.user.findOneAndUpdate({ email: verify.email }, { email_verified: true });
    await verify.delete();
  }

  public async resetPassword(token: string, password: string) {
    const verify = await verifyModel.findOne({ token, });

    if (!verify) throw new TokenNotExistException(token);
    const diff = (new Date(verify.createdAt).getTime() - new Date().getTime()) / 1000;

    if (diff > Number(settings.EXPIRES)) {
      throw new TokenExpiredException(verify.email, verify.token);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await this.user.findOneAndUpdate({ email: verify.email }, { password: hashedPassword });
    await verify.delete();
  }
}

export default AuthenticationService;
