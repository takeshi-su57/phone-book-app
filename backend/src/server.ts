import 'dotenv/config';
import 'module-alias/register';
import App from './app';
import validateEnv from './utils/validateEnv';
import AuthController from "./controllers/auth.controller";

validateEnv();

const app = new App(
  [
    new AuthController(),
  ],
);

app.listen();