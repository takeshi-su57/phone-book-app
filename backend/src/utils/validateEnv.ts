import {
  cleanEnv, num, port, str,
} from 'envalid';

function validateEnv() {
  cleanEnv(process.env, {
    DB_URI: str(),
    PORT: port(),
  });
}

export default validateEnv;