import * as crypto from "crypto";
import { OP_CODES } from "./features/script/op_codes";

export const taprootHash = (str: string, byteArray: string) => {
  const tag = crypto.createHash("sha256").update(str).digest("hex");
  return sha256(tag + tag + byteArray);
};

export const hash160 = (str: string) => {
  return crypto
    .createHash("ripemd160")
    .update(Buffer.from(sha256(str), "hex"))
    .digest("hex");
};

export const hash256 = (str: string) => {
  return sha256(sha256(str));
};

export const sha256 = (str: string) => {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(str, "hex"))
    .digest("hex");
};

export const asmToHex = (asm: string) => {
  const tokens = asm.split(" ") as (keyof typeof OP_CODES)[];
  return [...new Array(tokens.length)]
    .map((_, index) => OP_CODES[tokens[index]])
    .map((token, index) => (!token ? tokens[index] : token))
    .join("");
};

//reverses every byte of the string - every 2 hex chars
export const reversify = (str: string) => {
  return str
    .match(/.{1,2}/g)!
    .reverse()
    .join("");
};

// console.log(
//   hash160(
//     "00202791caef68f38a0fa3f14d5f4169894ebc318355d2c33bfc1a9d606403b1dbea"
//   )
// );
