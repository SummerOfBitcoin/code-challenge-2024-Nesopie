import * as crypto from "crypto";
import { OP_CODES } from "./features/script/op_codes";

export const hash256 = (str: string) => {
  return crypto
    .createHash("ripemd160")
    .update(Buffer.from(sha256(str), "hex"))
    .digest("hex");
};

export const sha256 = (str: string) => {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(str, "hex"))
    .digest("hex");
};

export const asmToHex = (asm: string) => {
  const tokens = asm.split(" ") as OP_CODES[];
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

// const asm = "OP_0 OP_PUSHBYTES_20 15ff0337937ecadd10ce56ffdfd4674817613223";
// const hex = asmToHex(asm);
// console.log(hex);
// console.log(
//   sha256(
//     "201dda24da0b91e0eed9770878c504aeb07628ca4ccae9a7bd5347b96ee85dac52ac0063036f726401010a746578742f706c61696e00357b2270223a226272632d3230222c226f70223a226d696e74222c227469636b223a22646f6765222c22616d74223a2234323030227d68"
//   )
// );
