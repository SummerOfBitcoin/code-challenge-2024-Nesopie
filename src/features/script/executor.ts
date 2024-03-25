import { OP_CODES } from "./op_codes";
import { ERRORS } from "./error";
import { ScriptStack } from "./stack";
import { encodeNumber, getNextNBytes, parseHex, parseNumber } from "./utils";
import * as crypto from "crypto";

//executes the op_code and modifies the stack
//todo: op_return - what does it mean by invalid
//todo: arithmetic - check for varint in parsenumber as well
export const executor = (
  stack: ScriptStack,
  initialScript: string
): { script: string } => {
  let [opcode, script] = getNextNBytes(initialScript, 1);
  if (opcode == OP_CODES.OP_0) {
    stack.push("0");
    return { script };
  } else if (
    opcode >= OP_CODES.OP_PUSHBYTES_1 &&
    opcode <= OP_CODES.OP_PUSHBYTES_75
  ) {
    let [bytes, newScript] = getNextNBytes(
      script,
      parseHex(opcode) - parseHex(OP_CODES.OP_PUSHBYTES_1) + 1
    );
    stack.push(bytes);
    return { script: newScript };
  } else if (opcode === OP_CODES.OP_PUSHDATA1) {
    let [bytesLength, newScript] = getNextNBytes(script, 1);
    let [bytes, newScript2] = getNextNBytes(newScript, parseHex(bytesLength));
    if (stack.shouldExecute()) stack.push(bytes);
    return { script: newScript2 };
  } else if (opcode === OP_CODES.OP_PUSHDATA2) {
    let [bytesLength, newScript] = getNextNBytes(script, 2);
    let [bytes, newScript2] = getNextNBytes(newScript, parseHex(bytesLength));
    if (stack.shouldExecute()) stack.push(bytes);
    return { script: newScript2 };
  } else if (opcode === OP_CODES.OP_PUSHDATA4) {
    let [bytesLength, newScript] = getNextNBytes(script, 4);
    let [bytes, newScript2] = getNextNBytes(newScript, parseHex(bytesLength));
    if (stack.shouldExecute()) stack.push(bytes);
    return { script: newScript2 };
  } else if (opcode >= OP_CODES.OP_1 && opcode <= OP_CODES.OP_16) {
    if (stack.shouldExecute())
      stack.push(String(parseHex(opcode) - parseHex(OP_CODES.OP_1) + 1));
    return { script };
  } else if (opcode === OP_CODES.OP_IF) {
    const condition = stack.pop() !== "0";
    stack.onIf(condition);
    return { script };
  } else if (opcode === OP_CODES.OP_NOTIF) {
    const condition = stack.pop() === "0";
    stack.onIf(condition);
    return { script };
  } else if (opcode === OP_CODES.OP_ELSE) {
    stack.onElse();
    return { script };
  } else if (opcode === OP_CODES.OP_ENDIF) {
    stack.onEndIf();
    return { script };
  } else if (opcode === OP_CODES.OP_NOP) {
    return { script };
  } else if (opcode === OP_CODES.OP_VERIFY) {
    if (stack.shouldExecute()) {
      const top = stack.pop();
      if (top === "0") throw new Error(ERRORS.VERIFY);
    }
    return { script };
  } else if (opcode === OP_CODES.OP_1ADD) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(encodeNumber(parseNumber(top!) + 1));
    return { script };
  } else if (opcode === OP_CODES.OP_RIPEMD160) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(crypto.createHash("ripemd160").update(top).digest("hex"));
    return { script };
  } else if (opcode === OP_CODES.OP_SHA1) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(crypto.createHash("sha1").update(top).digest("hex"));
    return { script };
  } else if (opcode === OP_CODES.OP_SHA256) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(crypto.createHash("sha256").update(top).digest("hex"));
    return { script };
  } else if (opcode === OP_CODES.OP_HASH160) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    const sha256 = crypto.createHash("sha256").update(top).digest("hex");
    stack.push(crypto.createHash("ripemd160").update(sha256).digest("hex"));
    return { script };
  } else if (opcode === OP_CODES.OP_HASH256) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    const sha256 = crypto.createHash("sha256").update(top).digest("hex");
    stack.push(crypto.createHash("sha256").update(sha256).digest("hex"));
    return { script };
  } else {
    throw new Error("not yet implemented");
  }
};

const test = `
    ${OP_CODES.OP_0}
    ${OP_CODES.OP_NOTIF}
        ${OP_CODES.OP_0}
        ${OP_CODES.OP_NOTIF}
            ${OP_CODES.OP_4}
        ${OP_CODES.OP_ELSE}
            ${OP_CODES.OP_5}
        ${OP_CODES.OP_ENDIF}
    ${OP_CODES.OP_ELSE}
        ${OP_CODES.OP_3}
    ${OP_CODES.OP_ENDIF}`.replace(/\s/g, "");

const testExecutor = () => {
  // const stack = new ScriptStack("", "");
  // let script = test;
  // console.log(script);
  // while (script.length != 0) {
  //   const { script: newScript } = executor(stack, script);
  //   script = newScript;
  // }
  // console.log(stack.top());

  const script =
    "52210395f33d5a959556ba6b57298066baf468c2e5ab3cc58ddaf7166f057fae1655a7210246aae217f1102dde12a7e77203f7114de07f0068cfb1a3d825fff4ca2266737621028ace79c534a3b5c482b6cc446ea20d757e88c516ec054ae31c7a47863864904853ae";
  const sha256 = crypto
    .createHash("sha256")
    .update(Buffer.from(script, "hex"))
    .digest("hex");
  console.log(sha256);
};

testExecutor();
