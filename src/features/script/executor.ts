import { OP_CODES } from "./op_codes";
import { ERRORS } from "./error";
import { ScriptStack } from "./stack";
import { encodeNumber, getNextNBytes, parseHex, parseNumber } from "./utils";
import * as crypto from "crypto";
import { FALSE } from "./constants";
import { hash160, hash256, sha256 } from "../../utils";
import { extractRSFromSignature } from "../encoding/serializer";
import { extractSighashFromSignature } from "../validator/signature";

import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";

import { getTransactionType } from "../transaction/utils";
import { compactSize } from "../encoding/compactSize";

const ECPair = ECPairFactory(ecc);

export const executor = (
  stack: ScriptStack,
  initialScript: string
): { script: string } => {
  let [opcode, script] = getNextNBytes(initialScript, 1);
  if (opcode === OP_CODES.OP_0) {
    if (stack.shouldExecute()) stack.push(FALSE);
    return { script };
  } else if (
    opcode >= OP_CODES.OP_PUSHBYTES_1 &&
    opcode <= OP_CODES.OP_PUSHBYTES_75
  ) {
    const length = parseHex(opcode) - parseHex(OP_CODES.OP_PUSHBYTES_1) + 1;
    let [bytes, newScript] = getNextNBytes(script, length);

    if (stack.shouldExecute()) stack.push(bytes);
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
    if (stack.shouldExecute()) {
      const buf = Buffer.alloc(1);
      const num = parseHex(opcode) - parseHex(OP_CODES.OP_1) + 1;

      buf.writeUintLE(num, 0, 1);

      stack.push(buf.toString("hex"));
    }
    return { script };
  } else if (opcode === OP_CODES.OP_IF) {
    const condition = stack.top() !== FALSE;
    stack.onIf(condition);

    return { script };
  } else if (opcode === OP_CODES.OP_IFDUP) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.top();

    if (!top) throw new Error(ERRORS.STACK_EMPTY);

    if (top !== FALSE) stack.push(top);

    return { script };
  } else if (opcode === OP_CODES.OP_NOTIF) {
    const condition = stack.top() === FALSE;
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
      if (top === FALSE) throw new Error(ERRORS.VERIFY);
    }
    return { script };
  } else if (opcode === OP_CODES.OP_1ADD) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(encodeNumber(parseNumber(top) + 1));
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
    stack.push(sha256(top));
    return { script };
  } else if (opcode === OP_CODES.OP_HASH160) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(hash160(top));
    return { script };
  } else if (opcode === OP_CODES.OP_HASH256) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(hash256(top));
    return { script };
  } else if (
    opcode === OP_CODES.OP_EQUAL ||
    opcode === OP_CODES.OP_EQUALVERIFY
  ) {
    if (!stack.shouldExecute()) return { script };
    const first = stack.pop();
    const second = stack.pop();
    if (!first || !second) throw new Error(ERRORS.STACK_EMPTY);
    stack.push(first === second ? OP_CODES.OP_1 : FALSE);
    if (opcode === OP_CODES.OP_EQUALVERIFY) {
      if (stack.pop() === FALSE) throw new Error(ERRORS.VERIFY);
    }
    return { script };
  } else if (
    opcode === OP_CODES.OP_CHECKSIG ||
    opcode === OP_CODES.OP_CHECKSIGVERIFY
  ) {
    if (!stack.shouldExecute()) return { script };

    const pubkey = stack.pop();
    const derEncodedSignature = stack.pop();

    if (!pubkey || !derEncodedSignature) throw new Error(ERRORS.STACK_EMPTY);

    const sighash = extractSighashFromSignature(derEncodedSignature);
    const sig = extractRSFromSignature(derEncodedSignature);

    const msg = stack.tx.signWith(
      stack.index,
      sighash,
      getTransactionType(stack.tx, stack.index)
    );
    const hash = hash256(msg);
    const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex"));

    const valid = ecpair.verify(
      Buffer.from(hash, "hex"),
      Buffer.from(sig, "hex")
    );

    if (valid) stack.push(OP_CODES.OP_1);
    else stack.push(FALSE);

    if (opcode === OP_CODES.OP_CHECKSIGVERIFY) {
      if (stack.pop() === FALSE) throw new Error(ERRORS.VERIFY);
    }

    return { script };
  } else if (opcode === OP_CODES.OP_CHECKMULTISIG) {
    if (!stack.shouldExecute()) return { script };
    const pubkeys = [];
    const sigs = [];
    let n = stack.pop();
    if (!n) throw new Error(ERRORS.STACK_EMPTY);
    if (isNaN(+n)) throw new Error(ERRORS.MULTISIG.INVALID_N_VALUE);
    let iterator = +n;
    while (iterator--) {
      pubkeys.push(stack.pop());
    }
    let m = stack.pop();
    if (!m) throw new Error(ERRORS.STACK_EMPTY);
    if (isNaN(+m)) throw new Error(ERRORS.MULTISIG.INVALID_M_VALUE);
    iterator = +m;
    while (iterator--) {
      sigs.push(stack.pop());
    }
    if (pubkeys.length < sigs.length)
      throw new Error(ERRORS.MULTISIG.M_GREATER_THAN_N);

    let sigIterator = 0;
    let pubkeyIterator = 0;
    let validPairs = 0;

    while (sigIterator < sigs.length && pubkeyIterator < pubkeys.length) {
      const derEncodedSignature = sigs[sigIterator]!; //iterator will always be < sigs.length
      const pubkey = pubkeys[pubkeyIterator]!; //iterator will always be < pubkeys.length as sig.length < sigs.length

      if (!derEncodedSignature || !pubkey) throw new Error(ERRORS.STACK_EMPTY);
      const sighash = extractSighashFromSignature(derEncodedSignature);
      if (!stack.tx.vin[stack.index].prevout) return { script }; // "0" will be on top
      const msg = stack.tx.signWith(
        stack.index,
        sighash,
        getTransactionType(stack.tx, stack.index)
      );

      const sig = extractRSFromSignature(derEncodedSignature);
      const hash = hash256(msg);

      const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex"));

      const valid = ecpair.verify(
        Buffer.from(hash, "hex"),
        Buffer.from(sig, "hex")
      );
      pubkeyIterator++;
      if (valid) {
        validPairs++;
        sigIterator++;
      }
    }

    stack.pop(); //pop 0 element
    if (validPairs >= +m) stack.push(OP_CODES.OP_1);
    else stack.push(FALSE);

    return { script };
  } else if (opcode === OP_CODES.OP_CHECKLOCKTIMEVERIFY) {
    if (!stack.shouldExecute()) return { script };
    const cltvLE = stack.pop();
    if (!cltvLE) throw new Error(ERRORS.STACK_EMPTY);

    const buf = Buffer.from(cltvLE, "hex");
    const num = buf.readUintLE(0, buf.length);

    if (num > stack.tx.locktime) throw new Error(ERRORS.INVALID_TX);

    return { script };
  } else if (opcode === OP_CODES.OP_CHECKSEQUENCEVERIFY) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.top();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);

    const buf = Buffer.from(top.padStart(2, "0"), "hex");
    const num = buf.readUintLE(0, buf.length);

    if (num > stack.tx.vin[stack.index].sequence)
      throw new Error(ERRORS.INVALID_TX);

    return { script };
  } else if (opcode === OP_CODES.OP_DROP) {
    if (!stack.shouldExecute()) return { script };
    const top = stack.pop();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);
    return { script };
  } else if (opcode === OP_CODES.OP_DUP) {
    if (!stack.shouldExecute()) return { script };

    const top = stack.top();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);

    stack.push(top);
    return { script };
  } else if (opcode === OP_CODES.OP_SIZE) {
    if (!stack.shouldExecute()) return { script };

    const top = stack.top();
    if (!top) throw new Error(ERRORS.STACK_EMPTY);

    stack.push(compactSize(BigInt(top.length / 2)).toString("hex"));

    return { script };
  } else if (opcode === OP_CODES.OP_SWAP) {
    if (!stack.shouldExecute()) return { script };

    const top1 = stack.pop();
    const top2 = stack.pop();

    if (!top1 || !top2) throw new Error(ERRORS.STACK_EMPTY);

    stack.push(top1);
    stack.push(top2);

    return { script };
  } else if (opcode === OP_CODES.OP_GREATERTHAN) {
    if (!stack.shouldExecute()) return { script };
    //should be a > b
    const b = stack.pop();
    const a = stack.pop();

    if (!b || !a) throw new Error(ERRORS.STACK_EMPTY);

    const bufA = Buffer.from(a.padStart(2, "0"), "hex");
    const bufB = Buffer.from(b.padStart(2, "0"), "hex");

    const numA = bufA.readUintLE(0, bufA.length);
    const numB = bufB.readUintLE(0, bufB.length);

    if (numA > numB) stack.push(OP_CODES.OP_1);
    else stack.push(FALSE);
    return { script };
  } else if (opcode === OP_CODES.OP_ROT) {
    if (!stack.shouldExecute()) return { script };
    const top1 = stack.pop();
    const top2 = stack.pop();
    const top3 = stack.pop();

    if (!top1 || !top2 || !top3) throw new Error(ERRORS.STACK_EMPTY);

    stack.push(top2);
    stack.push(top1);
    stack.push(top3);

    return { script };
  } else if (opcode === OP_CODES.OP_OVER) {
    if (!stack.shouldExecute()) return { script };

    const top1 = stack.pop();
    const top2 = stack.pop();

    if (!top1 || !top2) throw new Error(ERRORS.STACK_EMPTY);

    stack.push(top2);
    stack.push(top1);
    stack.push(top2);

    return { script };
  } else {
    console.log(JSON.stringify(stack.tx.vin[stack.index], null, 4));
    throw new Error("not yet implemented: " + opcode);
  }
};
