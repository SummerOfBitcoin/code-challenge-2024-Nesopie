import { Transaction, TransactionType } from "../../types";
import * as crypto from "crypto";
import { asmToHex, hash256, sha256 } from "../../utils";
import { OP_CODES } from "../script/op_codes";
import { collapseTextChangeRangesAcrossMultipleVersions } from "typescript";

export const HashValidator = (tx: Transaction) => {
  let lockingScript = "";
  let script = "";
  let hash = "";
  let publicKey = "";

  for (const input of tx.vin) {
    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2PKH:
        const scriptAsmTokens = input.scriptsig_asm.split(" ");
        publicKey = scriptAsmTokens[scriptAsmTokens.length - 1];

        hash = hash256(publicKey);

        lockingScript = input.prevout.scriptpubkey;
        script = `${OP_CODES.OP_DUP}${OP_CODES.OP_HASH160}${OP_CODES.OP_PUSHBYTES_20}${hash}${OP_CODES.OP_EQUALVERIFY}${OP_CODES.OP_CHECKSIG}`;

        if (script !== lockingScript) return false;
        break;
      case TransactionType.P2SH:
        const inputScript = input.scriptsig_asm.split(" ");
        const hex = asmToHex(inputScript[inputScript.length - 1]);
        lockingScript = input.prevout.scriptpubkey;

        const scriptHash = hash256(hex);

        script = `${OP_CODES.OP_HASH160}${OP_CODES.OP_PUSHBYTES_20}${scriptHash}${OP_CODES.OP_EQUAL}`;
        if (script !== lockingScript) return false;
        break;
      case TransactionType.P2WPKH:
        publicKey = input.witness[1];
        if (!publicKey) return false;

        hash = hash256(publicKey);
        lockingScript = input.prevout.scriptpubkey;
        script = `${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_20}${hash}`;

        if (script !== lockingScript) return false;
        break;
      case TransactionType.P2WSH:
        const witnessScript = input.witness[input.witness.length - 1];
        if (!witnessScript) return false;

        lockingScript = input.prevout.scriptpubkey;
        //OP_0 OP_PUSHBYTES_32 0b685cc06add0b2e23bcd67f0bef8d364cdc1abcf6fb126958826a7cfe351bf3
        script = `${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_32}${sha256(
          witnessScript
        )}`;
        if (script !== lockingScript) return false;
        break;
    }
  }

  return true;
};
