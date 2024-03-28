import { TransactionType } from "../../types";
import * as crypto from "crypto";
import { asmToHex, hash160, sha256 } from "../../utils";
import { OP_CODES } from "../script/op_codes";
import { collapseTextChangeRangesAcrossMultipleVersions } from "typescript";
import { Transaction } from "../transaction";

//in p2sh p2wsh
//sha256(inner witness script) = last part of inneer redeem script
//hash160 of the inner redeem script should be equal to the hash in the script pubkey
//eg 0d9ef76964c23e940ebcddde868c1089dfdb52147364da01ee92438dfb7c9375

export const HashValidator = (tx: Transaction) => {
  let lockingScript = "";
  let script = "";
  let hash = "";
  let publicKey = "";

  for (const input of tx.vin) {
    if (!input.prevout) continue;
    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2PKH:
        const scriptAsmTokens = input.scriptsig_asm.split(" ");
        publicKey = scriptAsmTokens[scriptAsmTokens.length - 1];

        hash = hash160(publicKey);

        lockingScript = input.prevout.scriptpubkey;
        script = `${OP_CODES.OP_DUP}${OP_CODES.OP_HASH160}${OP_CODES.OP_PUSHBYTES_20}${hash}${OP_CODES.OP_EQUALVERIFY}${OP_CODES.OP_CHECKSIG}`;

        if (script !== lockingScript) return false;
        break;
      case TransactionType.P2SH:
        const inputScript = input.scriptsig_asm.split(" ");
        const hex = asmToHex(inputScript[inputScript.length - 1]);
        lockingScript = input.prevout.scriptpubkey;

        const scriptHash = hash160(hex);

        script = `${OP_CODES.OP_HASH160}${OP_CODES.OP_PUSHBYTES_20}${scriptHash}${OP_CODES.OP_EQUAL}`;
        if (script !== lockingScript) return false;
        break;
      case TransactionType.P2WPKH:
        if (!input.witness || !input.witness[1]) return false;
        publicKey = input.witness[1];

        hash = hash160(publicKey);
        lockingScript = input.prevout.scriptpubkey;
        script = `${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_20}${hash}`;

        if (script !== lockingScript) return false;
        break;
      case TransactionType.P2WSH:
        if (!input.witness) return false;
        const witnessScript = input.witness[input.witness.length - 1];
        if (!witnessScript) return false;

        lockingScript = input.prevout.scriptpubkey;
        script = `${OP_CODES.OP_0}${OP_CODES.OP_PUSHBYTES_32}${sha256(
          witnessScript
        )}`;
        if (script !== lockingScript) return false;
        break;
    }
  }

  return true;
};
