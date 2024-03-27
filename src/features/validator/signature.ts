import { SigHash, TransactionType } from "../../types";
import { Transaction } from "../transaction";
import { hash256, sha256 } from "../../utils";
import * as asn1js from "asn1js";

import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";

const ECPair = ECPairFactory(ecc);

const removePadding = (r: string, s: string) => {
  //remove der padding if length === 66
  if (r.length === 66) {
    r = r.slice(2);
  }
  if (s.length === 66) {
    s = s.slice(2);
  }

  //add padding to make it 32 bytes for ecpair
  r = r.padStart(64, "0");
  s = s.padStart(64, "0");

  return r + s;
};

const extractSighashFromSignature = (signature: string) => {
  return signature.slice(signature.length - 2) as SigHash;
};

export const signatureValidator = (tx: Transaction): boolean => {
  let pubkey = "";
  let derEncodedSignature = "";
  for (let i = 0; i < tx.vin.length; i++) {
    const input = tx.vin[i];
    if (!input.prevout) return true; //there is nothing to validate
    switch (input.prevout.scriptpubkey_type) {
      case TransactionType.P2PKH:
        const asmTokens = input.scriptsig_asm.split(" ");
        derEncodedSignature = asmTokens[1];
        pubkey = asmTokens[asmTokens.length - 1];
        const sighash = extractSighashFromSignature(derEncodedSignature);
        const asn1 = asn1js.fromBER(Buffer.from(derEncodedSignature, "hex"));

        let r = Buffer.from(
          (asn1.result.valueBlock as any).value[0].valueBlock.valueHexView
        ).toString("hex");
        let s = Buffer.from(
          (asn1.result.valueBlock as any).value[1].valueBlock.valueHexView
        ).toString("hex");

        const signature = removePadding(r, s);

        const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex"));

        const msg = tx.signWith(i, sighash);
        const hash = sha256(sha256(msg));
        const valid = ecpair.verify(
          Buffer.from(hash, "hex"),
          Buffer.from(signature, "hex")
        );
        if (!valid) return false;
        break;

      case TransactionType.P2WPKH:
        if (!input.witness) return false;
        derEncodedSignature = input.witness[0];
        pubkey = input.witness[1];
        const pubkeyHash = hash256(pubkey);
        const pubkeyInScript = input.prevout.scriptpubkey.slice(4);

        if (pubkeyHash !== pubkeyInScript) return false;
    }
  }

  return true;
};
