import { SigHash, TransactionType } from "../../types";
import { Transaction } from "../transaction";
import { hash160, sha256 } from "../../utils";
import * as asn1js from "asn1js";

import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { Serializer } from "../encoding/serializer";

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
    for (let i = 0; i < tx.vin.length; i++) {
        const input = tx.vin[i];
        if (!input.prevout) return true; //there is nothing to validate
        switch (input.prevout.scriptpubkey_type) {
            case TransactionType.P2PKH: {
                const asmTokens = input.scriptsig_asm.split(" ");
                const derEncodedSignature = asmTokens[1];
                const pubkey = asmTokens[asmTokens.length - 1];
                const sighash =
                    extractSighashFromSignature(derEncodedSignature);
                const asn1 = asn1js.fromBER(
                    Buffer.from(derEncodedSignature, "hex")
                );

                let r = Buffer.from(
                    (asn1.result.valueBlock as any).value[0].valueBlock
                        .valueHexView
                ).toString("hex");
                let s = Buffer.from(
                    (asn1.result.valueBlock as any).value[1].valueBlock
                        .valueHexView
                ).toString("hex");

                const signature = removePadding(r, s);

                const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex")); //p2wpkh pubkeys must be compressed

                const msg = tx.signWith(i, sighash);
                const hash = sha256(sha256(msg));
                const valid = ecpair.verify(
                    Buffer.from(hash, "hex"),
                    Buffer.from(signature, "hex")
                );
                if (!valid) return false;
                break;
            }

            case TransactionType.P2WPKH: {
                if (!input.witness) return false;
                const derEncodedSignature = input.witness[0];
                const pubkey = input.witness[1];
                const pubkeyHash = hash160(pubkey);
                const pubkeyInScript = input.prevout.scriptpubkey.slice(4);

                if (pubkeyHash !== pubkeyInScript) return false;

                const sighash =
                    extractSighashFromSignature(derEncodedSignature);

                const asn1 = asn1js.fromBER(
                    Buffer.from(derEncodedSignature, "hex")
                );

                let r = Buffer.from(
                    (asn1.result.valueBlock as any).value[0].valueBlock
                        .valueHexView
                ).toString("hex");
                let s = Buffer.from(
                    (asn1.result.valueBlock as any).value[1].valueBlock
                        .valueHexView
                ).toString("hex");

                const signature = removePadding(r, s);

                const ecpair = ECPair.fromPublicKey(
                    Buffer.from(pubkey, "hex"),
                    { compressed: true }
                );
                const msg = Serializer.serializeWitness(tx, i, sighash);
                const hash = sha256(sha256(msg));
                const valid = ecpair.verify(
                    Buffer.from(hash, "hex"),
                    Buffer.from(signature, "hex")
                );
                if (!valid) {
                    console.log("valid: ", valid);
                    return false;
                }
                break;
            }
        }
    }

    return true;
};

// const derEncodedSignature =
//     "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee";
// const pubkey =
//     "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
// const sighash = extractSighashFromSignature(derEncodedSignature);
// const asn1 = asn1js.fromBER(Buffer.from(derEncodedSignature, "hex"));

// let r = Buffer.from(
//     (asn1.result.valueBlock as any).value[0].valueBlock.valueHexView
// ).toString("hex");
// let s = Buffer.from(
//     (asn1.result.valueBlock as any).value[1].valueBlock.valueHexView
// ).toString("hex");

// const signature = removePadding(r, s);

// const ecpair = ECPair.fromPublicKey(Buffer.from(pubkey, "hex")); //p2wpkh pubkeys must be compressed

// const hash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
// const valid = ecpair.verify(
//     Buffer.from(hash, "hex"),
//     Buffer.from(signature, "hex")
// );

// console.log(valid);
