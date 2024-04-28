import { Input } from "./input";
import { Output } from "./output";
import { Serializer } from "../../encoding/serializer";
import {
  hash160,
  hash256,
  reversify,
  sha256,
  taprootHash,
} from "../../../utils";
import { SigHash, TransactionType } from "../../../types";
import cloneDeep from "lodash.clonedeep";
import { Errors } from "../errors";
import { calculateWeight } from "../utils";
import { TAP_SIG_HASH, ZERO } from "../../../constants";
import { TEMPLATES } from "../../encoding/witnessTemplates";
import { compactSize } from "../../encoding/compactSize";

import { ECPairFactory } from "ecpair";
import * as ecc from "tiny-secp256k1";
import { calculateFee } from "../../block/fee";

const ECPair = ECPairFactory(ecc);

//depending on static serializer methods, instead use dependency injection
export class Transaction {
  private _txid: string | undefined; //cache these values
  private _wtxid: string | undefined;
  private _serializedTx: string | undefined;
  private _serializedWTx: string | undefined;
  private _weight: number | undefined;
  private _hashPrevouts: string | undefined;
  private _hashSequence: string | undefined;
  private _hashOutputs: string | undefined;
  private _fee: number | undefined;
  private _feeRate: number | undefined;

  version: number;
  locktime: number;
  vin: Input[] = [];
  vout: Output[] = [];
  isSegwit = false;
  isBip125Replaceable = false;

  constructor(version: number, locktime: number) {
    this.version = version;
    this.locktime = locktime;
  }

  addInput(input: Input) {
    this.resetState();
    if (input.witness && input.witness.length > 0) this.isSegwit = true;
    if (input.sequence < 0xffffffff - 1) this.isBip125Replaceable = true;
    this.vin.push(input);
  }

  addOutput(output: Output) {
    this.resetState();
    this.vout.push(output);
  }

  signWith(
    inputIndex: number,
    sighash: SigHash | 0x00,
    transactionType: TransactionType, //can be moved internally?
    extFlag: number = 0x00,
    extension?: string
  ) {
    if (
      transactionType === TransactionType.P2PKH ||
      transactionType === TransactionType.P2SH
    ) {
      const txCopy = cloneDeep(this);
      let hashcode = Buffer.alloc(4);
      switch (sighash) {
        case SigHash.ALL:
          for (let i = 0; i < txCopy.vin.length; i++) {
            hashcode.writeUint32LE(1, 0);
            if (i === inputIndex) {
              const input = txCopy.vin[i].prevout;
              if (!input) throw new Error(Errors.INVALID_INPUT);
              txCopy.vin[i].scriptsig = input.scriptpubkey;
            } else {
              txCopy.vin[i].scriptsig = "";
            }
          }
          break;
        case SigHash.ALL | SigHash.ANYONE_CAN_PAY:
          hashcode.writeUint32LE(0x81, 0);
          txCopy.vin = [txCopy.vin[inputIndex]];
          const input = txCopy.vin[0].prevout;
          if (!input) throw new Error(Errors.INVALID_INPUT);
          txCopy.vin[0].scriptsig = input.scriptpubkey;
          break;
      }

      return txCopy.serializedTx + hashcode.toString("hex");
    } else if (transactionType === TransactionType.P2TR) {
      let serializedWTx = "";
      const hashtype = Buffer.alloc(1);
      hashtype.writeUintLE(sighash, 0, 1);

      const nVersion = Buffer.alloc(4);
      nVersion.writeUint32LE(this.version, 0);

      const nLocktime = Buffer.alloc(4);
      nLocktime.writeUint32LE(this.locktime, 0);

      let prevouts = "";
      let shaPrevouts = "";

      let amounts = "";
      let shaAmounts = "";

      let scripts = "";
      let shaScripts = "";

      let sequences = "";
      let shaSequences = "";

      let annex = undefined;

      if (
        this.vin[inputIndex].witness &&
        this.vin[inputIndex].witness!.length > 1
      ) {
        const input = this.vin[inputIndex];
        const lastWitness = input.witness![input.witness!.length - 1];

        if (lastWitness.startsWith("50")) annex = lastWitness;
      }
      const annexBit = Buffer.alloc(1);
      annexBit.writeUintLE(annex ? 1 : 0, 0, 1);

      const extendBit = Buffer.alloc(1);
      extendBit.writeUintLE(extension ? 1 : 0, 0, 1);

      const spendType = Buffer.alloc(1);
      spendType.writeUintLE(
        (extFlag + extendBit.readUintLE(0, 1)) * 2 + annexBit.readUintLE(0, 1),
        0,
        1
      );

      let shaAnnex = "";
      if (annex) {
        shaAnnex = sha256(
          compactSize(BigInt(annex.length / 2)).toString("hex") + annex
        );
      }

      if (!((sighash & SigHash.ANYONE_CAN_PAY) === SigHash.ANYONE_CAN_PAY)) {
        for (const input of this.vin) {
          prevouts += reversify(input.txid);
          const prevoutVout = Buffer.alloc(4);
          prevoutVout.writeUint32LE(input.vout, 0);
          prevouts += prevoutVout.toString("hex");

          if (!input.prevout) continue;

          const amount = Buffer.alloc(8);
          amount.writeBigInt64LE(BigInt(input.prevout!.value), 0);
          amounts += amount.toString("hex");

          scripts += compactSize(
            BigInt(input.prevout!.scriptpubkey.length / 2)
          ).toString("hex");
          scripts += input.prevout?.scriptpubkey;

          const sequence = Buffer.alloc(4);
          sequence.writeUint32LE(input.sequence, 0);
          sequences += sequence.toString("hex");
        }
        shaPrevouts = sha256(prevouts);
        shaAmounts = sha256(amounts);
        shaScripts = sha256(scripts);
        shaSequences = sha256(sequences);
      }

      let outputs = "";
      let shaOutputs = "";

      if ((sighash & 0x03) < 2 || (sighash & 0x02) > 3) {
        for (const output of this.vout) {
          outputs += output.serialize();
        }

        shaOutputs = sha256(outputs);
      }

      let inputData = "";
      if ((sighash & SigHash.ANYONE_CAN_PAY) === SigHash.ANYONE_CAN_PAY) {
        const input = this.vin[inputIndex];

        inputData += reversify(input.txid);

        const prevoutVout = Buffer.alloc(4);
        prevoutVout.writeUint32LE(input.vout, 0);
        inputData += prevoutVout.toString("hex");

        const amount = Buffer.alloc(8);
        amount.writeBigInt64LE(BigInt(input.prevout!.value), 0);
        inputData += amount.toString("hex");

        inputData += compactSize(
          BigInt(input.prevout!.scriptpubkey.length / 2)
        ).toString("hex");
        inputData += input.prevout!.scriptpubkey;

        const sequence = Buffer.alloc(4);
        sequence.writeUint32LE(input.sequence, 0);
        inputData += sequence.toString("hex");
      } else {
        const index = Buffer.alloc(4);
        index.writeUint32LE(inputIndex, 0);

        inputData += index.toString("hex");
      }

      let outputData = "";
      let shaoutputData = "";
      if ((sighash & SigHash.SINGLE) === SigHash.SINGLE) {
        outputData = this.vout[inputIndex].serialize();
        shaoutputData = sha256(outputData);
      }

      serializedWTx += hashtype.toString("hex");
      serializedWTx += nVersion.toString("hex");
      serializedWTx += nLocktime.toString("hex");

      serializedWTx += shaPrevouts;
      serializedWTx += shaAmounts;
      serializedWTx += shaScripts;
      serializedWTx += shaSequences;
      serializedWTx += shaOutputs;

      serializedWTx += spendType.toString("hex");
      serializedWTx += inputData;

      serializedWTx += shaAnnex;
      serializedWTx += shaoutputData;

      return serializedWTx;
    }
    let serializedWTx = "";

    const version = Buffer.alloc(4);
    version.writeUint32LE(this.version, 0);

    let prevouts = "";
    let sequences = "";
    let hashPrevouts = "";
    let hashSequence = "";
    if (sighash >= SigHash.ANYONE_CAN_PAY) hashPrevouts = ZERO;
    else {
      if (this._hashPrevouts) {
        hashPrevouts = this._hashPrevouts;
      } else {
        for (const input of this.vin) {
          prevouts += reversify(input.txid);
          const prevoutVout = Buffer.alloc(4);
          prevoutVout.writeUint32LE(input.vout, 0);
          prevouts += prevoutVout.toString("hex");
        }
        hashPrevouts = hash256(prevouts);
        this._hashPrevouts = hashPrevouts;
      }
    }

    if (
      sighash >= SigHash.ANYONE_CAN_PAY ||
      sighash === SigHash.SINGLE ||
      sighash === SigHash.NONE
    )
      hashSequence = ZERO;
    else {
      if (this._hashSequence) {
        hashSequence = this._hashSequence;
      } else {
        for (const input of this.vin) {
          const sequence = Buffer.alloc(4);
          sequence.writeUint32LE(input.sequence, 0);
          sequences += sequence.toString("hex");
        }
        hashSequence = hash256(sequences);
        this._hashSequence = hashSequence;
      }
    }

    let outputs = "";
    let hashOutputs = "";
    if (
      (sighash & 0x1f) === SigHash.SINGLE ||
      (sighash & 0x1f) === SigHash.NONE
    ) {
      if (
        (sighash & 0x1f) === SigHash.SINGLE &&
        inputIndex < this.vout.length
      ) {
        hashOutputs = hash256(this.vout[inputIndex].serialize());
      } else hashOutputs = ZERO;
    } else {
      if (this._hashOutputs) {
        hashOutputs = this._hashOutputs;
      } else {
        for (const output of this.vout) {
          outputs += output.serialize();
        }
        hashOutputs = hash256(outputs);
        this._hashOutputs = hashOutputs;
      }
    }

    const input = this.vin[inputIndex];
    if (!input) throw new Error(Errors.INVALID_VOUT);
    const vout = Buffer.alloc(4);
    vout.writeUint32LE(input.vout, 0);
    const outpoint = reversify(input.txid) + vout.toString("hex");

    if (!input.witness) throw new Error(Errors.INVALID_WITNESS);
    let scriptCode = "";
    if (transactionType === TransactionType.P2WPKH) {
      if (!input.witness[1]) throw new Error(Errors.PUBKEY_NOT_FOUND);
      scriptCode = TEMPLATES.P2WPKH(hash160(input.witness[1]));
    } else {
      const script = input.witness[input.witness.length - 1];
      const scriptLength = compactSize(BigInt(script.length / 2));
      scriptCode = scriptLength.toString("hex") + script;
    }

    if (!input.prevout) throw new Error(Errors.INVALID_PREVOUT);
    const amount = Buffer.alloc(8);
    amount.writeBigInt64LE(BigInt(input.prevout.value), 0);

    const nSequence = Buffer.alloc(4);
    nSequence.writeUint32LE(input.sequence, 0);

    const nLocktime = Buffer.alloc(4);
    nLocktime.writeUint32LE(this.locktime, 0);

    const hashcode = Buffer.alloc(4);
    hashcode.writeUint32LE(sighash, 0);

    serializedWTx += version.toString("hex");
    serializedWTx += hashPrevouts;
    serializedWTx += hashSequence;
    serializedWTx += outpoint;
    serializedWTx += scriptCode;
    serializedWTx += amount.toString("hex");
    serializedWTx += nSequence.toString("hex");
    serializedWTx += hashOutputs;
    serializedWTx += nLocktime.toString("hex");
    serializedWTx += hashcode.toString("hex");

    return serializedWTx;
  }

  get serializedTx() {
    if (this._serializedTx) return this._serializedTx;
    this._serializedTx = Serializer.serializeTx(this);
    return this._serializedTx;
  }

  get serializedWTx() {
    if (this._serializedWTx) return this._serializedWTx;
    this._serializedWTx = Serializer.serializeWTx(this);
    return this._serializedWTx;
  }

  get txid() {
    if (this._txid) return this._txid;
    const txid = reversify(sha256(sha256(this.serializedTx)));
    this._txid = txid;
    return this._txid;
  }

  get wtxid() {
    if (!this.isSegwit) return this.txid;
    if (this._wtxid) return this._wtxid;
    const wtxid = reversify(sha256(sha256(this.serializedWTx)));
    this._wtxid = wtxid;
    return this._wtxid;
  }

  get weight() {
    if (this._weight) return this._weight;
    const weight = calculateWeight(this);
    this._weight = weight;
    return this._weight;
  }

  get fee() {
    if (this._fee) return this._fee;
    const fee = calculateFee(this);
    this._fee = fee;
    return this._fee;
  }

  get feeRate() {
    if (this._feeRate) return this._feeRate;
    const feeRate = this.fee / this.weight;
    this._feeRate = feeRate;
    return this._feeRate;
  }

  private resetState() {
    //remove cache as it gets invalidated when tx gets changed such as when you're adding input or outputs;
    this._txid = undefined;
    this._wtxid = undefined;
    this._serializedTx = undefined;
    this._serializedWTx = undefined;
  }
}
