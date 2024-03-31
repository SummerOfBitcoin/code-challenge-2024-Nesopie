import { Input } from "./input";
import { Output } from "./output";
import { Serializer } from "../../encoding/serializer";
import { hash160, hash256, reversify, sha256 } from "../../../utils";
import { SigHash, TransactionType } from "../../../types";
import cloneDeep from "lodash.clonedeep";
import { Errors } from "../errors";
import { calculateWeight } from "../utils";
import { ZERO } from "../../../constants";
import { TEMPLATES } from "../../encoding/witnessTemplates";
import { compactSize } from "../../encoding/compactSize";
import { collapseTextChangeRangesAcrossMultipleVersions } from "typescript";

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

  version: number;
  locktime: number;
  vin: Input[] = [];
  vout: Output[] = [];
  isSegwit = false;

  constructor(version: number, locktime: number) {
    this.version = version;
    this.locktime = locktime;
  }

  addInput(input: Input) {
    this.resetState();
    if (input.witness && input.witness.length > 0) this.isSegwit = true;
    this.vin.push(input);
  }

  addOutput(output: Output) {
    this.resetState();
    this.vout.push(output);
  }

  signWith(
    inputIndex: number,
    sighash: SigHash,
    transactionType: TransactionType
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
    const weight = calculateWeight(this, this.isSegwit);
    this._weight = weight;
    return this._weight;
  }

  private resetState() {
    //remove cache as it gets invalidated when tx gets changed such as when you're adding input or outputs;
    this._txid = undefined;
    this._wtxid = undefined;
    this._serializedTx = undefined;
    this._serializedWTx = undefined;
  }
}
