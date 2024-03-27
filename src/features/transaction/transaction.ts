import { Input } from "./input";
import { Output } from "./output";
import { Serializer } from "../encoding/serializer";
import { reversify, sha256 } from "../../utils";
import { SigHash } from "../../types";
import cloneDeep from "lodash.clonedeep";
import { Errors } from "./errors";
import { calculateWeight } from "./utils";

//depending on static serializer methods, instead use dependency injection
export class Transaction {
  private _txid: string | undefined; //cache these values
  private _wtxid: string | undefined;
  private _serializedTx: string | undefined;
  private _serializedWTx: string | undefined;
  private _weight: number | undefined;
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

  signWith(inputIndex: number, sighash: SigHash) {
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
      case SigHash.ALL_ANYONECANPAY:
        hashcode.writeUint32LE(0x81, 0);
        txCopy.vin = [txCopy.vin[inputIndex]];
        const input = txCopy.vin[0].prevout;
        if (!input) throw new Error(Errors.INVALID_INPUT);
        txCopy.vin[0].scriptsig = input.scriptpubkey;
        break;
    }

    return txCopy.serializedTx + hashcode.toString("hex");
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
