import { stringify } from "querystring";
import { Output } from "./output";
import { Serializer } from "../encoding/serializer";
import { TxIn, TxOut } from "./types";

export class Input {
  txid: string;
  vout: number;
  prevout: TxOut | null; //null in the case of coinbase
  scriptsig: string;
  scriptsig_asm: string;
  witness?: string[];
  is_coinbase: boolean;
  sequence: number;
  inner_redeemscript_asm: string | undefined;
  inner_witnessscript_asm: string | undefined;

  constructor(inputConfig: TxIn) {
    this.txid = inputConfig.txid;
    this.vout = inputConfig.vout;
    this.prevout = inputConfig.prevout;
    this.scriptsig = inputConfig.scriptsig;
    this.scriptsig_asm = inputConfig.scriptsig_asm;
    this.witness = inputConfig.witness;
    this.is_coinbase = inputConfig.is_coinbase;
    this.sequence = inputConfig.sequence;
    this.inner_redeemscript_asm = inputConfig.inner_redeemscript_asm;
    this.inner_witnessscript_asm = inputConfig.inner_witnessscript_asm;
  }

  serialize() {
    return Serializer.serializeInput(this);
  }
}
