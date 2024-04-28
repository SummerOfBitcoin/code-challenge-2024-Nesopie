import { TransactionType } from "../../../types";
import { Serializer } from "../../encoding/serializer";
import { TxOut } from "../types";

export class Output {
  scriptpubkey: string;
  scriptpubkey_asm: string;
  scriptpubkey_type: string;
  scriptpubkey_address?: string;
  value: number;

  private _serialized: string | undefined;
  constructor(outputConfig: TxOut) {
    this.scriptpubkey = outputConfig.scriptpubkey;
    this.scriptpubkey_asm = outputConfig.scriptpubkey_asm;
    this.scriptpubkey_type = outputConfig.scriptpubkey_type;
    this.scriptpubkey_address = outputConfig.scriptpubkey_address;
    this.value = outputConfig.value;
  }

  serialize() {
    if (this._serialized) {
      return this._serialized;
    }
    this._serialized = Serializer.serializeOutput(this);
    return this._serialized;
  }
}
