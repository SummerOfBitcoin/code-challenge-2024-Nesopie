import { Serializer } from "../encoding/serializer";
import { TxOut } from "./types";

export class Output {
  scriptpubkey: string;
  scriptpubkey_asm: string;
  scriptpubkey_type: string;
  scriptpubkey_address?: string;
  value: number;
  constructor(outputConfig: TxOut) {
    this.scriptpubkey = outputConfig.scriptpubkey;
    this.scriptpubkey_asm = outputConfig.scriptpubkey_asm;
    this.scriptpubkey_type = outputConfig.scriptpubkey_type;
    this.scriptpubkey_address = outputConfig.scriptpubkey_address;
    this.value = outputConfig.value;
  }

  serialize() {
    return Serializer.serializeOutput(this);
  }
}
