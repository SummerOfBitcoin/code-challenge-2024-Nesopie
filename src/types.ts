export type Transaction = {
  txid: string;
  version: number;
  locktime: number;
  vin: Input[];
  vout: Output[];
};

export type Input = {
  txid: string;
  vout: number;
  prevout: Output;
  scriptsig: string;
  scriptsig_asm: string;
  witness: string[];
  is_coinbase: boolean;
  sequence: number;
  inner_redeemscript_asm: string;
};

export type Output = {
  scriptpubkey: string;
  scriptpubkey_asm: string;
  scriptpubkey_type: string;
  scriptpubkey_address: string;
  value: number;
};

export enum TransactionType {
  P2PKH = "p2pkh",
  P2SH = "p2sh",
  P2WPKH = "v0_p2wpkh",
  P2WSH = "v0_p2wsh",
  P2TR = "v1_p2tr",
}
