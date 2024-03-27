export type Tx = {
  version: number;
  locktime: number;
  vin: TxIn[];
  vout: TxOut[];
};

export type TxIn = {
  txid: string;
  vout: number;
  prevout: TxOut | null;
  scriptsig: string;
  scriptsig_asm: string;
  witness?: string[];
  is_coinbase: boolean;
  sequence: number;
  inner_redeemscript_asm?: string;
  inner_witnessscript_asm?: string;
};

export type TxOut = {
  scriptpubkey: string;
  scriptpubkey_asm: string;
  scriptpubkey_type: string;
  scriptpubkey_address?: string; //not required in the case of a coinbase transaction, can be computed later anyways
  value: number;
};
