export enum TransactionType {
  P2PKH = "p2pkh",
  P2SH = "p2sh",
  P2WPKH = "v0_p2wpkh",
  P2WSH = "v0_p2wsh",
  P2TR = "v1_p2tr",
  OP_RETURN = "op_return",
}

export enum SigHash {
  ALL = "01", //all inputs and outputs
  NONE = "02", //all inputs and no output
  SINGLE = "03", //all inputs and output with the same index
  ALL_ANYONECANPAY = "81", //own input and anyone can pay
  NONE_ANYONECANPAY = "82", //own input and no output
  SINGLE_ANYONECANPAY = "83", //own input and output with the same index
}
