export enum TransactionType {
  P2PKH = "p2pkh",
  P2SH = "p2sh",
  P2WPKH = "v0_p2wpkh",
  P2WSH = "v0_p2wsh",
  P2TR = "v1_p2tr",
  OP_RETURN = "op_return",
}

export enum SigHash {
  ALL = 0x01, //all inputs and outputs
  NONE = 0x02, //all inputs and no output
  SINGLE = 0x03, //all inputs and output with the same index
  ANYONE_CAN_PAY = 0x80,
}
