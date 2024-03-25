export const compactSize = (num: bigint) => {
  if (+num.toString() < 0xfd) {
    const buf = Buffer.alloc(1);
    buf.writeUintLE(+num.toString(), 0, 1);
    return buf;
  } else if (+num.toString() <= 0xffff) {
    const buf = Buffer.alloc(3);
    buf.writeUint16LE(0xfd, 0);
    buf.writeUint16LE(+num.toString(), 1);
    return buf;
  } else if (+num.toString() <= 0xffffffff) {
    const buf = Buffer.alloc(5);
    buf.writeUInt16LE(0xfe, 0);
    buf.writeUint32LE(+num.toString(), 1);
    return buf;
  } else {
    const buf = Buffer.alloc(9);
    buf.writeUInt16LE(0xff, 0);
    buf.writeBigUInt64LE(num, 1);
    return buf;
  }
};
