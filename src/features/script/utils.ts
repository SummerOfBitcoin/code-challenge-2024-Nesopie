import { StringMappingType } from "typescript";

export const getNextNBytes = (str: string, n: number): [string, string] => {
  return [str.slice(0, n * 2), str.slice(n * 2)]; //2 hex chars per byte
};

export const parseHex = (str: string) => {
  return parseInt(str, 10);
};

export const parseNumber = (number: string) => {
  //reverse the number as it is in little endian format
  return parseInt(
    number
      .match(/.{1,2}/g)!
      .reverse()
      .join(""),
    16
  );
};

export const encodeNumber = (num: number) => {
  //reverse the number as it should be in little endian format
  return num
    .toString(16)
    .match(/.{1,2}/g)!
    .reverse()
    .join("");
};
