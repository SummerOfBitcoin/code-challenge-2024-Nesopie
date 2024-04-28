import { Transaction } from "../transaction";
import { HashValidator } from "./hash";
import { MetadataValidator } from "./metadata";
import { ScriptValidator } from "./script";
import { signatureValidator } from "./signature";

export class Validator {
  static validate(tx: Transaction) {
    return (
      ScriptValidator(tx) &&
      MetadataValidator(tx) &&
      HashValidator(tx) &&
      signatureValidator(tx)
    );
  }
}
