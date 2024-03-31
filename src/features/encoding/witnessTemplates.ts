// const p2wpkhTemplate = (pubkey: string) => `1976a914${pubkey}88ac`;
export const TEMPLATES = {
  P2WPKH: (pubkeyhash: string) => `1976a914${pubkeyhash}88ac`,
};
