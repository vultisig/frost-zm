export interface TaprootAddress {
  address: string;
  network: string;
}

export interface KeyShareInfo {
  publicKey: Uint8Array;
  chainCode: Uint8Array;
  birthday: number;
  network: number;
}
