import {
  frobt_sign_commit,
  frobt_sign_create_package,
  frobt_sign,
  frobt_sign_aggregate,
  frobt_verify_signature,
  frobt_sign_taproot,
  frobt_sign_aggregate_taproot,
  frobt_verify_taproot_signature,
  frobt_compute_sighash,
  frobt_attach_witness,
  frobt_compute_taproot_output_key,
  frobt_handle_free,
} from "./wasm.js";

export const sign = {
  commit: frobt_sign_commit,
  createPackage: frobt_sign_create_package,
  sign: frobt_sign,
  aggregate: frobt_sign_aggregate,
  verify: frobt_verify_signature,
};

export const signTaproot = {
  sign: frobt_sign_taproot,
  aggregate: frobt_sign_aggregate_taproot,
  verify: frobt_verify_taproot_signature,
};

export const tx = {
  computeSighash: frobt_compute_sighash,
  attachWitness: frobt_attach_witness,
  computeTaprootOutputKey: frobt_compute_taproot_output_key,
};

export { frobt_handle_free as freeHandle };
