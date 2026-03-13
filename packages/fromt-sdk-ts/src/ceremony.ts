import {
  fromt_spend_preprocess,
  fromt_spend_sign,
  fromt_spend_complete,
  fromt_build_signable_tx,
  fromt_handle_free,
} from "./wasm.js";

export const spend = {
  preprocess: fromt_spend_preprocess,
  sign: fromt_spend_sign,
  complete: fromt_spend_complete,
  buildSignableTx: fromt_build_signable_tx,
};

export { fromt_handle_free as freeHandle };
