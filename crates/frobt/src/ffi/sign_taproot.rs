use frost_core::SigningPackage;

use frosty::bytes::*;
use frosty::errors::*;
use frosty::handle::Handle;
use frosty::ceremony::dkg::ser_err;
use frosty::ceremony::sign::SignNonces;

use crate::S;
use crate::Bundle;

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_taproot(
    signing_package: Option<&go_slice>,
    nonces: Handle,
    key_share: Option<&go_slice>,
    merkle_root: Option<&go_slice>,
    out_share: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let mr = merkle_root.map(|s| s.as_slice());
        let nonces_obj = nonces.take::<SignNonces<S>>()?;

        let sp_parsed = SigningPackage::<S>::deserialize(sp.as_slice()).map_err(ser_err)?;
        let bundle = Bundle::deserialize(ks.as_slice())?;

        let tweaked_kp = crate::taproot::tweak_key_package(bundle.key_package, mr)?;

        let share_bytes = frost_ceremony::sign::sign::<S>(&sp_parsed, &nonces_obj.nonces, &tweaked_kp)?;

        *out = tss_buffer::from_vec(share_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_sign_aggregate_taproot(
    signing_package: Option<&go_slice>,
    shares_map: Option<&go_slice>,
    key_share: Option<&go_slice>,
    merkle_root: Option<&go_slice>,
    out_signature: Option<&mut tss_buffer>,
) -> lib_error {
    with_error_handler(|| {
        let sp = signing_package.ok_or(lib_error::LIB_NULL_PTR)?;
        let sm = shares_map.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;
        let out = out_signature.ok_or(lib_error::LIB_NULL_PTR)?;

        let mr = merkle_root.map(|s| s.as_slice());

        let sp_parsed = SigningPackage::<S>::deserialize(sp.as_slice()).map_err(ser_err)?;
        let bundle = Bundle::deserialize(ks.as_slice())?;

        let tweaked_pkp = crate::taproot::tweak_public_key_package(bundle.pub_key_package, mr)?;

        let sig_bytes = frost_ceremony::sign::sign_aggregate::<S>(&sp_parsed, sm.as_slice(), &tweaked_pkp)?;
        *out = tss_buffer::from_vec(sig_bytes);

        Ok(())
    })
}

#[cfg_attr(not(target_arch = "wasm32"), no_mangle)]
pub extern "C" fn frobt_verify_taproot_signature(
    message: Option<&go_slice>,
    signature: Option<&go_slice>,
    key_share: Option<&go_slice>,
    merkle_root: Option<&go_slice>,
) -> lib_error {
    with_error_handler(|| {
        let msg = message.ok_or(lib_error::LIB_NULL_PTR)?;
        let sig = signature.ok_or(lib_error::LIB_NULL_PTR)?;
        let ks = key_share.ok_or(lib_error::LIB_NULL_PTR)?;

        let mr = merkle_root.map(|s| s.as_slice());

        let bundle = Bundle::deserialize(ks.as_slice())?;
        let sig_parsed = frost_core::Signature::<S>::deserialize(sig.as_slice()).map_err(ser_err)?;

        let tweaked_pkp = crate::taproot::tweak_public_key_package(bundle.pub_key_package, mr)?;

        tweaked_pkp
            .verifying_key()
            .verify(msg.as_slice(), &sig_parsed)
            .map_err(|_| lib_error::LIB_SIGNING_ERROR)
    })
}
