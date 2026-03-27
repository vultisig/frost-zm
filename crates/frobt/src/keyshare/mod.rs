pub mod bundle {
    pub type KeyShareBundle = frosty::bundle::KeyShareBundle<crate::S, frosty::bundle::ChainCodeMeta>;

    pub use frosty::bundle::ChainCodeMeta;

}

pub mod identifier {
    pub fn identifier_to_u16(id: &frost_core::Identifier<crate::S>) -> Result<u16, frosty::lib_error> {
        frosty::identifier::identifier_to_u16::<crate::S>(id)
    }
}
