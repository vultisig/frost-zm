use reddsa::frost::redpallas::PallasBlake2b512;

type Scalar = frost_core::Scalar<PallasBlake2b512>;

pub fn zeroize_scalar(s: &mut Scalar) {
    unsafe {
        let ptr = s as *mut Scalar as *mut u8;
        let len = std::mem::size_of::<Scalar>();
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
}

pub fn zeroize_scalar_vec(v: &mut Vec<Scalar>) {
    for s in v.iter_mut() {
        zeroize_scalar(s);
    }
}
