//! Session-based ceremony driver for FROST protocols.
//!
//! Provides setup message serialisation, relay message routing, and
//! an async state machine that drives DKG, resharing, signing, and
//! key import ceremonies via a feed/take message loop.

pub mod message;
pub mod relay;
pub mod session;
pub mod setup;
