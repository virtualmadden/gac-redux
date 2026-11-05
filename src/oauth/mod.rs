//! Provider-neutral OAuth pieces: PKCE, the loopback redirect endpoint and RFC 8628 polling.
//! Nothing here knows about AWS.

pub mod device_poll;
pub mod loopback;
pub mod pkce;
