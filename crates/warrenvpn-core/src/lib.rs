//! Transport-agnostic privileged logic for the WarrenVPN daemon.
//!
//! These modules contain the parts of the daemon that can — and must — be tested
//! without any async runtime, D-Bus, systemd or a real OpenVPN process:
//!
//! * [`management`] — parse OpenVPN management-interface lines.
//! * [`openvpn`] — build the OpenVPN argument vector.
//! * [`store`] — the root-owned configuration shadow store (the highest-risk
//!   component) with server-side safe/unsafe classification.
//! * [`util`] — small dependency-free helpers.
//!
//! The `warrenvpnd` binary wires these into a zbus system-bus service.

pub mod dns;
pub mod killswitch;
pub mod management;
pub mod openvpn;
pub mod store;
pub mod util;
