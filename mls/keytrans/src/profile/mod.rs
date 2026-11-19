// SPDX-License-Identifier: MIT
//! The Peachy profile of the draft: what the labels are, what their values
//! hold, and the device set.
//!
//! The draft treats labels and values as opaque bytes. Everything that gives
//! them meaning for Peachy is here, so the draft's machinery (the rest of the
//! crate) never depends on it.
//!

pub mod device_set;
pub mod labels;
pub mod params;
pub mod values;

pub use device_set::{DeviceEntry, DeviceInclusion, DeviceSet};
pub use labels::Label;
pub use values::{AccountValue, AuditorInstance, MappingValue};
