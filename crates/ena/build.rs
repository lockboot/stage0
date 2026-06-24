// SPDX-License-Identifier: MIT OR Apache-2.0

//! Force the PE subsystem to EFI Boot Service Driver (11) instead of the target's
//! default EFI Application (10). A UEFI *application* is unloaded the moment its
//! entry point returns, which would tear down our DriverBinding; a boot-service
//! driver stays resident. lld-link takes the last `/subsystem`, and this link-arg
//! is emitted after the target's, so it wins. Done here (not .cargo/config.toml) so
//! it travels with the crate regardless of where cargo is invoked.
fn main() {
    println!("cargo::rustc-link-arg-bins=/subsystem:efi_boot_service_driver");
}
