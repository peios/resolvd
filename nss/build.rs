//! Bake the SONAME glibc looks for: `libnss_peios_net.so.2`, where the 2 is
//! the NSS interface version. See authd/nss/build.rs for why a cdylib nobody
//! links against still needs one (ldconfig skips SONAME-less libraries).
fn main() {
    println!("cargo::rustc-link-arg=-Wl,-soname,libnss_peios_net.so.2");
    println!("cargo::rerun-if-changed=build.rs");
}
