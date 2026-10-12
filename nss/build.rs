//! Bake the SONAME glibc looks for: `libnss_peios_net.so.2`, where the 2 is
//! the NSS interface version. See authd/nss/build.rs for why a cdylib nobody
//! links against still needs one (ldconfig skips SONAME-less libraries).
fn main() {
    println!("cargo::rustc-link-arg=-Wl,-soname,libnss_peios_net.so.2");
    // std retains backtrace/unwind references even with panic=abort. Resolve
    // those inside this module rather than adding libgcc_s to every NSS caller.
    // Whole-archive also works with GNU ld when std's objects follow this
    // archive; rustc's cdylib export map keeps the runtime symbols private.
    println!("cargo::rustc-link-lib=static:+whole-archive=gcc_eh");
    println!("cargo::rerun-if-changed=build.rs");
}
