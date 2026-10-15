#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    krb5::fuzz::pkinit::input(data);
});
