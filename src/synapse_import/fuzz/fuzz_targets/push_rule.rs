#![no_main]

use libfuzzer_sys::fuzz_target;
use tuwunel_synapse_import::fuzz;

fuzz_target!(|data: &[u8]| fuzz::push_rule(data));
