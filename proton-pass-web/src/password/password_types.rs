// Re-export core types with wasm bindings
pub use proton_pass_common::password::{
    PassphraseConfig as WasmPassphraseConfig, PasswordScore as WasmPasswordScore,
    PasswordScoreResult as WasmPasswordScoreResult, RandomPasswordConfig as WasmRandomPasswordConfig,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Tsify, Deserialize, Serialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct WasmPasswordScoreList(pub Vec<WasmPasswordScore>);
