mod common;
mod frozt_vectors;
mod fromt_vectors;
mod frobt_vectors;
mod froeth_vectors;

use std::path::Path;

fn main() {
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-data");

    std::fs::create_dir_all(&out_dir).expect("failed to create test-data directory");

    println!("=== Generating FROZT (Zcash Sapling) test vectors ===");
    let frozt = frozt_vectors::generate();
    let frozt_json = serde_json::to_string_pretty(&frozt).unwrap();
    std::fs::write(out_dir.join("frozt-vectors.json"), &frozt_json).unwrap();
    println!("  -> wrote frozt-vectors.json");

    println!("=== Generating FROMT (Monero) test vectors ===");
    let fromt = fromt_vectors::generate();
    let fromt_json = serde_json::to_string_pretty(&fromt).unwrap();
    std::fs::write(out_dir.join("fromt-vectors.json"), &fromt_json).unwrap();
    println!("  -> wrote fromt-vectors.json");

    println!("=== Generating FROBT (Bitcoin) test vectors ===");
    let frobt = frobt_vectors::generate();
    let frobt_json = serde_json::to_string_pretty(&frobt).unwrap();
    std::fs::write(out_dir.join("frobt-vectors.json"), &frobt_json).unwrap();
    println!("  -> wrote frobt-vectors.json");

    println!("=== Generating FROETH (Ethereum) test vectors ===");
    let froeth = froeth_vectors::generate();
    let froeth_json = serde_json::to_string_pretty(&froeth).unwrap();
    std::fs::write(out_dir.join("froeth-vectors.json"), &froeth_json).unwrap();
    println!("  -> wrote froeth-vectors.json");

    println!("\nAll test vectors generated successfully in {:?}", out_dir);
}
