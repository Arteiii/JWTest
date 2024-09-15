use rand::rngs::OsRng;
use rand::RngCore;


fn main() {
    #[cfg(debug_assertions)]
    cargo_force_rebuild();

    cargo_gen_secrets();
}

#[cfg(debug_assertions)]
fn cargo_force_rebuild() {
    use std::fs::File;
    use std::io::Write;
    
    println!("cargo:warning=Forced Rebuild");
    // to force rebuilds
    let mut timestamp_file = File::create("build_timestamp.txt").expect("Failed to create timestamp file");
    writeln!(timestamp_file, "Timestamp: {:?}", std::time::SystemTime::now()).expect("Failed to write to timestamp file");

    println!("cargo:rerun-if-changed=build_timestamp.txt");
}


fn cargo_gen_secrets(){
    let mut key = vec![0u8; 64];
    OsRng.try_fill_bytes(&mut key).expect(
        "Failed to generate secure random bytes. \
        Ensure that the system's entropy source is available and functioning correctly.",
    );

    let secret = hex::encode(key);

    println!("cargo:rustc-env=JWT_SECRET={}", secret);
    println!("cargo:warning=Secret: {}", &secret[..7]);
}