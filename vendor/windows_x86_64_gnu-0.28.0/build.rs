fn main() {
    if std::env::var("TARGET").unwrap() != "x86_64-pc-windows-gnu" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
