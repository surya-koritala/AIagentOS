use kernel::wire_contract::conformance_request_fixtures;

fn main() {
    let version = std::env::args()
        .nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: cargo run -p kernel --example export-wire-fixtures -- <version>");
            std::process::exit(2);
        })
        .parse::<u32>()
        .unwrap_or_else(|error| {
            eprintln!("protocol version must be an integer: {error}");
            std::process::exit(2);
        });
    let fixtures = conformance_request_fixtures(version).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&fixtures).expect("fixtures serialize")
    );
}
