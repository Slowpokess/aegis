use std::io::{self, Read};

#[tokio::main]
async fn main() {
    let mut input = Vec::new();
    if let Err(error) = io::stdin().read_to_end(&mut input) {
        eprintln!("failed to read executor stdin: {error}");
        std::process::exit(2);
    }

    let response = aegis_executor::process_input(&input).await;
    match serde_json::to_string(&response) {
        Ok(serialized) => println!("{serialized}"),
        Err(error) => {
            eprintln!("failed to serialize executor response: {error}");
            std::process::exit(3);
        }
    }
}
