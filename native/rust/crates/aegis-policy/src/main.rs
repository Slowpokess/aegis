use std::io::{self, Read};

use aegis_policy::{PolicyRequest, evaluate, malformed_response};

fn main() {
    let mut input = Vec::new();
    if io::stdin().read_to_end(&mut input).is_err() {
        emit(&malformed_response(&input));
        return;
    }
    let response = match serde_json::from_slice::<PolicyRequest>(&input) {
        Ok(request) => evaluate(&request),
        Err(_) => malformed_response(&input),
    };
    emit(&response);
}

fn emit(response: &aegis_policy::PolicyResponse) {
    match serde_json::to_string(response) {
        Ok(value) => println!("{value}"),
        Err(error) => eprintln!("policy serialization failure: {error}"),
    }
}
