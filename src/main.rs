use std::io::{Error, ErrorKind};
use std::process::exit;

use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::ciphersuite::CipherSuite;

mod account;
mod http;

// The ciphersuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
struct Default;
impl CipherSuite for Default {
    type Group = RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

fn main() {
    let mut rl = rustyline::Editor::<()>::new();
    loop {
        println!("Enter an option (1 or 2):");
        println!("1) Register a user");
        println!("2) Login as a user\n");
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                if line != "1" && line != "2" {
                    println!("Error: Invalid option (either specify 1 or 2)");
                    continue;
                }
                let email = get_string("Email", &mut rl, false);
                let password = get_string("Password", &mut rl, true);
                match line.as_ref() {
                    "1" => {
                        account::registration(email.clone(), password);
                        continue;
                    }
                    "2" => {
                        if account::login(email, password) {
                            println!("\nLogin success!");
                        } else {
                            // Note that at this point, the client knows whether or not the login
                            // succeeded. In this example, we simply rely on client-reported result
                            // of login, but in a real client-server implementation, the server may not
                            // know the outcome of login yet, and extra care must be taken to ensure
                            // that the server can learn the outcome as well.
                            println!("\nIncorrect password, please try again.");
                        }
                    }
                    _ => exit(0),
                }
            }
            Err(err) => {
                handle_error(err);
                exit(0)
            }
        }
    }
}

fn get_string(s1: &str, rl: &mut rustyline::Editor<()>, obfuscate: bool) -> String {
    let query = s1;
    let readline: Result<String, Error> = match obfuscate {
        false => rl
            .readline(&format!("{}: ", query))
            .map_err(|err| Error::new(ErrorKind::Other, format!("{:?}", err))),
        true => rpassword::read_password_from_tty(Some(&format!("{}: ", query)))
            .map_err(|err| Error::new(ErrorKind::Other, format!("{:?}", err))),
    };
    match readline {
        Ok(line) => line,
        Err(err) => {
            println!("Encountered an error getting user string: {:?}", err);
            exit(0)
        }
    }
}

// Helper functions:
// Handle readline errors
fn handle_error(err: rustyline::error::ReadlineError) {
    match err {
        rustyline::error::ReadlineError::Interrupted => {
            println!("CTRL-C");
        }
        rustyline::error::ReadlineError::Eof => {
            println!("CTRL-D");
        }
        err => {
            println!("Error: {:?}", err);
        }
    }
}
