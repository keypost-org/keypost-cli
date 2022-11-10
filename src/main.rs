use std::io::{Error, ErrorKind};
use std::process::exit;

mod account;
mod crypto;
mod http;
mod util;

fn init() {
    util::create_default_directory().expect("Cannot create default directory!");
}

fn main() {
    let mut rl = rustyline::Editor::<()>::new();
    init();
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
                        let response = account::registration(email.clone(), password);
                        println!("response={:?}", response);
                        continue;
                    }
                    "2" => {
                        match account::login(email, password) {
                            Ok(()) => {
                                println!("\nLogin success!")
                                // Note that at this point, the client knows whether or not the login
                                // succeeded. In this example, we simply rely on client-reported result
                                // of login, but in a real client-server implementation, the server may not
                                // know the outcome of login yet, and extra care must be taken to ensure
                                // that the server can learn the outcome as well.
                            }
                            Err(s) => println!("{}", &s),
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
