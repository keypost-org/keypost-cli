use std::io::{Error, ErrorKind};
use std::process::exit;

mod account;
mod crypto;
mod http;
mod locker;
mod models;
mod util;

fn init() {
    util::create_default_directory().expect("Cannot create default directory!");
}

fn main() {
    let mut rl = rustyline::Editor::<()>::new();
    init();
    loop {
        println!("Choose an option:");
        println!("1) Register a user");
        println!("2) Login as a user");
        println!("3) Put a key");
        println!("4) Get a key");
        println!();
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                if !["1", "2", "3", "4"].contains(&line.as_str()) {
                    println!("Error: Invalid option (either specify 1, 2, 3 or 4)");
                    continue;
                }
                let email = get_string("Email", &mut rl, false);
                let password = get_string("Password", &mut rl, true);
                match line.as_ref() {
                    "1" => {
                        let _registration_key = get_string("Registration Key", &mut rl, false); // TODO Provided by server once user has paid account.
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

                                // keypost-cli notes: Implement a challenge similar to PKCE or what `ssh` does with PKI.
                            }
                            Err(s) => println!("{}", &s),
                        }
                    }
                    "3" => {
                        let locker_id = get_string("Name", &mut rl, false);
                        let message = get_string("Secret", &mut rl, false);
                        let response =
                            locker::register_locker(&locker_id, &email, password, message);
                        println!("response={:?}", response);
                        continue;
                    }
                    "4" => {
                        let locker_id = get_string("Name", &mut rl, false);
                        let response = locker::open_locker(&locker_id, &email, password);
                        println!("response={:?}", response);
                        continue;
                    }
                    "5" => {
                        //TODO Give option to export all secrets to a file.
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
