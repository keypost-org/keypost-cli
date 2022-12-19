use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::io::{Error, ErrorKind};
use std::process::exit;

mod account;
mod crypto;
mod http;
mod locker;
mod models;
mod util;

const ERROR_EXIT_CODE: i32 = 1;

const MENU: &str = "
Choose an option:
1) Register a user
2) Login as a user
3) Put a key
4) Get a key
";

fn init() {
    util::create_default_directory().expect("Cannot create default directory!");
}

fn main() -> Result<(), Error> {
    init();
    //TODO Check for --interactive flag and choose correct run function (needs run_commands() fn).
    run_interactive()
}

fn run_interactive() -> Result<(), Error> {
    let mut rl = rustyline::Editor::<()>::new();
    loop {
        print_menu();
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                match line.as_ref() {
                    "1" => {
                        // TODO Provided by server once user has paid account.
                        let _registration_key = get_string("Registration Key", &mut rl, false);
                        let email = get_string("Email", &mut rl, false);
                        let password = get_string("Password", &mut rl, true);
                        // TODO password length validation
                        let response = account::registration(email.clone(), password)
                            .unwrap_or_else(|err| err);
                        print_response(&response);
                        continue;
                    }
                    "2" => {
                        //TODO Check for login session key before asking for email and password.
                        let email = get_string("Email", &mut rl, false);
                        let password = get_string("Password", &mut rl, true);
                        match account::login(email, password) {
                            Ok(()) => print_response("Login success!"),
                            Err(err) => print_response(&format!("Login failed: {}", &err)),
                        }
                    }
                    "3" => {
                        //TODO Check for login session key before asking for email and password.
                        let email = get_string("Email", &mut rl, false);
                        let locker_id = get_string("Name", &mut rl, false);
                        let message = get_string("Secret", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        let response =
                            locker::register_locker(&locker_id, &email, &export_key, message)
                                .unwrap_or_else(|err| err);
                        println!("\n{}", response);
                        print_response(&response);
                        continue;
                    }
                    "4" => {
                        //TODO Check for login session key before asking for email and password.
                        let email = get_string("Email", &mut rl, false);
                        let locker_id = get_string("Name", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        let response = locker::open_locker(&locker_id, &email, &export_key)
                            .unwrap_or_else(|err| err);
                        print_response(&response);
                        continue;
                    }
                    //TODO Give option '5' to delete a key.
                    //TODO Give option '6' to export all secrets to a file.
                    _ => {
                        let err = Error::new(
                            ErrorKind::Other,
                            "Invalid option (either specify 1, 2, 3 or 4)",
                        );
                        handle_error(ReadlineError::Io(err));
                    }
                }
            }
            Err(err) => {
                handle_error(err);
                exit(ERROR_EXIT_CODE)
            }
        }
    }
}

fn print_response(r: &str) {
    println!("{}", r);
}

fn print_menu() {
    println!("{}", MENU);
}

fn get_string(s1: &str, rl: &mut Editor<()>, obfuscate: bool) -> String {
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
            exit(ERROR_EXIT_CODE)
        }
    }
}

fn handle_error(err: ReadlineError) {
    match err {
        ReadlineError::Interrupted => {
            println!("CTRL-C");
        }
        ReadlineError::Eof => {
            println!("CTRL-D");
        }
        err => {
            println!("Error: {:?}", err);
        }
    }
}
