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
1) Register
2) Login
3) Get a key
4) Put a key
5) Delete a key
6) Logout
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
                        let registration_key = get_string("Registration Key", &mut rl, false);
                        let (email, password) = get_email_password(&mut rl);
                        let response = account_registration(registration_key, email, password);
                        print_response(&response);
                    }
                    "2" => {
                        execute_login_cmd(&mut rl);
                    }
                    "3" => {
                        //TODO Better way to not use email on server-side? (i.e. server stores email in plaintext)
                        // Maybe custom identifiers (ClientRegistrationFinishParameters):
                        //  https://github.com/facebook/opaque-ke/blob/556f6c2bd43123b20110f0a9bace8c5f91643328/src/lib.rs#L706-L722
                        let key_name = get_string("Name", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        match get_session_file() {
                            Ok((session_id, email)) => {
                                match get_key(&email, &key_name, &export_key, &session_id) {
                                    Ok(response) => print_response(&response),
                                    Err(error) => handle_error_response(&mut rl, error),
                                }
                            }
                            Err(error) => handle_error_response(&mut rl, error),
                        }
                    }
                    "4" => {
                        let key_name = get_string("Name", &mut rl, false);
                        let message = get_string("Secret", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        match get_session_file() {
                            Ok((session_id, email)) => {
                                match put_key(&email, &key_name, &export_key, message, &session_id)
                                {
                                    Ok(response) => print_response(&response),
                                    Err(error) => handle_error_response(&mut rl, error),
                                }
                            }
                            Err(error) => handle_error_response(&mut rl, error),
                        }
                    }
                    "5" => {
                        let key_name = get_string("Name", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        match get_session_file() {
                            Ok((session_id, email)) => {
                                match delete_key(&email, &key_name, &export_key, &session_id) {
                                    Ok(response) => print_response(&response),
                                    Err(error) => handle_error_response(&mut rl, error),
                                }
                            }
                            Err(error) => handle_error_response(&mut rl, error),
                        }
                    }
                    //TODO Give option to export all secrets to a file.
                    "6" => match get_session_file() {
                        Ok((session_id, _email)) => {
                            let _ = util::delete_session_file()
                                .map_err(|_err| "Could not delete session file!".to_string());
                            let response = account_logout(&session_id);
                            print_response(&response);
                        }
                        Err(_error) => {
                            print_response("Session file not found, you're no longer logged in.")
                        }
                    },
                    _ => {
                        let err = Error::new(
                            ErrorKind::Other,
                            "Invalid option (specify a number between 1-6)",
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

fn execute_login_cmd(rl: &mut Editor<()>) {
    let (email, password) = get_email_password(rl);
    let response = account_login(email, password);
    print_response(&response);
}

fn account_registration(registration_key: String, email: String, password: String) -> String {
    account::registration(registration_key, email, password).unwrap_or_else(|err| err)
}

fn account_login(email: String, password: String) -> String {
    match account::login(email, password) {
        Ok(()) => "Login success!".to_string(),
        Err(err) => format!("Login failed: {}", &err),
    }
}

fn account_logout(session_id: &str) -> String {
    match account::logout(session_id) {
        Ok(response) => response,
        Err(err) => format!("Logout failed: {}", &err),
    }
}

fn get_session_file() -> Result<(String, String), String> {
    match util::read_session_file() {
        Ok(response) => Ok(response),
        Err(_err) => Err("no_session".to_string()),
    }
}

fn put_key(
    email: &str,
    key_name: &str,
    export_key: &[u8],
    secret_message: String,
    session_id: &str,
) -> Result<String, String> {
    locker::register_locker(key_name, email, export_key, secret_message, session_id)
}

fn get_key(
    email: &str,
    key_name: &str,
    export_key: &[u8],
    session_id: &str,
) -> Result<String, String> {
    locker::open_locker(key_name, email, export_key, session_id)
}

fn delete_key(
    email: &str,
    key_name: &str,
    export_key: &[u8],
    session_id: &str,
) -> Result<String, String> {
    locker::delete_locker(key_name, email, export_key, session_id)
}

fn print_response(r: &str) {
    println!("{}", r);
}

fn handle_error_response(rl: &mut Editor<()>, error: String) {
    if &error == "unauthorized" {
        print_response("Your session may have expired. Please login again:");
        execute_login_cmd(rl);
    } else if &error == "no_session" {
        print_response("No session available. Please login:");
        execute_login_cmd(rl);
    } else {
        print_response(&error);
    }
}

fn print_menu() {
    print_response(MENU);
}

fn get_email_password(rl: &mut Editor<()>) -> (String, String) {
    let email = get_email(rl);
    // TODO password length validation
    let password = get_string("Password", rl, true);
    (email, password)
}

fn get_email(rl: &mut Editor<()>) -> String {
    get_string("Email", rl, false)
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
