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
3) Get a key
4) Put a key
5) Delete a key
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
                        //TODO Check for login session key before asking for email.
                        let email = get_email(&mut rl);
                        let key_name = get_string("Name", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        let session_id: String = util::read_base64_file_path("session_id.public")
                            .expect("Error reading session_id");
                        match get_key(&email, &key_name, &export_key, &session_id) {
                            Ok(response) => print_response(&response),
                            Err(error) => {
                                if &error == "unauthorized" {
                                    print_response(
                                        "Your session may have expired. Please login again:",
                                    );
                                    execute_login_cmd(&mut rl);
                                } else {
                                    print_response(&error);
                                }
                            }
                        }
                    }
                    "4" => {
                        //TODO Check for login session key before asking for email.
                        let email = get_email(&mut rl);
                        let key_name = get_string("Name", &mut rl, false);
                        let message = get_string("Secret", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        let session_id: String = util::read_base64_file_path("session_id.public")
                            .expect("Error reading session_id");
                        let response =
                            put_key(&email, &key_name, &export_key, message, &session_id);
                        print_response(&response);
                    }
                    "5" => {
                        //TODO Check for login session key before asking for email.
                        let email = get_email(&mut rl);
                        let key_name = get_string("Name", &mut rl, false);
                        let export_key = util::read_file("export_key.private", true)
                            .expect("Error reading export_key");
                        let session_id: String = util::read_base64_file_path("session_id.public")
                            .expect("Error reading session_id");
                        let response = delete_key(&email, &key_name, &export_key, &session_id);
                        print_response(&response);
                    }
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

fn put_key(
    email: &str,
    key_name: &str,
    export_key: &[u8],
    secret_message: String,
    session_id: &str,
) -> String {
    locker::register_locker(key_name, email, export_key, secret_message, session_id)
        .unwrap_or_else(|err| err)
}

fn get_key(
    email: &str,
    key_name: &str,
    export_key: &[u8],
    session_id: &str,
) -> Result<String, String> {
    locker::open_locker(key_name, email, export_key, session_id)
}

fn delete_key(email: &str, key_name: &str, export_key: &[u8], session_id: &str) -> String {
    locker::delete_locker(key_name, email, export_key, session_id).unwrap_or_else(|err| err)
}

fn print_response(r: &str) {
    println!("{}", r);
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
