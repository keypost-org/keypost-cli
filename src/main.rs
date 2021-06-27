use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::process::exit;

use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::keypair::KeyPair;
use opaque_ke::ClientRegistrationStartResult;
use opaque_ke::{
    ciphersuite::CipherSuite, rand::rngs::OsRng, ClientRegistration,
    ClientRegistrationFinishParameters, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, ServerRegistration, ServerRegistrationStartResult,
};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginStartParameters, CredentialFinalization,
    CredentialRequest, CredentialResponse, ServerLogin, ServerLoginStartParameters,
};

// The ciphersuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
#[allow(dead_code)]
struct Default;
impl CipherSuite for Default {
    type Group = RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

fn client_side_registration(
    client_rng: &mut OsRng,
    password: String,
) -> ClientRegistrationStartResult<Default> {
    ClientRegistration::<Default>::start(client_rng, password.as_bytes()).unwrap()
}

fn client_side_registration_finish(
    client_rng: &mut OsRng,
    client_registration_start_result: ClientRegistrationStartResult<Default>,
    registration_response_base64: &str,
) -> String {
    let registration_response_bytes =
        base64::decode(registration_response_base64).expect("Could not perform base64 decode");
    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            client_rng,
            RegistrationResponse::deserialize(&registration_response_bytes[..]).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let client_message_bytes = client_finish_registration_result.message.serialize();
    base64::encode(client_message_bytes)
}

fn server_side_registration_start(
    registration_request_base64: &str,
    server_kp: &KeyPair<RistrettoPoint>,
) -> ServerRegistrationStartResult<Default> {
    let registration_request_bytes =
        base64::decode(registration_request_base64).expect("Could not perform base64 decode");
    let server_public_key = server_kp.public();
    let mut server_rng = OsRng;
    ServerRegistration::<Default>::start(
        &mut server_rng,
        RegistrationRequest::deserialize(&registration_request_bytes[..]).unwrap(),
        server_public_key,
    )
    .unwrap()
}

fn server_side_registration_finish(
    client_message_base64: String,
    server_registration_start_result: ServerRegistrationStartResult<Default>,
) -> Vec<u8> {
    let client_message_bytes =
        base64::decode(client_message_base64).expect("Could not perform base64 decode");
    let password_file = server_registration_start_result
        .state
        .finish(RegistrationUpload::deserialize(&client_message_bytes[..]).unwrap())
        .unwrap();
    password_file.serialize()
}

fn account_registration(client_password: String, server_kp: &KeyPair<RistrettoPoint>) -> Vec<u8> {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        client_side_registration(&mut client_rng, client_password);
    let registration_request_bytes = client_registration_start_result.message.serialize();
    let registration_request_base64 = base64::encode(&registration_request_bytes);
    println!(
        "{}",
        CURL_TEMPLATE
            .replace("{{__DATA__}}", &registration_request_base64)
            .replace("{{__URLPATH__}}", "register/start")
    );
    let server_registration_start_result =
        server_side_registration_start(&registration_request_base64, &server_kp);
    let registration_response_bytes = server_registration_start_result.message.serialize();
    let registration_response_base64 = base64::encode(&registration_response_bytes);
    let client_message_base64 = client_side_registration_finish(
        &mut client_rng,
        client_registration_start_result,
        &registration_response_base64,
    );
    server_side_registration_finish(client_message_base64, server_registration_start_result)
    // the password_file
}

static CURL_TEMPLATE: &str = r#"
For sending to server:
curl -X POST --header "Content-Type: application/json" --data '{"data": "{{__DATA__}}"}' http://localhost:8000/{{__URLPATH__}}
"#;

fn main() {
    let mut server_rng = OsRng;
    let server_kp = Default::generate_random_keypair(&mut server_rng);

    let mut rl = rustyline::Editor::<()>::new();
    let mut registered_users = HashMap::<String, Vec<u8>>::new();
    loop {
        println!(
            "\nCurrently registered usernames: {:?}\n",
            registered_users.keys()
        );

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
                let username = get_string("Username", &mut rl, false);
                let password = get_string("Password", &mut rl, true);
                match line.as_ref() {
                    "1" => {
                        let password_file_bytes = account_registration(password, &server_kp);
                        let password_file_base64: String = base64::encode(&password_file_bytes);
                        println!(
                            "{}",
                            CURL_TEMPLATE
                                .replace("{{__DATA__}}", &password_file_base64)
                                .replace("{{__URLPATH__}}", "register/file")
                        );
                        registered_users.insert(username, password_file_bytes);
                        continue;
                    }
                    "2" => match registered_users.get(&username) {
                        Some(password_file_bytes) => {
                            println!("{}", base64::encode(password_file_bytes));
                            if account_login(&server_kp, password, password_file_bytes) {
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
                        None => println!("Error: Could not find username registered"),
                    },
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

// Password-based login between a client and server
fn account_login(
    server_kp: &opaque_ke::keypair::KeyPair<curve25519_dalek::ristretto::RistrettoPoint>,
    client_password: String,
    password_file_bytes: &[u8],
) -> bool {
    let mut client_rng = OsRng;
    let client_login_start_result = ClientLogin::<Default>::start(
        &mut client_rng,
        client_password.as_bytes(),
        ClientLoginStartParameters::default(),
    )
    .unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();

    // Client sends credential_request_bytes to server

    let password_file = ServerRegistration::<Default>::deserialize(password_file_bytes).unwrap();
    let mut server_rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        password_file,
        &server_kp.private(),
        CredentialRequest::deserialize(&credential_request_bytes[..]).unwrap(),
        ServerLoginStartParameters::default(),
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize();

    // Server sends credential_response_bytes to client

    let result = client_login_start_result.state.finish(
        CredentialResponse::deserialize(&credential_response_bytes[..]).unwrap(),
        ClientLoginFinishParameters::default(),
    );

    if result.is_err() {
        // Client-detected login failure
        return false;
    }
    let client_login_finish_result = result.unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();

    // Client sends credential_finalization_bytes to server

    let server_login_finish_result = server_login_start_result
        .state
        .finish(CredentialFinalization::deserialize(&credential_finalization_bytes[..]).unwrap())
        .unwrap();

    client_login_finish_result.session_key == server_login_finish_result.session_key
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
