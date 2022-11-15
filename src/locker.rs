use crate::crypto;
use crate::http;

// Password-based registration and encryption of client secret message between a client and server
pub fn register_locker(
    locker_id: &str,
    email: &str,
    password: String,
    secret_message: String,
) -> Result<String, String> {
    let mut client_rng = crypto::opaque::rng();
    let client_registration_start_result =
        crypto::register_locker_start(&mut client_rng, &password)
            .map_err(|err| format!("Error with crypto::register_locker_start: {:?}", err))?;
    let registration_request_bytes = client_registration_start_result
        .message
        .serialize()
        .to_vec();

    // Client sends registration_request_bytes to server
    let registration_response = http::register_locker_start(
        locker_id,
        email,
        &base64::encode(registration_request_bytes),
    )
    .map_err(|err| format!("Error with http::register_locker_start: {:?}", err))?;
    let registration_response_bytes =
        base64::decode(&registration_response.o).expect("Could not decode base64 str");

    // Server sends registration_response_bytes to client
    let client_finish_registration_result = crypto::opaque::register_locker_finish(
        &mut client_rng,
        client_registration_start_result,
        &registration_response_bytes,
        &password,
    )
    .map_err(|err| {
        format!(
            "Error with ClientRegistrationStartResult finish state: {:?}",
            err
        )
    })?;
    let message_bytes = client_finish_registration_result.message.serialize();

    // Client encrypts secret message using export key
    let ciphertext = crypto::encrypt_locker(
        &client_finish_registration_result.export_key,
        secret_message.as_bytes(),
    );

    let response = http::register_locker_finish(
        locker_id,
        email,
        &base64::encode(&message_bytes),
        &base64::encode(&ciphertext),
    );

    if response.is_err() {
        return Err(format!("Error registering locker: {:?}", response.err()));
    }

    Ok(response.unwrap().o)
}

// Open the contents of a locker with a password between a client and server
pub fn open_locker(locker_id: &str, email: &str, password: String) -> Result<String, String> {
    let mut client_rng = crypto::opaque::rng();
    let client_login_start_result =
        crypto::opaque::open_locker_start(&mut client_rng, password.as_bytes())
            .map_err(|err| format!("Error in opaque::open_locker_start: {:?}", err))?;
    let credential_request_bytes = client_login_start_result.message.serialize().to_vec();

    // Client sends credential_request_bytes to server

    let credential_response =
        http::open_locker_start(locker_id, email, &base64::encode(credential_request_bytes))
            .map_err(|err| format!("Error in http::open_locker_start: {:?}", err))?;
    let nonce: u32 = credential_response.n;

    // Server sends credential_response_bytes to client

    let result = crypto::opaque::open_locker_finish(
        client_login_start_result,
        password.as_bytes(),
        &base64::decode(credential_response.o).expect("Could not base64 decode!"),
    );
    if result.is_err() {
        return Err(String::from("Incorrect password, please try again."));
    }
    let client_login_finish_result = result.unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();

    // Client sends credential_finalization_bytes to server

    let encrypted_locker_contents = http::open_locker_finish(
        locker_id,
        email,
        &base64::encode(credential_finalization_bytes),
        nonce,
    )
    .map_err(|err| format!("Error in http::open_locker_finish: {:?}", err))?;

    // Client decrypts contents of locker, first under the session key, and then
    let plaintext = crypto::decrypt_locker(
        &client_login_finish_result.export_key,
        &crypto::decrypt_locker(
            &client_login_finish_result.session_key,
            &base64::decode(encrypted_locker_contents.o).expect("Could not base64 decode!"),
        ),
    );
    String::from_utf8(plaintext).map_err(|_| String::from("UTF8 error"))
}
