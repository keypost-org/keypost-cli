use crate::crypto;
use crate::http;

use http::RegisterResponse;

pub fn login(client_email: String, client_password: String) -> Result<bool, String> {
    let (client_session_key, server_session_key) =
        execute_login_exchange(&client_email, &client_password)?;
    Ok(client_session_key == server_session_key)
}

pub fn registration(client_email: String, client_password: String) -> Result<String, String> {
    let server_response = execute_registration_exchange(client_email, client_password)
        .map_err(|err| format!("account registration error: {:?}", err))?;
    let response = server_response.o;
    Ok(response)
}

// https://docs.rs/opaque-ke/0.6.0/opaque_ke/#structs
// https://docs.rs/opaque-ke/0.6.0/opaque_ke/struct.ServerRegistrationStartResult.html
// https://docs.rs/opaque-ke/0.6.0/opaque_ke/struct.ServerRegistration.html
fn execute_registration_exchange(
    client_email: String,
    client_password: String,
) -> Result<RegisterResponse, reqwest::Error> {
    let mut client_rng = crypto::opaque::rng();
    let client_registration_start_result =
        crypto::opaque::register_start(&mut client_rng, client_password.clone());
    let registration_request_bytes = client_registration_start_result.message.serialize();

    let pkce_code_verify = pkce::code_verifier(128);
    let pkce_code_verify_b64 = base64::encode(&pkce_code_verify);
    let pkce_code_challenge = pkce::code_challenge(&pkce_code_verify);

    let server_response: RegisterResponse = http::register_start(
        "http://localhost:8000/register/start",
        &client_email,
        &base64::encode(&registration_request_bytes),
        &pkce_code_challenge,
    )
    .expect("Error getting response from register/start");

    let client_message_base64 = crypto::opaque::register_finish(
        &mut client_rng,
        client_password,
        client_registration_start_result,
        &server_response.o,
    );

    let server_response: RegisterResponse = http::register_finish(
        "http://localhost:8000/register/finish",
        server_response.id,
        &client_email,
        &client_message_base64,
        &pkce_code_verify_b64,
    )?;
    Ok(server_response)
}

fn execute_login_exchange(
    client_email: &str,
    client_password: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let client_login_start_result = crypto::opaque::login_start(client_password)
        .map_err(|err| format!("account login error: {:?}", err))?;
    let credential_request_bytes = client_login_start_result.message.serialize();

    // Client sends credential_request_bytes to server
    let credential_response =
        http::login_start(client_email, &base64::encode(credential_request_bytes)).unwrap();
    let credential_response_bytes =
        base64::decode(&credential_response.o).expect("Could not decode base64 str");

    let (credential_finalization_bytes, client_session_key) = crypto::opaque::login_finish(
        client_password.to_string(),
        client_login_start_result,
        &credential_response_bytes,
    )
    .map_err(|err| format!("account login error: {:?}", err))?;
    let credential_finalization_str = base64::encode(credential_finalization_bytes);

    // Client sends credential_finalization_bytes to server
    let login_response = http::login_finish(
        credential_response.id,
        client_email,
        &credential_finalization_str,
    )
    .expect("Could not get a LoginResponse!");
    let server_session_key =
        base64::decode(login_response.o).expect("Could not decode binary session_key");
    Ok((client_session_key, server_session_key))
}
