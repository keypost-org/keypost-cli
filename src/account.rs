use sha2::Digest;
use sha2::Sha256;

use crate::crypto;
use crate::http;
use crate::models::*;
use crate::util;

pub fn login(client_email: String, client_password: String) -> Result<(), String> {
    let (session_key, export_key) = execute_login_exchange(&client_email, &client_password)?;
    // store the session and export keys (https://github.com/novifinancial/opaque-ke/blob/94fd3598d0bb8ae5747264112937e988f741ccbb/src/lib.rs#L620-L641)
    util::write_to_secure_file("export_key.private", &export_key, true)
        .map_err(|err| format!("Could not write export_key to file: {:?}", err))?;
    util::write_to_secure_file("session_key.private", &session_key, true)
        .map_err(|err| format!("Could not write session_key to file: {:?}", err))?;
    Ok(())
}

pub fn registration(
    _registration_key: String,
    client_email: String,
    client_password: String,
) -> Result<String, String> {
    // TODO registration_key provided by server once user has paid account.
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
) -> Result<RegisterResponse, String> {
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
        &base64::encode(registration_request_bytes),
        &pkce_code_challenge,
    )
    .map_err(|_e| String::from("Error getting response from register/start"))?;

    let (client_message_bytes, client_export_key) = crypto::opaque::register_finish(
        &mut client_rng,
        client_password,
        client_registration_start_result,
        &server_response.o,
    )
    .map_err(|err| format!("account register finish error: {:?}", err))?;
    util::write_to_secure_file("export_key.private", &client_export_key, true)
        .map_err(|_| "Could not write export_key to file!")?;

    let server_response: RegisterResponse = http::register_finish(
        "http://localhost:8000/register/finish",
        server_response.id,
        &client_email,
        &base64::encode(client_message_bytes),
        &pkce_code_verify_b64,
    )
    .map_err(|err| format!("http register finish error: {:?}", err))?;
    Ok(server_response)
}

fn execute_login_exchange(
    client_email: &str,
    client_password: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let client_login_start_result = crypto::opaque::login_start(client_password)
        .map_err(|err| format!("account login start error: {:?}", err))?;
    let credential_request_bytes = client_login_start_result.message.serialize();

    // Client sends credential_request_bytes to server
    let credential_response =
        http::login_start(client_email, &base64::encode(credential_request_bytes))
            .map_err(|err| format!("Failed login_start: {:?}", err))?;
    let credential_response_bytes =
        base64::decode(&credential_response.o).map_err(|_| "Could not decode base64 str")?;

    let (credential_finalization_bytes, client_session_key, client_export_key) =
        crypto::opaque::login_finish(
            client_password.to_string(),
            client_login_start_result,
            &credential_response_bytes,
        )
        .map_err(|err| format!("account login finish error: {:?}", err))?;
    let credential_finalization_str = base64::encode(credential_finalization_bytes);

    // Client sends credential_finalization_bytes to server
    let login_response = http::login_finish(
        credential_response.id,
        client_email,
        &credential_finalization_str,
    )
    .map_err(|err| format!("Could not get a LoginResponse: {:?}", err))?;

    match execute_login_verify(login_response, &client_session_key, client_email) {
        Ok(()) => Ok((client_session_key, client_export_key)),
        Err(err) => Err(err),
    }
}

fn execute_login_verify(
    response: LoginResponse,
    client_session_key: &[u8],
    email: &str,
) -> Result<(), String> {
    match response.o.as_str() {
        "Failed" => Err("login_finish error".to_string()),
        rand_challenge => {
            let rand_bytes = base64::decode(rand_challenge)
                .map_err(|_| "Could not base64 decode rand_challenge")?;
            let nonce = crypto::expand_u32_nonce(&response.id);
            let ciphertext = &crypto::encrypt_bytes(&nonce, client_session_key, &rand_bytes);
            let hash_bytes = Sha256::digest(ciphertext);
            let hash = base64::encode(hash_bytes);
            let server_response = http::login_verify(response.id, &hash)
                .map_err(|err| format!("Error during login_verify request: {:?}", err))?;
            let session_id = crypto::encrypt_bytes_with_u32_nonce(
                &response.id,
                client_session_key,
                &[response.id.to_be_bytes()].concat(),
            );
            util::write_session_file(&session_id, email)
                .map_err(|err| format!("Could not write session_id to file: {:?}", err))?;
            match server_response.o.as_str() {
                "Success" => Ok(()),
                _ => Err("login_verify error".to_string()),
            }
        }
    }
}
