use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::ClientRegistrationStartResult;
use opaque_ke::{
    ciphersuite::CipherSuite, rand::rngs::OsRng, ClientRegistration,
    ClientRegistrationFinishParameters, RegistrationResponse,
};
use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};

use crate::http;

use http::RegisterResponse;

// The ciphersuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
struct Default;
impl CipherSuite for Default {
    type Group = RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

pub fn login(client_email: String, client_password: String) -> bool {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<Default>::start(&mut client_rng, client_password.as_bytes()).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();

    // Client sends credential_request_bytes to server
    let credential_response =
        http::login_start(&client_email, &base64::encode(credential_request_bytes)).unwrap();
    let credential_response_bytes =
        base64::decode(&credential_response.o).expect("Could not decode base64 str");

    // Server sends credential_response_bytes to client

    let result = client_login_start_result.state.finish(
        CredentialResponse::deserialize(&credential_response_bytes[..]).unwrap(),
        ClientLoginFinishParameters::default(),
    );

    if result.is_err() {
        println!("Client-detected login failure");
        return false;
    }
    let client_login_finish_result = result.unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();
    let credential_finalization_str = base64::encode(credential_finalization_bytes);

    // Client sends credential_finalization_bytes to server
    let login_response = http::login_finish(
        credential_response.id,
        &client_email,
        &credential_finalization_str,
    )
    .expect("Could not get a LoginResponse!");
    let server_session_key = login_response.o;

    client_login_finish_result.session_key
        == base64::decode(server_session_key).expect("Could not decode binary session_key")
}

// https://docs.rs/opaque-ke/0.6.0/opaque_ke/#structs
// https://docs.rs/opaque-ke/0.6.0/opaque_ke/struct.ServerRegistrationStartResult.html
// https://docs.rs/opaque-ke/0.6.0/opaque_ke/struct.ServerRegistration.html
pub fn registration(client_email: String, client_password: String) {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        client_side_registration_start(&mut client_rng, client_password);
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

    let client_message_base64 = client_side_registration_finish(
        &mut client_rng,
        client_registration_start_result,
        &server_response.o,
    );

    let server_response: RegisterResponse = http::register_finish(
        "http://localhost:8000/register/finish",
        server_response.id,
        &client_email,
        &client_message_base64,
        &pkce_code_verify_b64,
    )
    .expect("Error getting response from register/finish");
    let response = server_response.o;
    println!("response={:?}", response);
}

fn client_side_registration_start(
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
