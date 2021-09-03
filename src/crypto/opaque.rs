use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::{
    ciphersuite::CipherSuite, errors::ProtocolError, rand::rngs::OsRng, ClientLogin,
    ClientLoginFinishParameters, ClientLoginStartResult, ClientRegistration,
    ClientRegistrationFinishParameters, ClientRegistrationStartResult, CredentialResponse,
    RegistrationResponse,
};

// The ciphersuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
pub struct Default;
impl CipherSuite for Default {
    type OprfGroup = RistrettoPoint;
    type KeGroup = RistrettoPoint;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDH;
    type Hash = sha2::Sha512;
    type SlowHash = opaque_ke::slow_hash::NoOpHash;
}

pub fn rng() -> OsRng {
    OsRng
}

pub fn login_start(
    client_password: &str,
) -> Result<ClientLoginStartResult<Default>, ProtocolError> {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<Default>::start(&mut client_rng, client_password.as_bytes())?;
    Ok(client_login_start_result)
}

/// Server sends credential_response_bytes to client
pub fn login_finish(
    client_login_start_result: ClientLoginStartResult<Default>,
    credential_response: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let client_login_finish_result = client_login_start_result.state.finish(
        CredentialResponse::deserialize(credential_response).unwrap(),
        ClientLoginFinishParameters::default(),
    )?;
    Ok((
        client_login_finish_result.message.serialize(),
        client_login_finish_result.session_key,
    ))
}

pub fn register_start(rng: &mut OsRng, password: String) -> ClientRegistrationStartResult<Default> {
    let client_registration_start_result =
        ClientRegistration::<Default>::start(rng, password.as_bytes()).unwrap();
    client_registration_start_result
}

pub fn register_finish(
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
