// use curve25519_dalek::ristretto::RistrettoPoint;
use opaque_ke::{
    ciphersuite::CipherSuite, errors::ProtocolError, rand::rngs::OsRng, ClientLogin,
    ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
    ClientRegistrationStartResult, CredentialResponse, Identifiers, RegistrationResponse,
};

// The CipherSuite trait allows to specify the underlying primitives
// that will be used in the OPAQUE protocol
pub struct DefaultCipherSuite;

#[cfg(feature = "ristretto255")]
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

#[cfg(not(feature = "ristretto255"))]
impl CipherSuite for DefaultCipherSuite {
    type OprfCs = p256::NistP256;
    type KeGroup = p256::NistP256;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

pub fn rng() -> OsRng {
    OsRng
}

pub fn login_start(
    client_password: &str,
) -> Result<ClientLoginStartResult<DefaultCipherSuite>, ProtocolError> {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<DefaultCipherSuite>::start(&mut client_rng, client_password.as_bytes())?;
    Ok(client_login_start_result)
}

/// Server sends credential_response_bytes to client
pub fn login_finish(
    password: String,
    client_login_start_result: ClientLoginStartResult<DefaultCipherSuite>,
    credential_response: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ProtocolError> {
    let client_login_finish_result = client_login_start_result.state.finish(
        password.as_bytes(),
        CredentialResponse::deserialize(credential_response).unwrap(),
        ClientLoginFinishParameters::new(
            None,
            Identifiers {
                client: None,
                server: None,
            },
            None,
        ),
    )?;
    let export_key = client_login_finish_result.export_key.to_vec();
    Ok((
        client_login_finish_result.message.serialize().to_vec(),
        client_login_finish_result.session_key.to_vec(),
        export_key,
    ))
}

pub fn register_start(
    rng: &mut OsRng,
    password: String,
) -> ClientRegistrationStartResult<DefaultCipherSuite> {
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(rng, password.as_bytes()).unwrap();
    client_registration_start_result
}

pub fn register_finish(
    client_rng: &mut OsRng,
    password: String,
    client_registration_start_result: ClientRegistrationStartResult<DefaultCipherSuite>,
    registration_response_base64: &str,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let registration_response_bytes =
        base64::decode(registration_response_base64).expect("Could not perform base64 decode");
    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&registration_response_bytes[..]).unwrap(),
            ClientRegistrationFinishParameters::new(
                Identifiers {
                    client: None,
                    server: None,
                },
                None,
            ),
        )
        .unwrap();
    let client_message_bytes = client_finish_registration_result
        .message
        .serialize()
        .to_vec();
    let export_key = client_finish_registration_result.export_key.to_vec();
    Ok((client_message_bytes, export_key))
}

pub fn register_locker_start(
    rng: &mut OsRng,
    password: &str,
) -> Result<ClientRegistrationStartResult<DefaultCipherSuite>, ProtocolError> {
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(rng, password.as_bytes())?;
    Ok(client_registration_start_result)
}

pub fn register_locker_finish(
    rng: &mut OsRng,
    client_registration_start_result: ClientRegistrationStartResult<DefaultCipherSuite>,
    registration_response_bytes: &[u8],
    password: &str,
) -> Result<ClientRegistrationFinishResult<DefaultCipherSuite>, ProtocolError> {
    client_registration_start_result.state.finish(
        rng,
        password.as_bytes(),
        RegistrationResponse::deserialize(registration_response_bytes).unwrap(),
        ClientRegistrationFinishParameters::default(),
    )
}

pub fn open_locker_start(
    rng: &mut OsRng,
    password_bytes: &[u8],
) -> Result<ClientLoginStartResult<DefaultCipherSuite>, ProtocolError> {
    let client_login_start_result = ClientLogin::<DefaultCipherSuite>::start(rng, password_bytes)?;
    Ok(client_login_start_result)
}

pub fn open_locker_finish(
    client_login_start_result: ClientLoginStartResult<DefaultCipherSuite>,
    password_bytes: &[u8],
    credential_response: &[u8],
) -> Result<ClientLoginFinishResult<DefaultCipherSuite>, ProtocolError> {
    let client_login_finish_result: ClientLoginFinishResult<DefaultCipherSuite> =
        client_login_start_result.state.finish(
            password_bytes,
            CredentialResponse::deserialize(credential_response)
                .expect("Could not deserialize credential_response"),
            ClientLoginFinishParameters::default(),
        )?;
    Ok(client_login_finish_result)
}
