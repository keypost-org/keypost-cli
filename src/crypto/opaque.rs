use std::io::ErrorKind;

use opaque_ke::{
    ciphersuite::CipherSuite, errors::ProtocolError, rand::rngs::OsRng, ClientLogin,
    ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
    ClientRegistrationStartResult, CredentialResponse, Identifiers, RegistrationResponse,
};

use crate::util;

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
        CredentialResponse::deserialize(credential_response)?,
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
    let current_server_static_public_key: Vec<u8> =
        client_login_finish_result.server_s_pk.serialize().to_vec();
    match util::read_file("server.public", true) {
        Ok(registered_server_static_public_key) => {
            if current_server_static_public_key == registered_server_static_public_key {
                Ok((
                    client_login_finish_result.message.serialize().to_vec(),
                    client_login_finish_result.session_key.to_vec(),
                    export_key,
                ))
            } else {
                println!("server public key doesn't match, possible man-in-the-middle attack!");
                Err(ProtocolError::InvalidLoginError)
            }
        }
        Err(err) => {
            if err.kind() == ErrorKind::NotFound {
                util::write_to_secure_file(
                    "server.public",
                    &current_server_static_public_key,
                    true,
                )
                .expect("Could not write server public key to file");
                Ok((
                    client_login_finish_result.message.serialize().to_vec(),
                    client_login_finish_result.session_key.to_vec(),
                    export_key,
                ))
            } else {
                Err(ProtocolError::InvalidLoginError)
            }
        }
    }
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
    let client_registration_finish_result = client_registration_start_result
        .state
        .finish(
            client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&registration_response_bytes[..])
                .expect("Could not deserialize RegistrationResponse"),
            ClientRegistrationFinishParameters::new(
                Identifiers {
                    client: None,
                    server: None,
                },
                None,
            ),
        )
        .expect("An error occured during ClientRegistrationFinishResult");
    let client_message_bytes = client_registration_finish_result
        .message
        .serialize()
        .to_vec();
    let export_key = client_registration_finish_result.export_key.to_vec();
    let server_static_public_key = client_registration_finish_result.server_s_pk.serialize();
    util::write_to_secure_file("server.public", &server_static_public_key, true)
        .expect("Could not write server public key to file");
    Ok((client_message_bytes, export_key))
}

pub fn register_locker_start(
    rng: &mut OsRng,
    key: &[u8],
) -> Result<ClientRegistrationStartResult<DefaultCipherSuite>, ProtocolError> {
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(rng, key)?;
    Ok(client_registration_start_result)
}

pub fn register_locker_finish(
    rng: &mut OsRng,
    client_registration_start_result: ClientRegistrationStartResult<DefaultCipherSuite>,
    registration_response_bytes: &[u8],
    key: &[u8],
) -> Result<ClientRegistrationFinishResult<DefaultCipherSuite>, ProtocolError> {
    client_registration_start_result.state.finish(
        rng,
        key,
        RegistrationResponse::deserialize(registration_response_bytes).unwrap(),
        ClientRegistrationFinishParameters::default(),
    )
}

pub fn open_locker_start(
    rng: &mut OsRng,
    key: &[u8],
) -> Result<ClientLoginStartResult<DefaultCipherSuite>, ProtocolError> {
    let client_login_start_result = ClientLogin::<DefaultCipherSuite>::start(rng, key)?;
    Ok(client_login_start_result)
}

pub fn open_locker_finish(
    client_login_start_result: ClientLoginStartResult<DefaultCipherSuite>,
    key: &[u8],
    credential_response: &[u8],
) -> Result<ClientLoginFinishResult<DefaultCipherSuite>, ProtocolError> {
    let client_login_finish_result: ClientLoginFinishResult<DefaultCipherSuite> =
        client_login_start_result.state.finish(
            key,
            CredentialResponse::deserialize(credential_response)
                .expect("Could not deserialize credential_response"),
            ClientLoginFinishParameters::default(),
        )?;
    Ok(client_login_finish_result)
}
