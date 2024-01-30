mod error;

pub use error::CliError;
use serde::{Deserialize, Serialize};

// TODO Decide whether to use one request struct to simplify and make code reusable.
#[derive(Serialize, Deserialize, Debug)]
pub struct CliRequest {
    pub id: u32,    // id
    pub e: String,  // email
    pub i: String,  // protocol input
    pub ch: String, // PKCE challenge
    pub ci: String, // locker protocol ciphertext
    pub ve: String, // PKCE verifier
    pub n: u32,     // nonce
}

// TODO Decide whether to use one response struct to simplify and make code reusable.
#[derive(Serialize, Deserialize, Debug)]
pub struct CliResponse {
    pub id: u32,   // id
    pub o: String, // protocol output
    pub n: u32,    // nonce
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterStartRequest {
    pub e: String,
    pub i: String,
    pub c: String, // PKCE challenge
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterFinishRequest {
    pub id: u32,
    pub e: String,
    pub i: String,
    pub v: String, // PKCE verifier
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStartRequest {
    pub e: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinishRequest {
    pub id: u32,
    pub e: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginVerifyRequest {
    pub id: u32,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResponse {
    pub id: u32,
    pub o: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginResponse {
    pub id: u32,
    pub o: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterLockerResponse {
    pub id: u32,
    pub o: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterLockerStartRequest {
    pub id: String,
    pub e: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterLockerFinishRequest {
    pub id: String,
    pub e: String,
    pub i: String,
    pub c: String, // locker protocol ciphertext
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenLockerStartRequest {
    pub id: String,
    pub e: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenLockerFinishRequest {
    pub id: String,
    pub e: String,
    pub i: String,
    pub n: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenLockerResponse {
    pub id: u32,
    pub o: String,
    pub n: u32,
}

//TODO Either need to parameterize response structs using generics or all to share the same struct to DRY-up.
impl OpenLockerResponse {
    pub fn new(response: reqwest::blocking::Response) -> Result<OpenLockerResponse, CliError> {
        response
            .json::<OpenLockerResponse>()
            .map_err(CliError::ApiResponseReqwestError)
    }

    pub fn unauthorized(id: u32, n: u32) -> OpenLockerResponse {
        OpenLockerResponse {
            id,
            o: "unauthorized".to_string(),
            n,
        }
    }

    pub fn unknown(id: u32, n: u32) -> OpenLockerResponse {
        OpenLockerResponse {
            id,
            o: "unknown".to_string(),
            n,
        }
    }
}

impl RegisterLockerResponse {
    pub fn new(response: reqwest::blocking::Response) -> Result<RegisterLockerResponse, CliError> {
        response
            .json::<RegisterLockerResponse>()
            .map_err(CliError::ApiResponseReqwestError)
    }

    pub fn unauthorized(_response: reqwest::blocking::Response) -> RegisterLockerResponse {
        RegisterLockerResponse {
            id: 0,
            o: "unauthorized".to_string(),
        }
    }

    pub fn unknown(_response: reqwest::blocking::Response) -> RegisterLockerResponse {
        RegisterLockerResponse {
            id: 0,
            o: "unknown".to_string(),
        }
    }
}

impl DeleteLockerResponse {
    pub fn new(response: reqwest::blocking::Response) -> Result<DeleteLockerResponse, CliError> {
        response
            .json::<DeleteLockerResponse>()
            .map_err(CliError::ApiResponseReqwestError)
    }

    pub fn unauthorized(_response: reqwest::blocking::Response) -> DeleteLockerResponse {
        DeleteLockerResponse {
            id: 0,
            o: "unauthorized".to_string(),
            n: 0,
        }
    }

    pub fn unknown(_response: reqwest::blocking::Response) -> DeleteLockerResponse {
        DeleteLockerResponse {
            id: 0,
            o: "unknown".to_string(),
            n: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteLockerStartRequest {
    pub id: String,
    pub e: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteLockerFinishRequest {
    pub id: String,
    pub e: String,
    pub i: String,
    pub n: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteLockerResponse {
    pub id: u32,
    pub o: String,
    pub n: u32,
}
