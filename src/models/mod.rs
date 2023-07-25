use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterStartRequest {
    pub e: String,
    pub i: String,
    pub c: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterFinishRequest {
    pub id: u32,
    pub e: String,
    pub i: String,
    pub v: String,
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
    pub c: String,
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
    pub fn new(response: reqwest::blocking::Response) -> OpenLockerResponse {
        response
            .json::<OpenLockerResponse>()
            .expect("Could not deserialize JSON response: OpenLockerResponse")
    }

    pub fn unauthorized(_response: reqwest::blocking::Response) -> OpenLockerResponse {
        OpenLockerResponse {
            id: 0,
            o: "unauthorized".to_string(),
            n: 0,
        }
    }

    pub fn unknown(_response: reqwest::blocking::Response) -> OpenLockerResponse {
        OpenLockerResponse {
            id: 0,
            o: "unknown".to_string(),
            n: 0,
        }
    }
}

impl RegisterLockerResponse {
    pub fn new(response: reqwest::blocking::Response) -> RegisterLockerResponse {
        response
            .json::<RegisterLockerResponse>()
            .expect("Could not deserialize JSON response: RegisterLockerResponse")
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
    pub fn new(response: reqwest::blocking::Response) -> DeleteLockerResponse {
        response
            .json::<DeleteLockerResponse>()
            .expect("Could not deserialize JSON response: DeleteLockerResponse")
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
