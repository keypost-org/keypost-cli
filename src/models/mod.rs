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
