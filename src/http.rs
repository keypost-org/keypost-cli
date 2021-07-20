use reqwest::header::HeaderMap;
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

pub fn register_start(
    url: &str,
    email: &str,
    input: &str,
    pkce_code_challenge: &str,
) -> Result<RegisterResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post(url)
        .headers(headers)
        .json::<RegisterStartRequest>(&RegisterStartRequest {
            e: email.to_string(),
            i: input.to_string(),
            c: pkce_code_challenge.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<RegisterResponse>(),
        Err(err) => Err(err),
    }
}

pub fn register_finish(
    url: &str,
    id: u32,
    email: &str,
    input: &str,
    pkce_code_verify: &str,
) -> Result<RegisterResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post(url)
        .headers(headers)
        .json::<RegisterFinishRequest>(&RegisterFinishRequest {
            id,
            e: email.to_string(),
            i: input.to_string(),
            v: pkce_code_verify.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<RegisterResponse>(),
        Err(err) => Err(err),
    }
}

pub fn login_start(email: &str, input: &str) -> Result<LoginResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/start")
        .headers(headers)
        .json::<LoginStartRequest>(&LoginStartRequest {
            e: email.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<LoginResponse>(),
        Err(err) => Err(err),
    }
}

pub fn login_finish(id: u32, email: &str, input: &str) -> Result<LoginResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/finish")
        .headers(headers)
        .json::<LoginFinishRequest>(&LoginFinishRequest {
            id,
            e: email.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<LoginResponse>(),
        Err(err) => Err(err),
    }
}
