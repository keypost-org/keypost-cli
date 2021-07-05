use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterStartRequest {
    pub u: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterFinishRequest {
    pub id: u32,
    pub u: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStartRequest {
    pub u: String,
    pub i: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinishRequest {
    pub id: u32,
    pub u: String,
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
    user_name: &str,
    input: &str,
) -> Result<RegisterResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post(url)
        .headers(headers)
        .json::<RegisterStartRequest>(&RegisterStartRequest {
            u: user_name.to_string(),
            i: input.to_string(),
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
    user_name: &str,
    input: &str,
) -> Result<RegisterResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post(url)
        .headers(headers)
        .json::<RegisterFinishRequest>(&RegisterFinishRequest {
            id,
            u: user_name.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<RegisterResponse>(),
        Err(err) => Err(err),
    }
}

pub fn login_start(user_name: &str, input: &str) -> Result<LoginResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/start")
        .headers(headers)
        .json::<LoginStartRequest>(&LoginStartRequest {
            u: user_name.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<LoginResponse>(),
        Err(err) => Err(err),
    }
}

pub fn login_finish(
    id: u32,
    user_name: &str,
    input: &str,
) -> Result<LoginResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/finish")
        .headers(headers)
        .json::<LoginFinishRequest>(&LoginFinishRequest {
            id,
            u: user_name.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<LoginResponse>(),
        Err(err) => Err(err),
    }
}
