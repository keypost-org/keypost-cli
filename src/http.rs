use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterStartRequest {
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterFinishRequest {
    pub id: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginStartRequest {
    pub file: String,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginFinishRequest {
    pub id: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResponse {
    pub id: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginResponse {
    pub id: u32,
    pub data: String,
}

pub fn login_start(file: &str, data: &str) -> Result<LoginResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/start")
        .headers(headers)
        .json::<LoginStartRequest>(&LoginStartRequest {
            file: file.to_string(),
            data: data.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<LoginResponse>(),
        Err(err) => Err(err),
    }
}

pub fn login_finish(id: u32, data: &str) -> Result<LoginResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/finish")
        .headers(headers)
        .json::<LoginFinishRequest>(&LoginFinishRequest {
            id,
            data: data.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<LoginResponse>(),
        Err(err) => Err(err),
    }
}

pub fn register_post(
    url: &str,
    id: Option<u32>,
    data: &str,
) -> Result<RegisterResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());

    match id {
        Some(id) => {
            match reqwest::blocking::Client::new()
                .post(url)
                .headers(headers)
                .json::<RegisterFinishRequest>(&RegisterFinishRequest {
                    id,
                    data: data.to_string(),
                })
                .send()
            {
                Ok(response) => response.json::<RegisterResponse>(),
                Err(err) => Err(err),
            }
        }
        None => {
            match reqwest::blocking::Client::new()
                .post(url)
                .headers(headers)
                .json::<RegisterStartRequest>(&RegisterStartRequest {
                    data: data.to_string(),
                })
                .send()
            {
                Ok(response) => response.json::<RegisterResponse>(),
                Err(err) => Err(err),
            }
        }
    }
}
