use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResponse {
    pub id: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterRequest {
    pub id: u32,
    pub data: String,
}

pub fn post(url: &str, id: u32, data: &str) -> Result<RegisterResponse, reqwest::Error> {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::CONTENT_TYPE, "json".parse().unwrap());
    let json_data = RegisterRequest {
        id,
        data: data.to_string(),
    };
    match reqwest::blocking::Client::new()
        .post(url)
        .headers(headers)
        .json::<RegisterRequest>(&json_data)
        .send()
    {
        Ok(response) => response.json::<RegisterResponse>(),
        Err(err) => Err(err),
    }
}
