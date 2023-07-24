use crate::models::*;
use reqwest::header::HeaderMap;

//TODO This struct, or a version of it, might come in handy once an error crate is implemented
// struct ApiError {
//     pub status: u16,
//     pub message: String,
//     pub error: Option<reqwest::Error>,
// }

// impl ApiError {
//     pub fn new(status: u16, message: String, error: Option<reqwest::Error>) -> Self {
//         ApiError {
//             status,
//             message,
//             error
//         }
//     }
// }

pub fn register_start(
    url: &str,
    email: &str,
    input: &str,
    pkce_code_challenge: &str,
) -> Result<RegisterResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post(url)
        .headers(create_headers())
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
    match reqwest::blocking::Client::new()
        .post(url)
        .headers(create_headers())
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
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/start")
        .headers(create_headers())
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
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/finish")
        .headers(create_headers())
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

pub fn login_verify(id: u32, input: &str) -> Result<LoginResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/verify")
        .headers(create_headers())
        .json::<LoginVerifyRequest>(&LoginVerifyRequest {
            id,
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<LoginResponse>(),
        Err(err) => Err(err),
    }
}

pub fn register_locker_start(
    id: &str,
    email: &str,
    input: &str,
    auth: &str,
) -> Result<RegisterLockerResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/locker/register/start")
        .headers(create_headers_with_auth(auth))
        .json::<RegisterLockerStartRequest>(&RegisterLockerStartRequest {
            id: id.to_string(),
            e: email.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<RegisterLockerResponse>(),
        Err(err) => Err(err),
    }
}

pub fn register_locker_finish(
    id: &str,
    email: &str,
    input: &str,
    ciphertext: &str,
    auth: &str,
) -> Result<RegisterLockerResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/locker/register/finish")
        .headers(create_headers_with_auth(auth))
        .json::<RegisterLockerFinishRequest>(&RegisterLockerFinishRequest {
            id: id.to_string(),
            e: email.to_string(),
            i: input.to_string(),
            c: ciphertext.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<RegisterLockerResponse>(),
        Err(err) => Err(err),
    }
}

pub fn open_locker_start(
    id: &str,
    email: &str,
    input: &str,
    auth: &str,
) -> Result<OpenLockerResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/locker/open/start")
        .headers(create_headers_with_auth(auth))
        .json::<OpenLockerStartRequest>(&OpenLockerStartRequest {
            id: id.to_string(),
            e: email.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => match response.status() {
            reqwest::StatusCode::OK => Ok(OpenLockerResponse::new(response)),
            reqwest::StatusCode::UNAUTHORIZED => Ok(OpenLockerResponse::unauthorized(response)),
            _ => Ok(OpenLockerResponse::unknown(response)),
        },
        Err(err) => Err(err),
    }
}

pub fn open_locker_finish(
    id: &str,
    email: &str,
    input: &str,
    nonce: u32,
    auth: &str,
) -> Result<OpenLockerResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/locker/open/finish")
        .headers(create_headers_with_auth(auth))
        .json::<OpenLockerFinishRequest>(&OpenLockerFinishRequest {
            id: id.to_string(),
            e: email.to_string(),
            i: input.to_string(),
            n: nonce,
        })
        .send()
    {
        Ok(response) => response.json::<OpenLockerResponse>(),
        Err(err) => Err(err),
    }
}

pub fn delete_locker_start(
    id: &str,
    email: &str,
    input: &str,
    auth: &str,
) -> Result<DeleteLockerResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/locker/delete/start")
        .headers(create_headers_with_auth(auth))
        .json::<DeleteLockerStartRequest>(&DeleteLockerStartRequest {
            id: id.to_string(),
            e: email.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => response.json::<DeleteLockerResponse>(),
        Err(err) => Err(err),
    }
}

pub fn delete_locker_finish(
    id: &str,
    email: &str,
    input: &str,
    nonce: u32,
    auth: &str,
) -> Result<DeleteLockerResponse, reqwest::Error> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/locker/delete/finish")
        .headers(create_headers_with_auth(auth))
        .json::<DeleteLockerFinishRequest>(&DeleteLockerFinishRequest {
            id: id.to_string(),
            e: email.to_string(),
            i: input.to_string(),
            n: nonce,
        })
        .send()
    {
        Ok(response) => response.json::<DeleteLockerResponse>(),
        Err(err) => Err(err),
    }
}

fn create_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    headers
}

fn create_headers_with_auth(auth: &str) -> HeaderMap {
    let mut headers: HeaderMap = create_headers();
    headers.insert(reqwest::header::AUTHORIZATION, auth.parse().unwrap());
    headers
}
