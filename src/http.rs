use crate::models::*;
use reqwest::blocking::Response;
use reqwest::header::HeaderMap;

pub fn register_start(
    url: &str,
    email: &str,
    input: &str,
    pkce_code_challenge: &str,
) -> Result<RegisterResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<RegisterResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn register_finish(
    url: &str,
    id: u32,
    email: &str,
    input: &str,
    pkce_code_verify: &str,
) -> Result<RegisterResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<RegisterResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn login_start(email: &str, input: &str) -> Result<LoginResponse, CliError> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/start")
        .headers(create_headers())
        .json::<LoginStartRequest>(&LoginStartRequest {
            e: email.to_string(),
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<LoginResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn login_finish(id: u32, email: &str, input: &str) -> Result<LoginResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<LoginResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn login_verify(id: u32, input: &str) -> Result<LoginResponse, CliError> {
    match reqwest::blocking::Client::new()
        .post("http://localhost:8000/login/verify")
        .headers(create_headers())
        .json::<LoginVerifyRequest>(&LoginVerifyRequest {
            id,
            i: input.to_string(),
        })
        .send()
    {
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<LoginResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn register_locker_start(
    id: &str,
    email: &str,
    input: &str,
    auth: &str,
) -> Result<RegisterLockerResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<RegisterLockerResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                Ok(RegisterLockerResponse::unauthorized(response))
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn register_locker_finish(
    id: &str,
    email: &str,
    input: &str,
    ciphertext: &str,
    auth: &str,
) -> Result<RegisterLockerResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<RegisterLockerResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                Ok(RegisterLockerResponse::unauthorized(response))
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn open_locker_start(
    id: &str,
    email: &str,
    input: &str,
    auth: &str,
) -> Result<OpenLockerResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                OpenLockerResponse::new(response)
            } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                Ok(OpenLockerResponse::unauthorized(0, 0))
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn open_locker_finish(
    id: &str,
    email: &str,
    input: &str,
    nonce: u32,
    auth: &str,
) -> Result<OpenLockerResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<OpenLockerResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                Ok(OpenLockerResponse::unauthorized(0, 0))
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn delete_locker_start(
    id: &str,
    email: &str,
    input: &str,
    auth: &str,
) -> Result<DeleteLockerResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<DeleteLockerResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                Ok(DeleteLockerResponse::unauthorized(response))
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
    }
}

pub fn delete_locker_finish(
    id: &str,
    email: &str,
    input: &str,
    nonce: u32,
    auth: &str,
) -> Result<DeleteLockerResponse, CliError> {
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
        Ok(response) => {
            if response.status().is_success() {
                response
                    .json::<DeleteLockerResponse>()
                    .map_err(CliError::ApiResponseReqwestError)
            } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                Ok(DeleteLockerResponse::unauthorized(response))
            } else {
                create_error_response::<_>(response)
            }
        }
        Err(err) => Err(CliError::ApiResponseReqwestError(err)),
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

fn create_error_response<T>(response: Response) -> Result<T, CliError> {
    let resp_bytes = response
        .bytes()
        .map_err(CliError::ApiResponseReqwestError)?
        .to_vec();
    let resp_str = String::from_utf8(resp_bytes).map_err(|_err: std::string::FromUtf8Error| {
        CliError::ApiResponseParseError(String::from("Could not parse response bytes into String!"))
    })?;
    Err(CliError::ApiResponseUnknownError(resp_str))
}
