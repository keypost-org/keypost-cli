use std::env;
use std::fs;
use std::io::Error;
use std::os::unix::fs::PermissionsExt;

const SESSION_ID_LEN: usize = 20;

fn default_dir() -> String {
    String::from(env!("HOME")) + "/.keypost-cli"
}

pub fn create_default_directory() -> Result<(), Error> {
    let dir = default_dir();
    match fs::read_dir(&dir) {
        Ok(_) => Ok(()),
        Err(err) => {
            println!("DEBUG: Looked for directory {}. But error {:?}", &dir, err);
            println!("INFO: Will attempt to create directory {}", &dir);
            fs::create_dir(&dir)
        }
    }
}

pub fn write_to_secure_file(file_name: &str, bytes: &[u8], base64: bool) -> Result<(), Error> {
    let file_path = default_dir() + "/" + file_name;
    match base64 {
        true => fs::write(&file_path, base64::encode(bytes))?,
        false => fs::write(&file_path, bytes)?,
    }
    let mut p = fs::metadata(&file_path)?.permissions();
    p.set_mode(0o600);
    fs::set_permissions(&file_path, p)
}

pub fn read_file(file_name: &str, base64: bool) -> Result<Vec<u8>, Error> {
    match base64 {
        true => match read_base64_file_path(file_name) {
            Ok(s) => Ok(base64::decode(s).expect("Could not base64 decode bytes!")),
            Err(err) => Err(err),
        },
        false => {
            let file_path = default_dir() + "/" + file_name;
            fs::read(file_path)
        }
    }
}

pub fn read_base64_file_path(file_name: &str) -> Result<String, Error> {
    let file_path = default_dir() + "/" + file_name;
    fs::read_to_string(file_path)
}

pub fn write_session_file(session_id: &[u8], email: &str) -> Result<(), Error> {
    let session = [session_id, email.as_bytes()].concat();
    write_to_secure_file("session_id.public", &session, true)
}

pub fn read_session_file() -> Result<(String, String), Error> {
    let session = base64::decode(read_base64_file_path("session_id.public")?)
        .expect("Could not base64 decode session file!");
    let (session_id, email_bytes) = session.split_at(SESSION_ID_LEN);
    let email = String::from_utf8(email_bytes.to_vec()).expect("Could not parse into String");
    Ok((base64::encode(session_id).to_string(), email.to_string()))
}
