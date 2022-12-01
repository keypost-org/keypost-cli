use std::env;
use std::fs;
use std::io::Error;
use std::os::unix::fs::PermissionsExt;

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
        true => fs::write(&file_path, base64::encode(&bytes))?,
        false => fs::write(&file_path, bytes)?,
    }
    let mut p = fs::metadata(&file_path)?.permissions();
    p.set_mode(0o600);
    fs::set_permissions(&file_path, p)
}

pub fn read_file(file_name: &str, base64: bool) -> Result<Vec<u8>, Error> {
    let file_path = default_dir() + "/" + file_name;
    match base64 {
        true => match read_base64_file_path(&file_path) {
            Ok(s) => Ok(base64::decode(s).expect("Could not base64 decode bytes!")),
            Err(err) => Err(err),
        },
        false => fs::read(&file_path),
    }
}

pub fn read_base64_file_path(file_path: &str) -> Result<String, Error> {
    fs::read_to_string(&file_path).map_err(|err| {
        println!(
            "ERROR: Could not read file {}. Error: {:?}",
            &file_path, err
        );
        err
    })
}
