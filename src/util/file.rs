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

pub fn write_to_secure_file(file_name: &str, bytes: &[u8]) -> Result<(), Error> {
    let file_path = default_dir() + "/" + file_name;
    fs::write(&file_path, bytes)?;
    let mut p = fs::metadata(&file_path)?.permissions();
    p.set_mode(0o600);
    fs::set_permissions(&file_path, p)
}

pub fn read_file(file_path: &str) -> Result<Vec<u8>, Error> {
    fs::read(file_path).map_err(|err| {
        println!("ERROR: Could not read file {}. Error: {:?}", file_path, err);
        err
    })
}
