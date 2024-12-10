use sha2::{Sha256, Digest};
use crate::file_manager::file_manager::user_file_handler;

pub fn authentificate(username: &String, password: &String, users_file: &String) -> (bool, String) {
    let user_map = user_file_handler::get_user_map(users_file);
    let mut hasher = Sha256::new();
    hasher.update(password);
    let pass_hash = hasher.finalize();

    if !user_map.contains_key(username) 
    || user_map[username].0 != format!("{:x}", pass_hash) {
        println!("Wrong credentials. Goodbye.");
        return (false, "".to_string());
    }

    (true, username.to_string())
}