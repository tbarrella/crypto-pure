use std::io;
use rand::Rng;
use rand::os::OsRng;

pub fn new(len: usize) -> io::Result<Vec<u8>> {
    let mut rng = OsRng::new()?;
    let mut key = vec![0; len];
    rng.fill_bytes(&mut key);
    Ok(key)
}
