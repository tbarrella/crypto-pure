use std::io;
use rand::{Rand, Rng};
use rand::os::OsRng;

pub fn new(len: usize) -> io::Result<Vec<u8>> {
    let mut rng = OsRng::new()?;
    let mut key = vec![0; len];
    rng.fill_bytes(&mut key);
    Ok(key)
}

pub fn gen<T: Rand>() -> io::Result<T> {
    let mut rng = OsRng::new()?;
    Ok(rng.gen())
}
