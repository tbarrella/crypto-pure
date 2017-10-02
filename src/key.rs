use std::io;
use rand::{Rand, Rng};
use rand::os::OsRng;

pub fn gen<T: Rand>() -> io::Result<T> {
    let mut rng = OsRng::new()?;
    Ok(rng.gen())
}
