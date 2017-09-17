pub fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    lhs.iter().zip(rhs).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use one_time_pad::*;

    #[test]
    fn test_xor() {
        assert_eq!(vec![3, 1], xor(&[1, 2], &[2, 3]));
    }
}
