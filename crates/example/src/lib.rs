use rand::Rng;

/// Generates a random number between 1 and 100
pub fn generate_random_number() -> i32 {
    rand::thread_rng().gen_range(1..=100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_number_in_range() {
        let num = generate_random_number();
        assert!(num >= 1 && num <= 100);
    }
}
