/// Return a borrowed UTF-8 prefix within the requested byte budget.
pub fn bounded_prefix(input: &str, max_bytes: usize) -> &str {
    &input[..input.len().min(max_bytes)]
}
