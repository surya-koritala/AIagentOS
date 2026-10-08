use coding_utf8_budget_fixture::bounded_prefix;

#[test]
fn ascii_empty_and_unlimited_budgets() {
    assert_eq!(bounded_prefix("abcdef", 3), "abc");
    assert_eq!(bounded_prefix("abcdef", usize::MAX), "abcdef");
    assert_eq!(bounded_prefix("", 9), "");
    assert_eq!(bounded_prefix("abc", 0), "");
}

#[test]
fn multibyte_text_never_panics_or_exceeds_the_byte_budget() {
    for input in ["雪ab", "a💻z", "éclair", "e\u{301}cho", "中文 🦀 Rust"] {
        for budget in 0..=input.len() + 2 {
            let actual = bounded_prefix(input, budget);
            assert!(actual.len() <= budget);
            assert!(input.starts_with(actual));
            if actual.len() < input.len() {
                let next_width = input[actual.len()..].chars().next().unwrap().len_utf8();
                assert!(actual.len() + next_width > budget, "prefix must be maximal");
            }
        }
    }
}
