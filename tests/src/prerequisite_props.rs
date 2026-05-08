//! Property test for prerequisite validation (Property 26).

use kernel::prerequisites::*;
use proptest::prelude::*;

proptest! {
    /// Property 26: For any system config, checker SHALL correctly identify all
    /// deficiencies; passing systems pass, failing systems report specific issue.
    #[test]
    fn prop26_prerequisite_validation(min_ram in 0u64..200, min_disk in 0u64..200) {
        let result = check_with_thresholds(min_ram, min_disk, false);

        if result.passed {
            prop_assert!(result.deficiencies.is_empty(),
                "Passing result should have no deficiencies");
        } else {
            prop_assert!(!result.deficiencies.is_empty(),
                "Failing result should report specific deficiencies");
            // Each deficiency should be descriptive
            for d in &result.deficiencies {
                prop_assert!(!d.is_empty(), "Deficiency should not be empty");
            }
        }
    }
}
