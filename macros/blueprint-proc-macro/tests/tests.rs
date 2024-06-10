#[cfg(test)]
mod tests {
    use trybuild::TestCases;

    #[test]
    fn test_jobs_valid_cases() {
        let t = TestCases::new();
        t.pass("tests/valid_cases/job/*.rs");
    }

    #[test]
    fn test_jobs_invalid_cases() {
        let t = TestCases::new();
        t.compile_fail("tests/invalid_cases/job/*.rs");
    }

    #[test]
    fn test_blueprint_valid_cases() {
        let t = TestCases::new();
        t.pass("tests/valid_cases/blueprint/*.rs");
    }
}
