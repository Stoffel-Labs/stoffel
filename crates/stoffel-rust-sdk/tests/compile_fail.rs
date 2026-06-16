#[test]
fn generated_client_io_bindings_reject_wrong_types_at_compile_time() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/generated_client_io_wrong_*.rs");
}
