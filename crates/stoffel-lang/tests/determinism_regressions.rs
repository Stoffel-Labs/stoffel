use stoffellang::{compile, convert_to_binary, CompilerOptions};

fn binary(level: u8) -> Vec<u8> {
    let program = compile(
        include_str!("../examples/local_control_flow/main.stfl"),
        "determinism.stfl",
        &CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            ..Default::default()
        },
    )
    .unwrap();
    let mut bytes = Vec::new();
    convert_to_binary(&program).serialize(&mut bytes).unwrap();
    bytes
}

#[test]
fn sequential_and_concurrent_compilations_produce_identical_binary_bytes() {
    for level in 0..=3 {
        let expected = binary(level);
        for _ in 0..8 {
            assert_eq!(binary(level), expected, "sequential O{level}");
        }
        let barrier = std::sync::Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let barrier = &barrier;
                let expected = &expected;
                scope.spawn(move || {
                    barrier.wait();
                    for _ in 0..8 {
                        assert_eq!(&binary(level), expected, "concurrent O{level}");
                    }
                });
            }
        });
    }
}
