use stoffel_vm_types::instructions::Instruction;
use stoffellang::compiler::{compile, CompilerOptions};

#[test]
fn secret_expressions_cannot_be_refined_into_clear_assignments() {
    for (ty, expression) in [("int64", "s + 0"), ("int64", "-s"), ("bool", "not s")] {
        let source = format!("def main(s: secret {ty}):\n  var result: {ty}\n  result = {expression}\n  print(result)\n");
        let errors = compile(&source, "veria-301.stfl", &CompilerOptions::default())
            .expect_err("secret assignment must require an explicit reveal");
        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("implicitly reveal")),
            "{errors:?}"
        );
    }
}

#[test]
fn secret_scalar_cannot_be_assigned_to_a_clear_share_handle() {
    let source = "def main(s: secret int64):\n  var handle: Share\n  handle = s\n  print(handle)\n";
    assert!(compile(source, "veria-303.stfl", &CompilerOptions::default()).is_err());
}

#[test]
fn a_user_reveal_function_is_not_compiled_as_an_mpc_open() {
    let source = "def reveal(s: secret int64) -> secret int64:\n  return s\ndef main(s: secret int64) -> secret int64:\n  return reveal(s)\n";
    let program = compile(source, "veria-294.stfl", &CompilerOptions::default()).unwrap();
    assert!(program
        .main_chunk
        .instructions
        .iter()
        .any(|instruction| matches!(instruction, Instruction::CALL(name) if name == "reveal")));
    assert!(!program
        .main_chunk
        .instructions
        .iter()
        .any(|instruction| matches!(instruction, Instruction::CALL(name) if name == "Share.open")));
}

#[test]
fn explicit_reveal_and_secret_arguments_to_share_builtins_remain_supported() {
    let source = "def main(s: secret int64) -> int64:\n  var handle: Share = s\n  MpcOutput.send_to_client(0, s)\n  var result: int64\n  result = s.reveal()\n  return result\n";
    compile(source, "veria-controls.stfl", &CompilerOptions::default()).unwrap();
}

#[test]
fn aes_carry_remains_secret_when_reassigned() {
    for optimization_level in [0, 3] {
        let options = CompilerOptions {
            optimization_level,
            optimize: optimization_level > 0,
            ..Default::default()
        };
        let good = "def main(bit: secret bool) -> secret bool:\n  var carry: secret bool = Share.from_clear_int(1, 1)\n  carry = bit\n  return carry\n";
        compile(good, "carry.stfl", &options).unwrap();
        let unsafe_source = good.replace("carry: secret bool", "carry");
        assert!(compile(&unsafe_source, "carry.stfl", &options).is_err());
    }
}

#[test]
fn assigning_secret_values_to_share_list_slots_keeps_boxed_values_supported() {
    let source = "def main(s: secret int64):\n  var keys: list[Share] = list(1)\n  keys[0] = s\n";
    compile(source, "share-list.stfl", &CompilerOptions::default()).unwrap();
}
