use std::time::{SystemTime, UNIX_EPOCH};

use stoffel::prelude::*;

fn main() -> stoffel::Result<()> {
    let source = "def main(a: int64, b: int64) -> int64:\n  return a * b";
    let runtime = Stoffel::compile(source)?.build()?;

    let bytecode_path = std::env::temp_dir().join(format!(
        "stoffel-sdk-bytecode-{}-{}.stfb",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    runtime.save_bytecode(&bytecode_path)?;
    let summary = runtime.bytecode_summary()?;

    let result = Stoffel::load_file(&bytecode_path)?
        .with_inputs(&[("a", 6_i64), ("b", 7_i64)])
        .execute_clear()?;

    let _ = std::fs::remove_file(&bytecode_path);
    println!(
        "Bytecode round-trip result: {} ({} bytes, {} function(s))",
        result[0], summary.byte_len, summary.program.function_count
    );
    Ok(())
}
