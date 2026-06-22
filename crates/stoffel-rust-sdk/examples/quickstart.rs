use stoffel::prelude::*;

fn main() -> stoffel::Result<()> {
    let result = Stoffel::compile("def main(a: int64, b: int64) -> int64:\n  return a + b")?
        .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
        .execute_clear()?;

    println!("Result: {}", result[0]);
    Ok(())
}
