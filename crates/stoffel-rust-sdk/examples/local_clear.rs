use stoffel::prelude::*;

fn main() -> stoffel::Result<()> {
    let runtime = Stoffel::compile(
        r#"
def double(value: int64) -> int64:
  return value * 2

def main(value: int64) -> int64:
  return double(value)
"#,
    )?
    .with_inputs(&[("value", 21_i64)])
    .build()?;

    let result = runtime.execute_clear()?;
    println!("Local clear VM result: {}", result[0]);
    Ok(())
}
