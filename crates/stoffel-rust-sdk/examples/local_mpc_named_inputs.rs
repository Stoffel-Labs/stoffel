use stoffel::prelude::*;

#[tokio::main]
async fn main() -> stoffel::Result<()> {
    let source = r#"
def add_private_values(a: Share, b: Share) -> int64:
  var sum = Share.add(a, b)
  return sum.open()
"#;

    match Stoffel::compile(source)?
        .parties(5)
        .threshold(1)
        .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
        .execute_local_function("add_private_values")
        .await
    {
        Ok(result) => println!("Local MPC named-input result: {}", result[0]),
        Err(stoffel::Error::Unsupported(message)) if message.contains("stoffel run-node") => {
            println!("Build the stoffel CLI first (`cargo build -p stoffel-cli`) to execute local MPC: {message}");
        }
        Err(error) => return Err(error),
    }

    Ok(())
}
