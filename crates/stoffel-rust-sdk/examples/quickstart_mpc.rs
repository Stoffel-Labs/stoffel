use stoffel::prelude::*;

#[tokio::main]
async fn main() -> stoffel::Result<()> {
    let result = Stoffel::compile(
        "def main(a: secret int64, b: secret int64) -> secret int64:\n  return a + b",
    )?
    .parties(5)
    .threshold(1)
    .with_inputs(&[("a", 42_i64), ("b", 58_i64)])
    .execute_local()
    .await;

    match result {
        Ok(values) => println!("Private result: {}", values[0]),
        Err(stoffel::Error::Unsupported(message)) if message.contains("stoffel-run") => {
            println!("Build stoffel-run first to execute local MPC: {message}");
        }
        Err(error) => return Err(error),
    }

    Ok(())
}
