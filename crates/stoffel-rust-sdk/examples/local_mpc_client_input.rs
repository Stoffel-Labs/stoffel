use stoffel::prelude::*;

#[tokio::main]
async fn main() -> stoffel::Result<()> {
    let source = r#"
def main() -> int64:
  var share = ClientStore.take_share(0, 0)
  var opened: int64 = share.open()
  return opened + 5
"#;

    let runtime = Stoffel::compile(source)?.parties(5).threshold(1).build()?;
    let client = runtime.program().client(0).expect("client slot 0");
    println!(
        "Program expects {} input(s) from client slot {}",
        client.input_count(),
        client.client_slot()
    );

    match Stoffel::load(&runtime.program().to_bytecode()?)?
        .parties(5)
        .threshold(1)
        .with_client_input(0, &[42_i64])
        .execute_local()
        .await
    {
        Ok(result) => println!("Local MPC result: {}", result[0]),
        Err(stoffel::Error::Unsupported(message)) if message.contains("stoffel-run") => {
            println!("Build stoffel-run first to execute local MPC: {message}");
        }
        Err(error) => return Err(error),
    }

    Ok(())
}
