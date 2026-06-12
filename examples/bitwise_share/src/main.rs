use stoffel::prelude::*;

mod stoffel_bindings;

#[tokio::main]
async fn main() -> stoffel::Result<()> {
    let _manifest = stoffel_bindings::ProgramManifest;
    let result = Stoffel::compile_file("src/main.stfl")?
        .parties(5)
        .threshold(1)
        .execute_local()
        .await?;

    println!("{}", result[0]);
    Ok(())
}
