use pyo3_stub_gen::Result;

fn main() -> Result<()> {
    let stub = nitrobox_core::stub_info()?;
    stub.generate()?;
    Ok(())
}
