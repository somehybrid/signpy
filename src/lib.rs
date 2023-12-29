use pyo3::prelude::*;
mod ed25519;
mod ge;
mod utils;

#[pymodule]
fn signpy(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<ed25519::SigningKey>()?;
    m.add_class::<ed25519::VerifyingKey>()?;
    m.add_function(wrap_pyfunction!(ed25519::generate, m)?)?;
    Ok(())
}
