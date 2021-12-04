use std::io::Write;

fn main() {
    output_data_file().unwrap();
}

/// Builds and outputs the `data.rs` file.
fn output_data_file() -> std::io::Result<()> {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let out_path = std::path::Path::new(&out_dir).join("data.rs");
    let mut out = std::fs::File::create(out_path)?;

    // Build data buffer.
    const USERNAME_LEN: usize = 512;
    const PASSWORD_LEN: usize = 512;
    const CMD_LEN: usize = 2048;
    const CWD_LEN: usize = 2048;
    const MAGIC: &[u16; 8] = &[8387, 11430, 4708, 64710, 46462, 37608, 29767, 19419];

    // Data is stored in UTF-16.
    let mut data = Vec::<u16>::new();

    let magic_offset = data.len();
    data.extend(MAGIC);

    let username_offset = data.len();
    data.extend(&[0; USERNAME_LEN + 1]);

    let password_offset = data.len();
    data.extend(&[0; PASSWORD_LEN + 1]);

    let cmd_offset = data.len();
    data.extend(&[0; CMD_LEN + 1]);

    let cwd_offset = data.len();
    data.extend(&[0; CWD_LEN + 1]);

    // Write constants.
    //
    // Note that DATA is written to a `static mut` buffer even though it is never mutated; this
    // ensures that the compiler doesn't optimize away reads.
    writeln!(
        &mut out,
        "static mut DATA: &[u16; {}] = &{:?};",
        data.len(),
        &data,
    )?;

    for (name, offset, len) in [
        ("MAGIC", magic_offset, MAGIC.len()),
        ("USERNAME", username_offset, USERNAME_LEN),
        ("PASSWORD", password_offset, PASSWORD_LEN),
        ("CMD", cmd_offset, CMD_LEN),
        ("CWD", cwd_offset, CWD_LEN),
    ] {
        writeln!(
            &mut out,
            "pub(super) const {}_OFFSET: usize = {};",
            name, offset,
        )?;
        writeln!(&mut out, "pub(super) const {}_LEN: usize = {};", name, len)?;
    }

    Ok(())
}
