use clap_complete::{generate_to, shells::Bash, shells::Zsh};
use clap::CommandFactory;
use std::env;
use std::io::Error;

include!("src/cli.rs");

fn main() -> Result<(), Error> {
    print!("cargo:rerun-if-changed=build.rs");
    print!("cargo:rerun-if-changed=src/cli.rs");
    let outdir = match env::var_os("OUT_DIR") {
        None => panic!("Env variable doesn't exist."),
        Some(outdir) => outdir,
    };

    let mut cmd = Cli::command();
    let bash_path = generate_to(
        Bash,
        &mut cmd, // We need to specify what generator to use
        "senior",  // We need to specify the bin name manually
        &outdir,   // We need to specify where to write to
    ).expect("Failed to generate Bash completion");

    println!("cargo:warning=bash completion file is generated: {:?}", bash_path);

    let zsh_path = generate_to(
        Zsh,
        &mut cmd, // We need to specify what generator to use
        "senior",  // We need to specify the bin name manually
        &outdir,   // We need to specify where to write to
    ).expect("Failed to generate Zsh completion");

    println!("cargo:warning=Zsh file is generated: {:?}", zsh_path);
    println!("cargo:warning=Bash file is generated: {:?}", bash_path);
    Ok(())
}
