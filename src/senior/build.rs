use clap::CommandFactory;
use clap_complete::{generate_to, shells::Bash, shells::Zsh};
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
        Bash, &mut cmd, // We need to specify what generator to use
        "senior", // We need to specify the bin name manually
        &outdir,  // We need to specify where to write to
    )
    .expect("Failed to generate Bash completion");

    println!("cargo:warning=Generated bash completion: {:?}", bash_path);

    let zsh_path = generate_to(
        Zsh, &mut cmd, // We need to specify what generator to use
        "senior", // We need to specify the bin name manually
        &outdir,  // We need to specify where to write to
    )
    .expect("Failed to generate Zsh completion");

    println!("cargo:warning=Generated zsh completion: {:?}", zsh_path);

    let out_dir = std::path::PathBuf::from("../man");
    std::fs::create_dir_all(&out_dir)?;
    let man = clap_mangen::Man::new(cmd);
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;
    let man_file = out_dir.join("senior.1");
    std::fs::write(&man_file, buffer)?;
    println!("cargo:warning=Generated man page {}", man_file.display());

    for subcommand in Cli::command().get_subcommands() {
        let man = clap_mangen::Man::new(subcommand.clone());
        let mut buffer: Vec<u8> = Default::default();
        man.render(&mut buffer)?;
        let man_file = out_dir.join(format!("senior-{}.1", subcommand.get_name()));
        std::fs::write(&man_file, buffer)?;
        println!("cargo:warning=Generated man page {}", man_file.display());
    }

    Ok(())
}
