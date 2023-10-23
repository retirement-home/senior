use clap::CommandFactory;
use clap_complete::{generate_to, shells::Bash, shells::Zsh};
use clap_mangen::Man;
use std::env;
use std::path::Path;
use std::fs::File;
use std::io::Result;
use clap::Command;
use std::io::Write;

include!("src/cli.rs");

fn generate_manpages(dir: &Path) -> Result<()> {
    fn generate(dir: &Path, app: &Command) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let name = app.get_display_name().unwrap_or_else(|| app.get_name());
        let mut out = File::create(dir.join(format!("{name}.1")))?;

        Man::new(app.clone()).title(name.to_uppercase()).manual("senior").render(&mut out)?;
        out.flush()?;

        for sub in app.get_subcommands() {
            let sub = sub.clone().name(format!("senior {}", sub.get_name()));
            generate(dir, &sub)?;
        }
        Ok(())
    }

    let mut app = Cli::command().disable_help_subcommand(true);
    app.build();

    println!("cargo:warning=Generating manpages in ../man/");
    generate(dir, &app)
}

fn main() -> Result<()> {
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
    generate_manpages(&out_dir)?;

    Ok(())
}
