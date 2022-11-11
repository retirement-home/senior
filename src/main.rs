use std::path::PathBuf;
use std::{env, fs};
use std::process::Command;
use std::ffi::OsString;

use clap::{Parser, Subcommand};
use which::which;
use tempdir::TempDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// alias for the store; default: "main", or the only existing one
    #[arg(short, long)]
    store: Option<String>,

    /// the age backend to use
    #[arg(long)]
    age: Option<String>,

    /// the command to run; "show" if omitted
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// initialises a new store
    Init {
        /// path of the private key used for decrypting; will be generated if none is supplied
        #[arg(long = "private-key")]
        private_key: Option<String>,

        /// alias for recipient; defaults to the username
        #[arg(long = "recipient-alias")]
        recipient_alias: Option<String>,
    },

    /// clones a store from a git repository
    Clone {
        /// address of the remote git repository
        #[arg(index = 1)]
        address: String,
    },

    /// edit/create a password
    Edit {
        /// name of the password file
        #[arg(index = 1)]
        name: String,
    },

    /// show the password
    Show {
        /// show only this key
        #[arg(short, long)]
        key: Option<String>,

        /// name of the password file
        #[arg(index = 1)]
        name: String,
    },

    /// show the one-time password
    Otp {
        /// name of the password file
        #[arg(index = 1)]
        name: String,
    },

    /// change to the store's directory
    Cd {},

    /// show the store's directory path
    PrintDir {},

    /// git pull and push
    Sync {},

    /// add recipient
    AddRecipient {
        /// public key of the new recipient; cleartext or path
        #[arg(index = 1)]
        public_key: String
    },

    /// request recipient
    RequestRecipient {
        /// add your key to the requested recipients; cleartext or path
        #[arg(index = 1)]
        public_key: String
    },
}

fn find_age_backend() -> String {
    let known_backends = ["rage", "age"];
    for backend in known_backends {
        if let Ok(_) = which(backend) {
            return String::from(backend);
        }
    }
    panic!("Could not find an age backend!");
}

fn init(cli: &Cli, stores_dir: PathBuf, private_key: &Option<String>, recipient_alias: &mut Option<String>) {
    let store_dir = stores_dir.join(cli.store.as_ref().unwrap());
    assert!(!store_dir.exists(), "The directory of the store exists already");
    if recipient_alias == &None {
        *recipient_alias = Some(env::var_os("USER").expect("Could not get the username").into_string().unwrap());
    }

    //let (privkeyfile, pubkey) =
    match private_key {
        Some(path_string) => {
            let pathbuf = PathBuf::from(path_string);
            assert!(pathbuf.is_file(), "supplied path is not a file");
            (pathbuf, "pubkey")
        },
        None => {
            let tmp_dir = TempDir::new("senior-keygen").expect("Could not create temporary directory");
            let keypath = tmp_dir.path().join("privkey.txt");
            let mut age_keygen = cli.age.as_ref().unwrap().clone();
            age_keygen.push_str("-keygen");
            let command_output = Command::new(OsString::from(age_keygen)).args(["-o", keypath.to_str().unwrap()]).output().expect("Could not generate key-pair").stdout;
            let output = String::from_utf8_lossy(&command_output);
            (keypath, &output["Public key: ".len()..])
        }
    };
}

fn main() {
    let mut cli = Cli::parse();

    let stores_dir = match env::var_os("XDG_DATA_HOME") {
        Some(val) => PathBuf::from(val),
        None => PathBuf::from(env::var_os("HOME").unwrap()).join(".local/share"),
    }.join("senior/stores/");

    if cli.store == None {
        cli.store = Some(if stores_dir.is_dir() {
            let mut entries = stores_dir.read_dir().expect("Could not read stores directory").filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir());
            match (entries.next(), entries.next()) {
                (Some(entry), None) => entry.unwrap().file_name().into_string().unwrap(),
                _ => String::from("main"),
            }
        } else {
            String::from("main")
        });
    }

    if cli.age == None {
        cli.age = Some(find_age_backend());
    }

    match &cli.command {
        Commands::Init { private_key, mut recipient_alias, } => init(&cli, stores_dir, private_key, &mut recipient_alias),
        _ => panic!("Command not yet implemented"),
    }

    print!("{:?}", cli);
}
