use std::path::PathBuf;
use std::{env, fs};

use clap::{Parser, Subcommand};
use which::which;

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
        /// generate new keys
        #[arg(long)]
        generate: bool,

        /// private key used for decrypting; cleartext or path
        #[arg(long = "private-key")]
        private_key: Option<String>,

        /// public key used for encrypting; cleartext or path
        #[arg(long)]
        recipient: Option<String>,

        /// alias for recipient; defaults to the username
        #[arg(long = "recipient-alias")]
        recipient_alias: Option<String>,

        /// the backend to use for age
        #[arg(long = "age-backend")]
        age_backend: Option<String>,
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

fn init(cli: &Cli) {
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

    print!("{:?}", cli);
}
