use std::path::PathBuf;
use std::{env, fs};
use std::collections::HashMap;

use clap::{Parser, Subcommand};
use which::which;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// alias for the store; default: first in the config, or "main"
    #[arg(short, long)]
    store: Option<String>,

    /// the age backend to use
    #[arg(long)]
    age: Option<String>,

    /// the command to run; "show" if omitted
    #[command(subcommand)]
    command: Option<Commands>,
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

    /// change to the store directory
    Cd {},

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

    /// show/edit the config
    Config {
        /// edit the store-independent options
        #[arg(long)]
        global: bool,

        /// list the current config options
        #[arg(short, long)]
        list: bool,

        /// the key to change
        #[arg(index = 1)]
        key: Option<String>,

        /// the value to set
        #[arg(index = 2)]
        value: Option<String>,
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

    if cli.store == None {
        cli.store = Some(match config.stores.is_empty() {
            true => String::from("main"),
            false => config.stores
        });
    }
}
