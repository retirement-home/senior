use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// alias for the store; default: first in the config, or "main"
    #[arg(short, long)]
    store: Option<String>,

    /// the command to run; "show" if omitted
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
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

fn main() {
    let cli = Cli::parse();

    // You can check the value provided by positional arguments, or option arguments
    /*
    if let Some(name) = cli.name.as_deref() {
        println!("Value for name: {}", name);
    }
    */

    if let Some(config_path) = cli.config.as_deref() {
        println!("Value for config: {}", config_path.display());
    }

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    /*
    match cli.debug {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        _ => println!("Don't be crazy"),
    }
    */

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    /*
    match &cli.command {
        Some(Commands::Test { list }) => {
            if *list {
                println!("Printing testing lists...");
            } else {
                println!("Not printing testing lists...");
            }
        }
        None => {}
    }
    */

    // Continued program logic goes here...
}
