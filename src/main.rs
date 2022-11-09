use std::path::PathBuf;
use std::{env, fs};
use std::collections::HashMap;

use clap::{Parser, Subcommand};
use serde_derive::{Serialize, Deserialize};
use which::which;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

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

#[derive(Deserialize, Serialize, Debug)]
struct StoreConfig {
    privkey: PathBuf,
    age_backend: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    age_backend: String,
    stores: HashMap<String, StoreConfig>,
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

impl Config {
    fn default(cli: &Cli) -> Config {
        Config {
            age_backend: match &cli.age {
                Some(backend) => backend.to_string(),
                None => find_age_backend(),
            },
            stores: HashMap::new(),
        }
    }
}

fn init(cli: &Cli, config: &mut Config) {
}

fn main() {
    let mut cli = Cli::parse();

    if cli.config == None {
        cli.config = Some(match env::var_os("XDG_CONFIG_HOME") {
            Some(val) => PathBuf::from(val),
            None => PathBuf::from(env::var_os("HOME").unwrap()).join(".config"),
        }.join("senior/config.toml"));
    }

    let config = match cli.config.as_ref().unwrap().is_file() {
        true => toml::from_str(&fs::read_to_string(cli.config.as_ref().unwrap()).expect("Unable to read file!")).unwrap(),
        false => Config::default(&cli),
    };

    /*
    if cli.store == None {
        cli.store = Some(match config.stores.is_empty() {
            true => String::from("main"),
            false => config.stores
        });
    }
    */

    println!("{:?}", config);

    //let config: Config = toml::from_str()

    /*
    let main = StoreConfig {
        privkey: PathBuf::from("/home/geher/.ssh/id_ed25519_henkenet"),
        age_backend: Some(String::from("rage")),
    };

    let other = StoreConfig {
        privkey: PathBuf::from("/home/geher/.ssh/huso"),
        age_backend: None,
    };

    let mut stores = HashMap::new();
    stores.insert(String::from("main"), main);
    stores.insert(String::from("other"), other);

    let config = Config {
        age_backend: String::from("age"),
        stores: stores,
    };

    let toml = toml::to_string(&config).unwrap();
    println!("{}", toml);
    */
}
