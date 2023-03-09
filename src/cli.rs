use clap::{Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// alias for the store; default: "main", or the only existing one,
    ///                      or for senior clone the name of the repository
    #[arg(short, long)]
    pub store: Option<String>,

    /// the age backend to use; default: rage, age
    #[arg(long)]
    pub age: Option<String>,

    /// the command to run; "show" if omitted
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// initialises a new store
    Init {
        /// path of the identity used for decrypting; will be generated if none is supplied
        #[arg(long = "identity")]
        identity: Option<String>,

        /// alias for recipient; defaults to the username
        #[arg(long = "recipient-alias")]
        recipient_alias: Option<String>,
    },

    /// clones a store from a git repository
    Clone {
        /// address of the remote git repository
        #[arg(index = 1)]
        address: String,

        /// path of the identity used for decrypting; will be generated if none is supplied
        #[arg(short, long)]
        identity: Option<String>,
    },

    /// edit/create a password
    Edit {
        /// name of the password file
        #[arg(index = 1)]
        name: String,
    },

    /// show the password
    Show {
        /// also add the value to the clipboard
        #[arg(short, long)]
        clip: bool,

        /// show only this key; "password" shows the first line; "otp" generates the one-time
        /// password
        #[arg(short, long)]
        key: Option<String>,

        /// name of the password file
        #[arg(index = 1)]
        name: Option<String>,
    },

    /// remove a password
    Rm {
        /// must be used for directories
        #[arg(short, long)]
        recursive: bool,

        /// name of the password file or directory
        #[arg(index = 1)]
        name: String,
    },

    /// move a password
    Mv {
        /// old name of the password file or directory
        #[arg(index = 1)]
        old_name: String,

        /// new name of the password file or directory
        #[arg(index = 2)]
        new_name: String,
    },

    /// show the store's directory path
    PrintDir,

    /// run git commands in the specified store
    Git {
        #[arg(allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// add recipient
    AddRecipient {
        /// public key of the new recipient
        #[arg(index = 1)]
        public_key: String,

        /// alias of the new recipient
        #[arg(index = 2)]
        alias: String,
    },

    /// reencrypt the entire store
    Reencrypt,
}

