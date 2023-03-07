use std::path::PathBuf;
use std::{env, fs};
use std::process::{Command, Stdio};
use std::ffi::{OsString, OsStr};
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use which::which;
use tempdir::TempDir;
use base32;
use thotp;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// alias for the store; default: "main", or the only existing one,
    ///                      or for senior clone the name of the repository
    #[arg(short, long)]
    store: Option<String>,

    /// the age backend to use; default: rage, age
    #[arg(long)]
    age: Option<String>,

    /// the command to run; "show" if omitted
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
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
        #[arg(long)]
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

        /// name of te password file or directory
        #[arg(index = 1)]
        name: String,
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

fn find_age_backend() -> String {
    let known_backends = ["rage", "age"];
    for backend in known_backends {
        if let Ok(_) = which(backend) {
            return String::from(backend);
        }
    }
    panic!("Could not find an age backend!");
}

// the store is either the only directory in the senior directory, or "main"
fn cli_store_and_dir(cli: &mut Cli, senior_dir: &PathBuf) -> PathBuf {
    if cli.store == None {
        cli.store = Some(if senior_dir.is_dir() {
            let mut entries = senior_dir.read_dir().expect("Could not read the senior directory").filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir());
            match (entries.next(), entries.next()) {
                (Some(entry), None) => entry.unwrap().file_name().into_string().unwrap(),
                _ => String::from("main"),
            }
        } else {
            String::from("main")
        });
    }

    senior_dir.join(cli.store.as_ref().unwrap())
}

fn init_identity_file_and_recipient(cli: &Cli, identity: Option<String>) -> (PathBuf, String, TempDir)  {
    let tmp_dir = TempDir::new("senior-keygen").expect("Could not create a temporary directory.");

    // TODO: Support password protected identities
    let (identity_file_src, recipient) = match &identity {
        Some(path_string) => {
            let pathbuf = PathBuf::from(path_string);
            assert!(pathbuf.is_file(), "Supplied identity path is not a file");
            let content = fs::read_to_string(&pathbuf).expect("Could not read identity file");
            let pubkey = if content.contains("SSH PRIVATE KEY") {
                let command = Command::new("ssh-keygen").args(["-y", "-f", &path_string]).output().expect("Could not run ssh-keygen to get public key");
                String::from_utf8(command.stdout).expect("UTF-8 conversion error")
            } else {
                match content.find("public key: ") {
                    Some(start_index) => {
                        let substring = &content[(start_index + "public key: ".len())..];
                        match substring.find("\n") {
                            Some(end_index) => String::from(&substring[..end_index]),
                            None => String::from(substring),
                        }
                    },
                    None => panic!("Cannot read public key from identity file"),
                }
            };
            (pathbuf, pubkey)
        },
        None => {
            let identity_file = tmp_dir.path().join("identity");
            let mut age_keygen = cli.age.as_ref().unwrap().clone();
            age_keygen.push_str("-keygen");
            let command = Command::new(OsString::from(age_keygen)).args(["-o", identity_file.to_str().unwrap()]).output().expect("Could not generate key-pair");
            let output = String::from_utf8_lossy(&command.stderr);
            (identity_file, String::from(&output.trim()["Public key: ".len()..]))
        },
    };

    (identity_file_src, recipient, tmp_dir)
}

fn init(mut cli: Cli, senior_dir: PathBuf, identity: Option<String>, mut recipient_alias: Option<String>) {
    let store_dir = cli_store_and_dir(&mut cli, &senior_dir);
    assert!(!store_dir.exists(), "Store \"{}\" already exists in directory {}. Remove it first or use a different store with the -s flag.", cli.store.as_ref().unwrap(), store_dir.display());

    let (identity_file_src, recipient, tmp_dir) = init_identity_file_and_recipient(&cli, identity);

    // set up default values
    if recipient_alias == None {
        recipient_alias = Some(env::var_os("USER").expect("Could not get the username. Please manually supply a recipient-alias.").into_string().unwrap());
    }

    let recipients_dir = store_dir.join(".recipients");
    let recipients_main = recipients_dir.join("main.txt");
    //let recipients_request_dir = store_dir.join(".recipients-request");
    let gitignore = store_dir.join(".gitignore");
    let identity_file = store_dir.join(".identity.txt");
    // TODO: .gitattributes file

    fs::create_dir_all(recipients_dir).expect("Could not create .recipients directory");
    //fs::create_dir_all(recipients_request_dir).expect("Could not create .recipients-request directory");
    fs::copy(identity_file_src, identity_file).expect("Could not copy .identity file");
    drop(tmp_dir);
    let mut gitignore_file = File::create(gitignore).expect("Could not create gitignore file");
    gitignore_file.write_all(b"/.identity.*\n").expect("Could not write gitignore file");
    let mut recipients_main_file = File::create(recipients_main).expect("Could not create recipients main file");
    write!(recipients_main_file, "# {}\n{}\n", recipient_alias.unwrap(), recipient).expect("Could not write recipients main file");
    println!("Created {}", store_dir.display());
}

fn git_clone(mut cli: Cli, senior_dir: PathBuf, address: String, identity: Option<String>) {
    if cli.store == None {
        let mut store = address.rsplit('/').next().unwrap().to_string();
        store.truncate(store.len() - 4);
        cli.store = Some(store);
    }
    let store_dir = senior_dir.join(cli.store.as_ref().unwrap());
    assert!(!store_dir.exists(), "Store \"{}\" already exists in directory {}. Remove it first or use a different store with the -s flag.", cli.store.as_ref().unwrap(), store_dir.display());

    let (identity_file_src, recipient, tmp_dir) = init_identity_file_and_recipient(&cli, identity);
    let identity_file = store_dir.join(".identity.txt");

    // set up and clone
    fs::create_dir_all(senior_dir).expect("Could not create senior directory");
    let status = Command::new("git").args(["clone", &address, store_dir.to_str().unwrap()]).status().expect("Could not run git");
    assert!(status.success(), "Error when running git clone");
    fs::copy(identity_file_src, identity_file).expect("Could not copy .identity file");
    drop(tmp_dir);

    let recipient_alias = env::var_os("USER").unwrap_or("alias_of_recipient".into());

    println!("Cloned to {}", store_dir.display());
    println!("Tell an owner of the store to add you to the recipients. For this they should run the following command:");
    println!("senior -s {} add-recipient {} {}", cli.store.as_ref().unwrap(), recipient, recipient_alias.to_str().unwrap());
    println!("Note that their store name might differ.");
}

fn get_editor() -> OsString {
    match env::var_os("EDITOR") {
        Some(editor) => editor,
        None => {
            let editors = ["nvim", "vim", "emacs", "nano", "vi"];
            for editor in editors {
                if let Ok(_) = which(editor) {
                    return OsString::from(editor);
                }
            }
            panic!("Please set the EDITOR environment variable");
        }
    }
}

fn recipients_args(store_dir: &PathBuf) -> Vec<OsString> {
    let recipients_dir = store_dir.join(".recipients");
    let mut args = vec![];
    for recipient in recipients_dir.read_dir().expect("Could not read the .recipients directory").filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_file()) {
        args.push(OsString::from("-R"));
        args.push(OsString::from(recipient.unwrap().path().into_os_string()));
    }
    args
}

// resolve symlinks even if the end of the path does not exist
fn canonicalize(path: PathBuf) -> PathBuf {
    if path.exists() {
        path.canonicalize().unwrap().to_path_buf()
    } else {
        let filename = path.file_name().unwrap();
        let parent = path.parent().unwrap().to_path_buf();
        let parent = canonicalize(parent);
        parent.join(filename)
    }
}

fn edit(mut cli: Cli, senior_dir: PathBuf, name: String) {
    let mut store_dir = cli_store_and_dir(&mut cli, &senior_dir);
    assert!(store_dir.exists(), "The store directory {} does not exist", store_dir.display());

    let mut name_age = name.clone();
    name_age.push_str(".age");
    let agefile = canonicalize(store_dir.join(&name_age));
    cli.store = Some(agefile.strip_prefix(&senior_dir).expect("Path is outside of the senior directory").iter().next().unwrap().to_str().unwrap().into());
    store_dir = senior_dir.join(cli.store.as_ref().unwrap());

    let mut entry_is_new = true;

    // decrypt if it exists
    let identity_file = store_dir.join(".identity.txt");
    let mut name_txt = name.clone();
    name_txt.push_str(".txt");
    let name_txt = PathBuf::from(name_txt);
    let name_txt = name_txt.file_name().unwrap();
    let tmp_dir = TempDir::new("senior").expect("Could not create temporary directory");
    let tmpfile_txt = tmp_dir.path().join(name_txt);
    if agefile.is_file() {
        entry_is_new = false;
        let status = Command::new(cli.age.as_ref().unwrap()).args(["-d", "-i", identity_file.to_str().unwrap(), "-o", tmpfile_txt.to_str().unwrap(), agefile.to_str().unwrap()]).status().expect("Could not run age");
        assert!(status.success(), "Error when decrypting file");
    }

    // save content for comparison
    let old_content = match entry_is_new {
        true => vec![],
        false => fs::read(&tmpfile_txt).expect("Could not read decrypted file"),
    };

    // edit
    let editor = get_editor();
    Command::new(&editor).args([&tmpfile_txt]).status().expect("Could not edit file");

    // compare
    if !tmpfile_txt.exists() {
        println!("No file created");
        return;
    }
    let new_content = fs::read(&tmpfile_txt).expect("Could not read edited file");
    if old_content == new_content {
        println!("File is unchanged");
        return;
    }

    // create parent directories
    fs::create_dir_all(agefile.parent().unwrap()).expect("Could not create parent directory");

    // encrypt
    Command::new(cli.age.as_ref().unwrap()).args([OsString::from("-e"), OsString::from("-o"), OsString::from(&agefile)]).args(recipients_args(&store_dir)).arg(tmpfile_txt.into_os_string()).status().expect("Could not encrypt file");
    drop(tmp_dir);

    // check if we use git
    if Command::new("git").args(["-C", store_dir.to_str().unwrap(), "rev-parse"]).output().expect("Could not run git rev-parse").status.code().expect("git rev-parse terminated by signal") != 0 { return; }
    // git add, commit
    Command::new("git").args(["-C", store_dir.to_str().unwrap(), "add", agefile.to_str().unwrap()]).status().expect("Could not run git add");
    let message = format!("{} password for {} using {}", if entry_is_new { "Add" } else { "Edit" }, name, editor.to_str().unwrap());
    Command::new("git").args(["-C", store_dir.to_str().unwrap(), "commit", "-m", &message]).status().expect("Could not run git add");
    println!("Do not forget to senior -s {} git push", cli.store.unwrap());
}

fn show(mut cli: Cli, senior_dir: PathBuf, clip: bool, key: Option<String>, name: Option<String>) {
    let mut store_dir = cli_store_and_dir(&mut cli, &senior_dir);
    assert!(store_dir.exists(), "The store directory {} does not exist", store_dir.display());

    let name = match name {
        None => {
            Command::new("tree").args([&store_dir]).status().expect("Could not list directory");
            return;
        },
        Some(name) => name,
    };

    fn first_line(s: &str) -> &str {
        s.split("\n").next().unwrap()
    }

    let mut name_age = name.clone();
    name_age.push_str(".age");
    let mut agefile = store_dir.join(&name_age);
    assert!(agefile.exists(), "The password does not exist");

    agefile = agefile.canonicalize().unwrap();
    cli.store = Some(agefile.strip_prefix(&senior_dir).expect("Path is outside of the senior directory").iter().next().unwrap().to_str().unwrap().into());
    store_dir = senior_dir.join(cli.store.as_ref().unwrap());

    // decrypt
    let identity_file = store_dir.join(".identity.txt");
    let command = Command::new(cli.age.as_ref().unwrap()).args(["-d", "-i", identity_file.to_str().unwrap(), agefile.to_str().unwrap()]).output().expect("Could not run age");
    let output = String::from_utf8_lossy(&command.stdout);
    let (to_print, to_clip) = match key {
        // show everything, clip the first line
        None => {
            (String::from(output.trim_end()), String::from(first_line(&output)))
        },
        // show the value for the key, clip it
        Some(key) => {
            match key.trim() {
                "password" => (String::from(first_line(&output)), String::from(first_line(&output))),
                mut key => {
                    if key == "otp" {
                        key = "otpauth";
                    }
                    let start_index = output.find(&format!("{}:", &key)).expect("Could not find key");
                    let substring = &output[(start_index + key.len() + 1)..];
                    let value = match substring.find("\n") {
                        Some(end_index) => &substring[..end_index],
                        None => substring,
                    };

                    let mut value = value.trim();

                    if key == "otpauth" {
                        assert!(value.contains("secret="), "Could not find secret in otp string");
                        value = value.split_once("secret=").expect("Could not find secret in otp string").1;
                        value = value.split(&['=', '&']).next().unwrap();
                        let otp = thotp::otp(&base32::decode(base32::Alphabet::RFC4648 { padding: false }, value).unwrap(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30).unwrap();
                        (otp.clone(), otp.clone())
                    } else {
                        (String::from(value), String::from(value))
                    }
                },
            }
        },
    };
    println!("{}", to_print);
    // TODO: support X11, Android, Windows
    if clip {
        Command::new("wl-copy").args(["-o", &to_clip]).status().expect("Could not use clipboard");
    }
}

fn remove(mut cli: Cli, senior_dir: PathBuf, recursive: bool, mut name: String) {
    let store_dir = cli_store_and_dir(&mut cli, &senior_dir);
    assert!(store_dir.exists(), "The store directory {} does not exist", store_dir.display());
    let dir_path = store_dir.join(&name);
    name.push_str(".age");
    let file_path = store_dir.join(name);
    if recursive && dir_path.is_dir() {
        println!("Removing {}", dir_path.display());
        fs::remove_dir_all(dir_path).expect("Could not recursively remove the directory");
    } else if file_path.is_file() || file_path.is_symlink() {
        println!("Removing {}", file_path.display());
        fs::remove_file(file_path).expect("Could not remove the file");
    } else if dir_path.is_dir() {
        panic!("Use -r for directories");
    } else {
        panic!("No such file or directory");
    }
}

fn git_command(mut cli: Cli, senior_dir: PathBuf, mut args: Vec<String>) {
    let store_dir = cli_store_and_dir(&mut cli, &senior_dir);
    assert!(store_dir.exists(), "The store directory {} does not exist", store_dir.display());

    args.insert(0, String::from("-C"));
    args.insert(1, String::from(store_dir.to_str().unwrap()));
    Command::new("git").args(args).status().expect("Could not run the git command");
}

// returns whether git is used
fn reencrypt_helper(cli: &Cli, store_dir: PathBuf) -> bool {
    fn reencrypt_recursive(cli: &Cli, cur_dir: PathBuf, identity_file: &str, recipients_args: &Vec<OsString>, tmp_dir: &PathBuf, collect: &mut Vec<PathBuf>) {
        for entry in cur_dir.read_dir().expect("Could not read directory").filter(|entry| !entry.as_ref().unwrap().file_name().to_str().unwrap().starts_with('.')) {
            let filetype = entry.as_ref().unwrap().file_type().unwrap();
            let entry = entry.as_ref().unwrap().path();
            if filetype.is_dir() {
                reencrypt_recursive(cli, entry, identity_file, recipients_args, tmp_dir, collect);
                continue;
            } else if !filetype.is_file() || entry.extension() != Some(OsStr::new("age")) {
                continue;
            }


            let tmp_agefile = tmp_dir.join(entry.file_name().unwrap());
            let decrypt = Command::new(cli.age.as_ref().unwrap()).args(["-d", "-i", identity_file, entry.to_str().unwrap()]).stdout(Stdio::piped()).spawn().unwrap();
            let mut encrypt = Command::new(cli.age.as_ref().unwrap()).arg("-e").args(recipients_args).args(["-o", tmp_agefile.to_str().unwrap()]).stdin(Stdio::from(decrypt.stdout.unwrap())).spawn().unwrap();
            let output = encrypt.wait().unwrap();
            if output.success() {
                fs::copy(tmp_agefile, &entry).expect("Could not copy new agefile over the old one");
                collect.push(entry);
            } else {
                eprintln!("Reencrypted {} with error!", entry.to_str().unwrap());
            }
        }
    }

    let tmp_dir = TempDir::new("senior").expect("Could not create a temporary directory.").into_path();
    let identity_file = store_dir.join(".identity.txt");
    let recipients = recipients_args(&store_dir);
    let mut collect = vec![];
    reencrypt_recursive(&cli, store_dir.clone(), identity_file.to_str().unwrap(), &recipients, &tmp_dir, &mut collect);

    // check if we use git
    if Command::new("git").args(["-C", store_dir.to_str().unwrap(), "rev-parse"]).output().expect("Could not run git rev-parse").status.code().expect("git rev-parse terminated by signal") != 0 { return false; }
    // git add, commit
    Command::new("git").args(["-C", store_dir.to_str().unwrap(), "add"]).args(collect).status().expect("Could not run git add");
    true
}

fn add_recipient(mut cli: Cli, senior_dir: PathBuf, public_key: String, alias: String) {
    let store_dir = cli_store_and_dir(&mut cli, &senior_dir);
    assert!(store_dir.exists(), "The store directory {} does not exist", store_dir.display());

    let recipients_dir = store_dir.join(".recipients");

    // check if public_key is not already a recipient
    for recipient in recipients_dir.read_dir().expect("Could not read the .recipients directory").filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_file()) {
        let content = fs::read_to_string(recipient.as_ref().unwrap().path()).expect("Could not read recipients file");
        for line in content.lines() {
            if line.trim().starts_with('#') {
                continue;
            }
            if line.contains(&public_key) {
                println!("Recipient {} already in {}", &public_key, recipient.unwrap().path().display());
                return;
            }
        }
    }

    // choose the only existing file or use main.txt
    let mut entries = recipients_dir.read_dir().expect("Could not read the .recipients directory").filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir());
    let recipients_file = match (entries.next(), entries.next()) {
        (Some(entry), None) => entry.unwrap().path(),
        _ => recipients_dir.join("main.txt"),
    };
    // add new public_key to the recipients
    let mut recipients_main_file = File::options().create(true).append(true).open(&recipients_file).expect("Could not create/edit/open the main recipients file");
    write!(recipients_main_file, "# {}\n{}\n", &alias, &public_key).expect("Could not write recipients main file");

    if !reencrypt_helper(&cli, store_dir.clone()) { return; }

    Command::new("git").args(["-C", store_dir.to_str().unwrap(), "add", recipients_file.to_str().unwrap()]).status().expect("Could not run git add");
    let message = format!("Reencrypted store for {}", &alias);
    Command::new("git").args(["-C", store_dir.to_str().unwrap(), "commit", "-m", &message]).status().expect("Could not run git add");
}

fn reencrypt(mut cli: Cli, senior_dir: PathBuf) {
    let store_dir = cli_store_and_dir(&mut cli, &senior_dir);
    assert!(store_dir.exists(), "The store directory \"{}\" does not exist", cli.store.as_ref().unwrap());

    if !reencrypt_helper(&cli, store_dir.clone()) { return; }
    Command::new("git").args(["-C", store_dir.to_str().unwrap(), "commit", "-m", "Reencrypted store"]).status().expect("Could not run git add");
}

fn main() {
    let mut cli = Cli::parse();

    let senior_dir = match env::var_os("XDG_DATA_HOME") {
        Some(val) => PathBuf::from(val),
        None => PathBuf::from(env::var_os("HOME").unwrap()).join(".local/share"),
    }.join("senior/");

    if cli.age == None {
        cli.age = Some(find_age_backend());
    }

    match &cli.command {
        Commands::Init { identity, recipient_alias, } => init(cli.clone(), senior_dir, identity.clone(), recipient_alias.clone()),
        Commands::Clone { address, identity } => git_clone(cli.clone(), senior_dir, address.clone(), identity.clone()),
        Commands::Edit { name, } => edit(cli.clone(), senior_dir, name.clone()),
        Commands::Show { clip, key, name, } => show(cli.clone(), senior_dir, *clip, key.clone(), name.clone()),
        Commands::Git { args, } => git_command(cli.clone(), senior_dir, args.clone()),
        Commands::AddRecipient { public_key, alias, } => add_recipient(cli.clone(), senior_dir, public_key.clone(), alias.clone()),
        Commands::PrintDir => println!("{}", cli_store_and_dir(&mut cli.clone(), &senior_dir).display()),
        Commands::Reencrypt => reencrypt(cli.clone(), senior_dir),
        Commands::Rm { recursive, name, } => remove(cli.clone(), senior_dir, *recursive, name.clone()),
    }
}
