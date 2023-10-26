// #![feature(exit_status_error)]
#![allow(unstable_name_collisions)]

pub mod cli;

use std::collections::HashMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, str::FromStr};

use age::secrecy::{ExposeSecret, Secret};
use age::{self, ssh};
use atty::Stream;
use clap::Parser;
use interprocess::local_socket::{LocalSocketStream, NameTypeSupport};
use sysinfo::{System, SystemExt};
use tempdir::TempDir;
use which::which;

use cli::{Cli, CliCommand};

trait ExitOk {
    fn exit_ok(&self) -> Result<(), Box<dyn Error>>;
}
impl ExitOk for ExitStatus {
    fn exit_ok(&self) -> Result<(), Box<dyn Error>> {
        assert!(self.success(), "Non-zero returncode!");
        Ok(())
    }
}

enum DisplayServer {
    Wayland,
    X11,
    Termux,
    Wsl,
    Darwin, // macOS
    Windows,
}

fn get_display_server() -> DisplayServer {
    // WSL
    let wsl_file = Path::new("/proc/version");
    if wsl_file.is_file() {
        if let Ok(proc_version) = fs::read_to_string(wsl_file) {
            if proc_version.to_lowercase().contains("microsoft") {
                return DisplayServer::Wsl;
            }
        }
    }
    // Wayland
    if env::var_os("WAYLAND_DISPLAY").is_some() {
        return DisplayServer::Wayland;
    // X11
    } else if env::var_os("DISPLAY").is_some() {
        return DisplayServer::X11;
    // Darwin
    } else if which::which("uname").is_ok()
        && std::str::from_utf8(
            &Command::new("uname")
                .output()
                .expect("Could not run `uname`!")
                .stdout,
        )
        .expect("Could not convert output of `uname` to UTF8!")
            == "Darwin"
    {
        return DisplayServer::Darwin;
    // Termux
    } else if let Some(v) = env::var_os("PREFIX") {
        if v.into_string().unwrap().contains("termux") {
            return DisplayServer::Termux;
        }
    }
    // Default: Windows
    DisplayServer::Windows
}

fn agent_socket_name() -> &'static str {
    use NameTypeSupport::*;
    match NameTypeSupport::query() {
        OnlyPaths => "/tmp/senior-agent.sock",
        OnlyNamespaced | Both => "@senior-agent.sock",
    }
}

// returns Ok(None) if the connection to the agent fails (because it is probably not running)
// returns Ok(None) if the agent does not have the password
fn agent_get_passphrase(key: &str) -> Result<Option<String>, Box<dyn Error>> {
    let mut buffer = String::new();
    let conn = match LocalSocketStream::connect(agent_socket_name()) {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Ok(None),
        x => x?,
    };
    let mut conn = BufReader::new(conn);
    conn.get_mut()
        .write_all(format!("r {}\n", key.replace('\\', r"\\").replace(' ', r"\ ")).as_bytes())?;
    conn.read_line(&mut buffer)?;
    // remove trailing newline
    buffer.pop();
    match &buffer[0..1] {
        "o" => {
            buffer.drain(..3);
            Ok(Some(buffer))
        }
        _ => Ok(None),
    }
}

fn agent_set_passphrase(key: &str, passphrase: &str) -> Result<(), Box<dyn Error>> {
    let agent_is_running = System::new_all()
        .processes_by_exact_name("senior-agent")
        .next()
        .and(Some(true))
        .unwrap_or(false);
    let mut once = true;
    let conn = loop {
        match LocalSocketStream::connect(agent_socket_name()) {
            Err(e) if once && !agent_is_running && e.kind() == io::ErrorKind::ConnectionRefused => {
                once = false;
                let child = Command::new("senior-agent")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .spawn()?;
                let mut child_stdout = String::new();
                BufReader::new(child.stdout.unwrap()).read_line(&mut child_stdout)?;
                child_stdout.pop();
                if child_stdout.starts_with("Ready") {
                    continue;
                } else {
                    return Err(format!("senior-agent: {}", &child_stdout).into());
                }
            }
            x => break x?,
        }
    };
    let mut conn = BufReader::new(conn);
    conn.get_mut().write_all(
        format!(
            "w {} {}\n",
            key.replace('\\', r"\\").replace(' ', r"\ "),
            passphrase
        )
        .as_bytes(),
    )?;
    Ok(())
}

// use pinentry if there is no tty
fn prompt_password(prompt: &str) -> Result<String, Box<dyn Error>> {
    fn read_ok(
        stdout_reader: &mut BufReader<ChildStdout>,
        pinentry_program: &str,
    ) -> Result<(), Box<dyn Error>> {
        let mut buffer = String::new();
        stdout_reader.read_line(&mut buffer)?;
        if buffer.starts_with("OK") {
            Ok(())
        } else {
            buffer.pop();
            Err(format!("{}: {}", pinentry_program, &buffer).into())
        }
    }

    if atty::is(Stream::Stdout) {
        Ok(rpassword::prompt_password(format!("{}: ", prompt))?)
    } else {
        // People are used to pass and gnupg; Get their preferred pinentry program from their
        // gpg-agent.conf
        let gnupg_dir =
            env::var_os("GNUPGHOME").map_or_else(|| home().join(".gnupg"), PathBuf::from);
        let gpgagent_file = gnupg_dir.join("gpg-agent.conf");
        let pinentry_program = if gpgagent_file.exists() && gpgagent_file.canonicalize()?.is_file()
        {
            let gpgagent_conf = BufReader::new(File::open(gpgagent_file)?);
            gpgagent_conf
                .lines()
                .find(|l| {
                    l.as_ref()
                        .expect("Cannot read gpg-agent.conf")
                        .starts_with("pinentry-program")
                })
                .map_or("pinentry".to_owned(), |l| {
                    l.expect("Cannot read line")["pinentry-program".len()..]
                        .trim()
                        .to_owned()
                })
        } else {
            "pinentry".to_owned()
        };
        let child = Command::new(&pinentry_program)
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()?;
        let mut stdout_reader = BufReader::new(child.stdout.unwrap());
        let mut stdin_writer = child.stdin.unwrap();
        read_ok(&mut stdout_reader, &pinentry_program)?;
        stdin_writer.write_all(format!("SETPROMPT {}\n", prompt).as_bytes())?;
        read_ok(&mut stdout_reader, &pinentry_program)?;
        stdin_writer.write_all("GETPIN\n".as_bytes())?;
        let mut pass = String::new();
        stdout_reader.read_line(&mut pass)?;
        pass.pop();
        pass.drain(0..2);
        read_ok(&mut stdout_reader, &pinentry_program)?;
        stdin_writer.write_all(b"BYE\n")?;
        read_ok(&mut stdout_reader, &pinentry_program)?;
        Ok(pass)
    }
}

// return value: second value in tuple is whether the agent was used
fn get_or_ask_passphrase(
    key: &str,
    try_counter: &mut u32,
) -> Result<(String, bool), Box<dyn Error>> {
    let prompt = format!("Enter passphrase to unlock {}", key);
    *try_counter += 1;
    Ok(if *try_counter == 1 {
        match agent_get_passphrase(key)? {
            None => (prompt_password(&prompt)?, false),
            Some(p) => (p, true),
        }
    } else {
        (prompt_password(&prompt)?, false)
    })
}

fn ask_passphrase_twice() -> std::io::Result<String> {
    loop {
        let pass1 = rpassword::prompt_password("Enter a passphrase: ")?;
        let pass2 = rpassword::prompt_password("Confirm passphrase: ")?;
        if pass1 == pass2 {
            break Ok(pass1);
        } else {
            eprintln!("Passphrases did not match!");
        }
    }
}

// returns the public key
fn setup_identity(store_dir: &Path, identity: Option<String>) -> Result<String, Box<dyn Error>> {
    match identity {
        None => {
            let passphrase = ask_passphrase_twice()?;
            let use_passphrase = !passphrase.is_empty();
            let identity_file = store_dir.join(if use_passphrase {
                ".identity.age"
            } else {
                ".identity.txt"
            });
            let key = age::x25519::Identity::generate();
            let pubkey = key.to_public().to_string();
            fs::create_dir_all(store_dir)?;
            let mut write_to = File::create(identity_file)?;
            if use_passphrase {
                let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase));
                let mut write_to = encryptor.wrap_output(&mut write_to).unwrap();
                writeln!(
                    write_to,
                    "# created: {}",
                    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                )?;
                writeln!(write_to, "# public key: {}", &pubkey)?;
                writeln!(write_to, "{}", key.to_string().expose_secret())?;
                write_to.finish()?;
            } else {
                writeln!(
                    write_to,
                    "# created: {}",
                    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                )?;
                writeln!(write_to, "# public key: {}", &pubkey)?;
                writeln!(write_to, "{}", key.to_string().expose_secret())?;
            }
            Ok(pubkey)
        }
        Some(keyfile) => {
            match age::IdentityFile::from_file(keyfile.clone()) {
                Ok(identity_file) => {
                    // unencrypted age identity file
                    match identity_file
                        .into_identities()
                        .first()
                        .ok_or("No identities in file.")?
                    {
                        age::IdentityFileEntry::Native(i) => {
                            println!("The supplied age identity is unencrypted. It is recommended to encrypt it with a passphrase.");
                            let passphrase = ask_passphrase_twice()?;
                            let use_passphrase = !passphrase.is_empty();
                            let identity_file = store_dir.join(if use_passphrase {
                                ".identity.age"
                            } else {
                                ".identity.txt"
                            });
                            fs::create_dir_all(store_dir)?;
                            if use_passphrase {
                                let mut keyfile_handle = File::open(&keyfile)?;
                                let mut keyfile_content = vec![];
                                keyfile_handle.read_to_end(&mut keyfile_content)?;
                                let encryptor =
                                    age::Encryptor::with_user_passphrase(Secret::new(passphrase));
                                let mut write_to =
                                    encryptor.wrap_output(File::create(&identity_file)?)?;
                                write_to.write_all(&keyfile_content)?;
                                write_to.finish()?;
                            } else {
                                fs::copy(&keyfile, identity_file)?;
                            }
                            Ok(i.to_public().to_string())
                        }
                    }
                }
                Err(_) => {
                    // three possibilities left:
                    // 1. encrypted ssh key
                    // 2. unencrypted ssh key
                    // 3. encrypted age file
                    let mut keyfile_bufread = BufReader::new(File::open(&keyfile)?);
                    match ssh::Identity::from_buffer(
                        &mut keyfile_bufread,
                        Some(keyfile.to_string()),
                    ) {
                        Ok(i) => match i {
                            // ssh key
                            ssh::Identity::Encrypted(_) => loop {
                                let passphrase =
                                    rpassword::prompt_password("Unlock the supplied ssh key: ")?;
                                let mut keygen_command = Command::new("ssh-keygen")
                                    .args(["-y", "-P", &passphrase, "-f", &keyfile])
                                    .output()?;
                                if keygen_command.status.success() {
                                    // remove newline
                                    keygen_command.stdout.pop();
                                    fs::create_dir_all(store_dir)?;
                                    fs::copy(&keyfile, store_dir.join(".identity.pass.ssh"))?;
                                    break Ok(String::from_utf8(keygen_command.stdout)?);
                                } else {
                                    eprintln!("Could not produce public key! Is the passphrase correct? Please try again.");
                                }
                            },
                            ssh::Identity::Unencrypted(_) => {
                                let mut gen_pubkey = Command::new("ssh-keygen")
                                    .args(["-y", "-f", &keyfile])
                                    .output()?;
                                gen_pubkey.status.exit_ok()?;
                                // remove newline
                                gen_pubkey.stdout.pop();
                                println!("Supplied ssh key is unencrypted. It is recommended to encrypt it with a passphrase.");
                                let passphrase = ask_passphrase_twice()?;
                                let use_passphrase = !passphrase.is_empty();
                                let identity_file = store_dir.join(if use_passphrase {
                                    ".identity.pass.ssh"
                                } else {
                                    ".identity.ssh"
                                });
                                fs::create_dir_all(store_dir)?;
                                fs::copy(&keyfile, &identity_file)?;
                                if use_passphrase {
                                    Command::new("ssh-keygen")
                                        .args(["-p", "-f"])
                                        .arg(&identity_file)
                                        .args(["-N", &passphrase])
                                        .status()?
                                        .exit_ok()?;
                                }
                                Ok(String::from_utf8(gen_pubkey.stdout)?)
                            }
                            ssh::Identity::Unsupported(k) => Err(format!(
                                "Supplied ssh identity key type is not supported by age: {:?}",
                                k
                            )
                            .into()),
                        },
                        Err(_) => loop {
                            // encrypted age file, hopefully
                            let decryptor = match age::Decryptor::new(File::open(&keyfile)?)? {
                                age::Decryptor::Passphrase(d) => d,
                                _ => return Err("The supplied identity file should be encrypted with a passphrase, not with recipients/identities!".into()),
                            };
                            let pass =
                                rpassword::prompt_password("Unlock the supplied identity file: ")?;
                            let reader =
                                match decryptor.decrypt(&Secret::new(pass.clone()), Some(32)) {
                                    Ok(r) => r,
                                    Err(age::DecryptError::DecryptionFailed) => {
                                        eprintln!(
                                        "Decryption failed! Wrong passphrase? Please try again."
                                    );
                                        continue;
                                    }
                                    Err(e) => return Err(Box::new(e)),
                                };
                            let pubkey =
                                match age::IdentityFile::from_buffer(BufReader::new(reader))?
                                    .into_identities()
                                    .first()
                                    .ok_or("No identities in file.")?
                                {
                                    age::IdentityFileEntry::Native(i) => i.to_public().to_string(),
                                };
                            fs::create_dir_all(store_dir)?;
                            fs::copy(&keyfile, store_dir.join(".identity.age"))?;
                            break Ok(pubkey);
                        },
                    }
                }
            }
        }
    }
}

fn init_helper(
    store_dir: &Path,
    identity: Option<String>,
    recipient_alias: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // set up default values
    let recipient_alias = recipient_alias.unwrap_or_else(|| {
        env::var_os("USER")
            .unwrap_or_else(|| {
                env::var_os("USERNAME")
                    .expect("Could not get the username. Please manually supply a recipient-alias.")
            })
            .into_string()
            .unwrap()
    });

    let pubkey = setup_identity(store_dir, identity)?;

    let recipients_dir = store_dir.join(".recipients");
    let recipients_main = recipients_dir.join("main.txt");
    let gitignore = store_dir.join(".gitignore");
    // TODO: .gitattributes file

    fs::create_dir_all(recipients_dir)?;
    let mut gitignore_file = File::create(gitignore)?;
    gitignore_file.write_all(b"/.identity.*\n")?;
    let mut recipients_main_file = File::create(recipients_main)?;
    write!(recipients_main_file, "# {}\n{}\n", recipient_alias, pubkey)?;
    println!("Created {}", store_dir.display());
    Ok(())
}

fn init(
    store_dir: PathBuf,
    identity: Option<String>,
    recipient_alias: Option<String>,
) -> Result<(), Box<dyn Error>> {
    match init_helper(&store_dir, identity, recipient_alias) {
        Err(e) => {
            // cleanup
            if store_dir.is_dir() {
                if let Err(e) = fs::remove_dir_all(&store_dir) {
                    eprintln!("Error cleaning up {}! {}", store_dir.display(), e);
                }
            }
            Err(e)
        }
        Ok(()) => Ok(()),
    }
}

fn git_clone_helper(
    store_dir: &Path,
    identity: Option<String>,
    address: String,
) -> Result<(), Box<dyn Error>> {
    Command::new("git")
        .args(["clone", &address])
        .arg(store_dir)
        .status()?
        .exit_ok()?;
    let pubkey = setup_identity(store_dir, identity)?;

    let recipient_alias = env::var_os("USER").unwrap_or(OsString::from("<name of recipient>"));

    println!("Tell an owner of the store to add you to the recipients. For this they should run the following command:");
    println!(
        "senior -s {} add-recipient \"{}\" {}",
        store_dir.file_name().unwrap().to_str().unwrap(),
        &pubkey,
        recipient_alias.to_str().unwrap()
    );
    println!("Note that their store name might differ.");
    Ok(())
}

fn git_clone(
    store_dir: PathBuf,
    identity: Option<String>,
    address: String,
) -> Result<(), Box<dyn Error>> {
    match git_clone_helper(&store_dir, identity, address) {
        Err(e) => {
            // cleanup
            if store_dir.is_dir() {
                if let Err(e) = fs::remove_dir_all(&store_dir) {
                    eprintln!("Error cleaning up {}! {}", store_dir.display(), e);
                }
            }
            Err(e)
        }
        Ok(()) => Ok(()),
    }
}

// resolve symlinks even if the end of the path does not exist
fn canonicalise(path: &Path) -> std::io::Result<PathBuf> {
    if path.exists() {
        path.canonicalize()
    } else {
        let parent = path.parent().unwrap();
        let filename = path.file_name().unwrap_or(OsStr::new(".."));
        Ok(canonicalise(parent)?.join(filename))
    }
}

fn unlock_identity(
    identity_file: &Path,
    identities: &mut Vec<Box<dyn age::Identity>>,
) -> Result<(), Box<dyn Error>> {
    let mut try_counter = 0;
    match identity_file.extension().unwrap().to_str().unwrap() {
        "txt" => {
            // clear text identity
            let identities_native =
                age::IdentityFile::from_file(identity_file.to_str().unwrap().to_owned())?
                    .into_identities();
            for identity in identities_native {
                let age::IdentityFileEntry::Native(identity) = identity;
                identities.push(Box::new(identity) as Box<dyn age::Identity>);
            }
        }
        "age" => loop {
            // passphrase age encrypted identity
            let identity_decryptor = match age::Decryptor::new(File::open(identity_file)?)? {
                age::Decryptor::Passphrase(d) => d,
                _ => return Err(format!("The identity file {} should be encrypted with a passphrase, not with recipients/identities!", identity_file.display()).into()),
            };

            // for .identity.age the agent saves the string representation of the decrypted
            // identity, instead of the passphrase; this is done for faster decryption
            let (pass, pass_is_from_agent) =
                get_or_ask_passphrase(identity_file.to_str().unwrap(), &mut try_counter)?;
            if pass_is_from_agent {
                identities.push(
                    Box::new(age::x25519::Identity::from_str(&pass)?) as Box<dyn age::Identity>
                );
                break;
            }
            let reader = match identity_decryptor.decrypt(&Secret::new(pass.clone()), Some(32)) {
                Ok(r) => r,
                Err(age::DecryptError::DecryptionFailed) => {
                    eprintln!("Decryption failed! Wrong passphrase? Please try again.");
                    continue;
                }
                Err(e) => return Err(Box::new(e)),
            };
            let identities_native =
                age::IdentityFile::from_buffer(BufReader::new(reader))?.into_identities();
            let mut once = true;
            for identity in identities_native {
                let age::IdentityFileEntry::Native(identity) = identity;
                if once {
                    once = false;
                    agent_set_passphrase(
                        identity_file.to_str().unwrap(),
                        identity.to_string().expose_secret(),
                    )?
                };
                identities.push(Box::new(identity) as Box<dyn age::Identity>);
            }
            break;
        },
        "ssh" => {
            // ssh key (with or without passphrase)
            let identity = match ssh::Identity::from_buffer(
                BufReader::new(File::open(identity_file)?),
                Some(identity_file.to_str().unwrap().to_owned()),
            )? {
                ssh::Identity::Encrypted(k) => loop {
                    let (pass, pass_is_from_agent) =
                        get_or_ask_passphrase(identity_file.to_str().unwrap(), &mut try_counter)?;
                    match k.decrypt(Secret::new(pass.clone())) {
                        Ok(k) => {
                            if !pass_is_from_agent {
                                agent_set_passphrase(identity_file.to_str().unwrap(), &pass)?;
                            }
                            break k;
                        }
                        Err(age::DecryptError::KeyDecryptionFailed) => {
                            eprintln!("Decryption failed! Wrong passphrase? Please try again.");
                            continue;
                        }
                        Err(e) => return Err(Box::new(e)),
                    }
                },
                ssh::Identity::Unencrypted(k) => k,
                ssh::Identity::Unsupported(k) => {
                    return Err(format!(
                        "The ssh identity key type of {} is not supported by age! {:?}",
                        identity_file.display(),
                        k
                    )
                    .into())
                }
            };
            identities.push(Box::new(ssh::Identity::from(identity)) as Box<dyn age::Identity>);
        }
        _ => panic!(
            "Identity file with name {} not supported!",
            identity_file.file_name().unwrap().to_str().unwrap()
        ),
    };
    Ok(())
}

fn decrypt_password(
    identity_file: &Path,
    agefile: &Path,
    identities: &mut Vec<Box<dyn age::Identity>>,
) -> Result<age::stream::StreamReader<File>, Box<dyn Error>> {
    let password_decryptor = match age::Decryptor::new(File::open(agefile)?)? {
        age::Decryptor::Recipients(d) => d,
        _ => {
            return Err(format!(
            "The supplied age-file {} should be encrypted for recipients, not with a passphrase!",
            agefile.display()
        )
            .into())
        }
    };

    if identities.is_empty() {
        unlock_identity(identity_file, identities)?;
    }

    Ok(password_decryptor.decrypt(identities.iter().map(|i| i.as_ref()))?)
}

fn unlock(identity_file: &Path, check: bool) -> Result<(), Box<dyn Error>> {
    if check {
        match agent_get_passphrase(identity_file.to_str().unwrap())? {
            None => Err(format!("The identity file {} is not cached by senior-agent!", identity_file.display()).into()),
            Some(_) => Ok(()),
        }
    } else {
        unlock_identity(&identity_file, &mut vec![])
    }
}

fn get_editor() -> (OsString, Vec<&'static str>) {
    let mut editors = ["nvim", "vim", "emacs", "nano", "vi"].into_iter();
    let mut editor_args = HashMap::new();
    editor_args.insert(
        "nvim",
        vec![
            "-c",
            ":setlocal noswapfile nobackup nowritebackup noundofile shada=\"\"",
            "-c",
            "echomsg 'Editing password file--disabled leaky options!'",
        ],
    );
    editor_args.insert(
        "vim",
        vec![
            "-c",
            ":setlocal noswapfile nobackup nowritebackup noundofile viminfo=\"\"",
        ],
    );
    let editor = env::var_os("EDITOR").unwrap_or_else(|| loop {
        let candidate = editors
            .next()
            .expect("Cannot find editor! Please set the EDITOR environment variable.");
        if which(candidate).is_ok() {
            break OsString::from(candidate);
        }
    });
    let args = editor_args
        .remove(editor.to_str().unwrap())
        .unwrap_or(vec![]);
    (editor, args)
}

fn get_recipients_recursive(
    dir: &Path,
    recipients: &mut Vec<Box<dyn age::Recipient + Send>>,
) -> Result<(), Box<dyn Error>> {
    for child in dir.read_dir()? {
        let child = child?.path().canonicalize()?;
        if child.is_dir() {
            get_recipients_recursive(&child, recipients)?;
        } else if child.is_file() {
            let reader = BufReader::new(File::open(&child)?);
            for (i, line) in reader.lines().enumerate() {
                let line = line?;
                if line.starts_with('#') {
                    continue;
                }
                if line.starts_with("ssh") {
                    match ssh::Recipient::from_str(&line) {
                        Ok(r) => recipients.push(Box::new(r) as Box<dyn age::Recipient + Send>),
                        Err(e) => {
                            return Err(format!(
                                "Could not process ssh recipient in {}:{}!\n{:?}",
                                child.display(),
                                i + 1,
                                e
                            )
                            .into())
                        }
                    }
                } else {
                    match age::x25519::Recipient::from_str(&line) {
                        Ok(r) => recipients.push(Box::new(r) as Box<dyn age::Recipient + Send>),
                        Err(e) => {
                            return Err(format!(
                                "Could not process age recipient in {}:{}!\n{:?}",
                                child.display(),
                                i + 1,
                                e
                            )
                            .into())
                        }
                    }
                }
            }
        } else {
            panic!(
                "{} unsupported file type!\n{:?}",
                child.display(),
                child.metadata()?.file_type()
            );
        }
    }
    Ok(())
}

fn encrypt_password(
    recipients_dir: &Path,
    mut source: impl Read,
    target_file: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut recipients = vec![];
    get_recipients_recursive(recipients_dir, &mut recipients)?;
    let encryptor = age::Encryptor::with_recipients(recipients).ok_or(format!(
        "No recipients found in {}!",
        recipients_dir.display()
    ))?;
    let mut writer = encryptor.wrap_output(File::create(target_file)?)?;
    let mut content = vec![];
    source.read_to_end(&mut content)?;
    writer.write_all(&content)?;
    writer.finish()?;
    Ok(())
}

fn check_for_git(canon_store_dir: &Path) -> bool {
    which::which("git").map_or_else(
        |_| false,
        |v| {
            Command::new(v)
                .arg("-C")
                .arg(canon_store_dir)
                .arg("rev-parse")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .status()
                .expect("Could not run git rev-parse!")
                .success()
        },
    )
}

// use /dev/shm/ if available
fn tempdir() -> std::io::Result<TempDir> {
    let shm = Path::new("/dev/shm/");
    if shm.is_dir() {
        TempDir::new_in(shm, "senior")
    } else {
        TempDir::new("senior")
    }
}

// edit store_dir/name.age
// decrypt via identity_file
// encrypt via identity_file.parent()/.recipients/
fn edit(identity_file: PathBuf, store_dir: PathBuf, name: String) -> Result<(), Box<dyn Error>> {
    let canon_store_dir = identity_file.parent().unwrap();
    let agefile = canonicalise(&store_dir.join(format!("{}.age", name)))?;

    let tmp_dir = tempdir()?;
    let tmpfile_txt = tmp_dir
        .path()
        .join(agefile.file_name().unwrap())
        .with_extension("txt");

    // decrypt if it exists
    let old_content = if agefile.is_file() {
        let mut reader = decrypt_password(&identity_file, &agefile, &mut vec![])?;
        let mut old_content = vec![];
        reader.read_to_end(&mut old_content)?;
        File::create(&tmpfile_txt)?.write_all(&old_content)?;
        old_content
    } else {
        vec![]
    };

    // edit
    let (editor, args) = get_editor();
    Command::new(&editor)
        .args(args)
        .arg(&tmpfile_txt)
        .status()?
        .exit_ok()?;

    // compare
    if !tmpfile_txt.exists() {
        eprintln!("New password not saved.");
        return Ok(());
    }

    let new_content = fs::read(&tmpfile_txt)?;
    if old_content == new_content {
        eprintln!("Password unchanged.");
        return Ok(());
    }

    // create parent directories
    fs::create_dir_all(agefile.parent().unwrap())?;

    // encrypt
    encrypt_password(
        &canon_store_dir.join(".recipients"),
        File::open(tmpfile_txt)?,
        &agefile,
    )?;
    drop(tmp_dir);

    // git add/commit
    if check_for_git(canon_store_dir) {
        Command::new("git")
            .arg("-C")
            .arg(canon_store_dir)
            .arg("add")
            .arg(&agefile)
            .status()?
            .exit_ok()?;
        let message = format!(
            "{} password for {} using {}",
            if old_content.is_empty() {
                "Add"
            } else {
                "Edit"
            },
            agefile
                .with_extension("")
                .strip_prefix(canon_store_dir)?
                .display(),
            editor.to_str().unwrap()
        );
        Command::new("git")
            .arg("-C")
            .arg(canon_store_dir)
            .args(["commit", "-m", &message])
            .status()?
            .exit_ok()?;
    }
    Ok(())
}

// returns the index where pattern first occurs
fn index_of_pattern<'a, T>(slice: &'a [T], pattern: &'a [T]) -> Option<usize>
where
    [T]: PartialEq<[T]>,
{
    if slice.len() < pattern.len() {
        return None;
    }
    (0..(slice.len() - pattern.len()))
        .find(|&search_i| &slice[search_i..(search_i + pattern.len())] == pattern)
}

// returns the indices where the pattern occurs
fn indices_of_pattern<'a, T>(slice: &'a [T], pattern: &'a [T]) -> Vec<usize>
where
    [T]: PartialEq<[T]>,
{
    let mut ret = vec![];
    let mut range_start_i = 0;
    while let Some(new_i) = index_of_pattern(&slice[range_start_i..], pattern) {
        range_start_i += new_i;
        ret.push(range_start_i);
        range_start_i += pattern.len();
    }
    ret
}

fn show(
    identity_file: PathBuf,
    store_dir: PathBuf,
    clip: bool,
    key: Option<String>,
    name: String,
) -> Result<(), Box<dyn Error>> {
    fn first_line(s: &str) -> &str {
        s.split('\n').next().unwrap()
    }

    let name_dir = store_dir.join(&name);
    let agefile = store_dir.join(format!("{}.age", &name));

    if !agefile.exists() {
        // maybe it is just a directory
        if !name_dir.exists() || !name_dir.canonicalize()?.is_dir() {
            return Err(format!("The password {} does not exist!", agefile.display()).into());
        }

        // print the directory tree
        if name.is_empty() {
            println!("{}", store_dir.display());
        } else {
            println!("{}", name);
        }

        let mut tree = Command::new("tree")
            .args(["-N", "-C", "-l", "--noreport"])
            .arg(name_dir)
            .output()
            .unwrap_or_else(|e| {
                if e.kind() == ErrorKind::NotFound {
                    panic!("Cannot find `tree` in $PATH: {:?}", e);
                } else {
                    panic!("Cannot run `tree` command: {:?}", e);
                }
            });
        tree.status.exit_ok()?;

        // remove the first line
        // "\n".as_bytes() is 10
        let newline_index = match index_of_pattern(&tree.stdout, &[10]) {
            Some(i) => i,
            None => return Ok(()), // empty store
        };
        tree.stdout.drain(0..=newline_index);

        // add a newline character for the pattern matching
        tree.stdout.push(10);

        // remove the extension from the .age-files
        // this pattern is ".age\n".as_bytes() WITH the colour encoding for the terminal
        let pattern_colour = [46, 97, 103, 101, 27, 91, 48, 109, 10];
        for removal_index in indices_of_pattern(&tree.stdout, &pattern_colour)
            .iter()
            .rev()
        {
            tree.stdout //                                             -1 to not remove the "\n"
                .drain(*removal_index..(*removal_index + pattern_colour.len() - 1));
        }
        // this pattern is ".age\n".as_bytes() WITHOUT the colour encoding for the terminal
        // some terminals/shells (?) do not have the colour encodings at the end of uncoloured files
        let pattern_nocolour = [46, 97, 103, 101, 10];
        for removal_index in indices_of_pattern(&tree.stdout, &pattern_nocolour)
            .iter()
            .rev()
        {
            tree.stdout //                                             -1 to not remove the "\n"
                .drain(*removal_index..(*removal_index + pattern_nocolour.len() - 1));
        }

        // remove the "\n" at the end again
        tree.stdout.pop().unwrap();

        print!("{}", std::str::from_utf8(&tree.stdout)?);
        return Ok(());
    }

    let mut reader = decrypt_password(&identity_file, &agefile, &mut vec![])?;
    let mut output = String::new();
    reader.read_to_string(&mut output)?;
    let mut _otp = String::new();
    let (to_print, to_clip) = match key {
        // show everything, clip the first line
        None => (output.trim_end(), first_line(&output)),
        // show the value for the key, clip it
        Some(key) => match key.trim() {
            "password" => (first_line(&output), first_line(&output)),
            key => {
                let key_to_search = match key {
                    "otp" => "otpauth",
                    k => k,
                };
                let mut lines = output.split('\n');
                let value = loop {
                    let line = lines.next().ok_or(format!(
                        "Cannot find key \"{}\" in password file {}!",
                        key,
                        agefile.display()
                    ))?;
                    if !line.starts_with(key_to_search) {
                        continue;
                    }
                    break line[(key_to_search.len() + 1)..].trim();
                };

                match key {
                    "otp" => {
                        if !value.contains("secret=") {
                            return Err("otpauth string does not contain a secret".into());
                        }
                        let secret = value
                            .split_once("secret=")
                            .ok_or("Cannot find secret in otpauth string!")?
                            .1;
                        let secret = secret.split(&['=', '&']).next().unwrap_or(value);
                        _otp = thotp::otp(
                            &base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
                                .unwrap(),
                            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30,
                        )?;
                        (&_otp[..], &_otp[..])
                    }
                    _ => (value, value),
                }
            }
        },
    };
    println!("{}", to_print);
    // TODO: support Windows
    if clip {
        match get_display_server() {
            DisplayServer::Wayland => Command::new("wl-copy")
                .args(["-o", to_clip])
                .status()?
                .exit_ok()?,
            DisplayServer::X11 => {
                let mut xclip = Command::new("xclip").stdin(Stdio::piped()).spawn()?;
                xclip.stdin.take().unwrap().write_all(to_clip.as_bytes())?;
                xclip.wait()?.exit_ok()?;
            }
            DisplayServer::Termux => {
                if which::which("termux-clipboard-set").is_err() {
                    return Err("Please install Termux:API (https://f-droid.org/en/packages/com.termux.api/) and `pkg install termux-api`!".into());
                } else {
                    Command::new("termux-clipboard-set")
                        .arg(to_clip)
                        .status()?
                        .exit_ok()?;
                }
            }
            DisplayServer::Wsl => {
                if which::which("clip.exe").is_err() {
                    return Err("I think we are in WSL, but I cannot find clip.exe!".into());
                } else {
                    let child = Command::new("clip.exe").stdin(Stdio::piped()).spawn()?;
                    let mut stdin_writer = child.stdin.unwrap();
                    stdin_writer.write_all(to_clip.as_bytes())?;
                }
            }
            DisplayServer::Darwin => {
                if which::which("pbcopy").is_err() {
                    return Err("I think we are on Darwin (macOS), but I cannot find pbcopy!".into());
                } else {
                    let child = Command::new("pbcopy").stdin(Stdio::piped()).spawn()?;
                    let mut stdin_writer = child.stdin.unwrap();
                    stdin_writer.write_all(to_clip.as_bytes())?;
                }
            }
            _ => {
                return Err(
                    "Clipboard only implemented for Wayland (wl-copy), X11 (xclip), Termux (termux-clipboard-set), WSL (clip.exe), and Darwin (pbcopy) yet!".into(),
                )
            }
        }
    }
    Ok(())
}

// also removes parent directories until an error is raised
fn removedirs(path: &Path) -> io::Result<()> {
    let mut path_buf = path.to_path_buf();
    while path_buf.is_dir() {
        match fs::remove_dir(&path_buf) {
            Ok(()) => {
                if let Some(parent) = path_buf.parent() {
                    path_buf = parent.to_path_buf();
                } else {
                    break;
                }
            }
            Err(err) if err.raw_os_error() == Some(39) => break,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn move_name(
    identity_file: PathBuf,
    store_dir: PathBuf,
    old_name: String,
    new_name: String,
) -> Result<(), Box<dyn Error>> {
    let canon_store_dir = identity_file.parent().unwrap();
    let mut old_path = store_dir.join(&old_name);
    let mut new_path = store_dir.join(&new_name);
    let old_path_file = store_dir.join(format!("{}.age", &old_name));
    let new_path_file = store_dir.join(format!("{}.age", &new_name));
    // for git later
    let old_canon_name = canonicalise(&store_dir.join(&old_name))?;
    let new_canon_name = canonicalise(&store_dir.join(&new_name))?;

    if !old_name.ends_with('/') && old_path_file.is_file() {
        old_path = old_path_file;
    } else if !old_path.is_dir() {
        return Err(format!("No such file or directory: {}[.age]", old_path.display()).into());
    } else if old_path.canonicalize()? == canon_store_dir {
        return Err(format!("Source {} must not be the whole store!", old_path.display()).into());
    }

    if new_name.ends_with('/') || new_path.is_dir() {
        new_path = new_path.join(old_path.file_name().unwrap());
    } else if old_path.is_file() {
        new_path = new_path_file;
    }

    if old_path.canonicalize()? == canonicalise(&new_path)? {
        return Err(format!(
            "Source {} and destination {} are identical!",
            old_path.display(),
            new_path.display()
        )
        .into());
    }

    let new_path_parent = new_path.parent().unwrap();
    if !new_path_parent.exists() {
        fs::create_dir_all(new_path_parent)?;
    } else if new_path_parent.canonicalize()?.is_file() {
        return Err(format!(
            "The target directory {} must not be an existing file!",
            new_path_parent.display()
        )
        .into());
    }

    fs::rename(&old_path, &new_path)?;
    removedirs(old_path.parent().unwrap())?;

    // git add/commit
    if check_for_git(canon_store_dir) {
        Command::new("git")
            .arg("-C")
            .arg(canon_store_dir)
            .args(["rm", "-r"])
            .arg(&old_path)
            .status()?
            .exit_ok()?;
        Command::new("git")
            .arg("-C")
            .arg(canon_store_dir)
            .arg("add")
            .arg(&new_path)
            .status()?
            .exit_ok()?;
        let message = format!(
            "Rename {} to {}",
            old_canon_name.strip_prefix(canon_store_dir)?.display(),
            new_canon_name.strip_prefix(canon_store_dir)?.display()
        );
        Command::new("git")
            .arg("-C")
            .arg(canon_store_dir)
            .args(["commit", "-m", &message])
            .status()?
            .exit_ok()?;
    }
    Ok(())
}

fn remove(
    identity_file: PathBuf,
    store_dir: PathBuf,
    recursive: bool,
    name: String,
) -> Result<(), Box<dyn Error>> {
    let canon_store_dir = identity_file.parent().unwrap();
    let mut path = store_dir.join(&name);
    let path_file = store_dir.join(format!("{}.age", &name));
    // for git later
    let canon_name = canonicalise(&store_dir.join(&name))?;

    if !name.ends_with('/') && path_file.is_file() {
        path = path_file.canonicalize()?;
        println!("Removing {}", path.display());
        fs::remove_file(&path)?;
    } else if !path.is_dir() {
        return Err(format!("No such file or directory: {}[.age]", path.display()).into());
    } else if path.canonicalize()? == canon_store_dir {
        return Err(format!("Target {} must not be the whole store!", path.display()).into());
    } else if recursive {
        path = path.canonicalize()?;
        println!("Removing {}", path.display());
        fs::remove_dir_all(&path)?;
    } else {
        return Err("Use -r for directories".into());
    }

    removedirs(path.parent().unwrap())?;

    // git add/commit
    if check_for_git(canon_store_dir) {
        Command::new("git")
            .arg("-C")
            .arg(canon_store_dir)
            .args(["rm", "-r"])
            .arg(&path)
            .status()?
            .exit_ok()?;
        let message = format!(
            "Remove {}",
            canon_name.strip_prefix(canon_store_dir)?.display()
        );
        Command::new("git")
            .arg("-C")
            .arg(canon_store_dir)
            .args(["commit", "-m", &message])
            .status()?
            .exit_ok()?;
    }
    Ok(())
}

// returns whether git is used
fn reencrypt(identity_file: &Path) -> Result<bool, Box<dyn Error>> {
    fn reencrypt_recursive(
        identity_file: &Path,
        recipients_dir: &Path,
        identities: &mut Vec<Box<dyn age::Identity>>,
        cur_dir: &Path,
        collect: &mut Vec<PathBuf>,
    ) -> Result<(), Box<dyn Error>> {
        for entry in cur_dir.read_dir()?.filter(|entry| {
            !entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .starts_with('.')
        }) {
            let entry = entry?;
            let filetype = entry.file_type().unwrap();
            let entry_path = entry.path();
            if filetype.is_dir() {
                reencrypt_recursive(
                    identity_file,
                    recipients_dir,
                    identities,
                    &entry_path,
                    collect,
                )?;
                continue;
            } else if !filetype.is_file() || entry_path.extension() != Some(OsStr::new("age")) {
                continue;
            }

            let mut content = vec![];
            decrypt_password(identity_file, &entry_path, identities)?.read_to_end(&mut content)?;
            encrypt_password(recipients_dir, &content[..], &entry_path)?;
            collect.push(entry_path);
        }
        Ok(())
    }

    let mut collect = vec![];
    let mut identities = vec![];
    reencrypt_recursive(
        identity_file,
        &identity_file.parent().unwrap().join(".recipients"),
        &mut identities,
        identity_file.parent().unwrap(),
        &mut collect,
    )?;

    // git add
    if check_for_git(identity_file.parent().unwrap()) {
        Command::new("git")
            .arg("-C")
            .arg(identity_file.parent().unwrap())
            .arg("add")
            .args(collect)
            .status()?
            .exit_ok()?;
        return Ok(true);
    }
    Ok(false)
}

fn add_recipient(
    identity_file: PathBuf,
    public_key: String,
    alias: String,
) -> Result<(), Box<dyn Error>> {
    let recipients_dir = identity_file.parent().unwrap().join(".recipients");

    // check if public_key is not already a recipient
    for recipient in recipients_dir
        .read_dir()?
        .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_file())
    {
        let content = fs::read_to_string(recipient.as_ref().unwrap().path())?;
        for (i, line) in content.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            if line.contains(&public_key) {
                return Err(format!(
                    "Recipient already in {}:{}",
                    recipient.unwrap().path().display(),
                    i + 1
                )
                .into());
            }
        }
    }

    // choose the only existing file or use main.txt
    let mut entries = recipients_dir
        .read_dir()?
        .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_file());
    let recipients_file = match (entries.next(), entries.next()) {
        (Some(entry), None) => entry.unwrap().path(),
        _ => recipients_dir.join("main.txt"),
    };
    // add new public_key to the recipients
    let mut recipients_file_handle = File::options()
        .create(true)
        .append(true)
        .open(&recipients_file)?;
    write!(recipients_file_handle, "# {}\n{}\n", &alias, &public_key)?;

    if reencrypt(&identity_file)? {
        Command::new("git")
            .arg("-C")
            .arg(identity_file.parent().unwrap())
            .arg("add")
            .arg(&recipients_file)
            .status()?
            .exit_ok()?;
        let message = format!("Reencrypted store for {}", &alias);
        Command::new("git")
            .arg("-C")
            .arg(identity_file.parent().unwrap())
            .args(["commit", "-m", &message])
            .status()?
            .exit_ok()?;
    }
    Ok(())
}

fn change_passphrase(identity_file: PathBuf) -> Result<(), Box<dyn Error>> {
    let store_dir = identity_file.parent().unwrap();
    let extension = identity_file.extension().unwrap().to_str().unwrap();
    match extension {
        "txt" => {
            let passphrase = ask_passphrase_twice()?;
            if passphrase.is_empty() {
                println!("Empty passphrase. No changes.");
                return Ok(());
            }

            let mut keyfile_content = vec![];
            File::open(&identity_file)?.read_to_end(&mut keyfile_content)?;

            let new_identity_file = store_dir.join(".identity.age");
            let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase));
            let mut write_to = encryptor.wrap_output(File::create(new_identity_file)?)?;
            write_to.write_all(&keyfile_content)?;
            write_to.finish()?;
            fs::remove_file(&identity_file)?;
        }
        "age" => loop {
            // passphrase age encrypted identity
            let identity_decryptor = match age::Decryptor::new(File::open(&identity_file)?)? {
                age::Decryptor::Passphrase(d) => d,
                _ => return Err(format!("The identity file {} should be encrypted with a passphrase, not with recipients/identities!", identity_file.display()).into()),
            };

            let passphrase = rpassword::prompt_password("Enter the current passphrase: ")?;
            let mut reader =
                match identity_decryptor.decrypt(&Secret::new(passphrase.clone()), Some(32)) {
                    Ok(r) => r,
                    Err(age::DecryptError::DecryptionFailed) => {
                        eprintln!("Decryption failed! Wrong passphrase? Please try again.");
                        continue;
                    }
                    Err(e) => return Err(Box::new(e)),
                };

            let mut keyfile_content = vec![];
            reader.read_to_end(&mut keyfile_content)?;

            let passphrase = ask_passphrase_twice()?;
            let new_identity_filename = if passphrase.is_empty() {
                ".identity.txt"
            } else {
                ".identity.age"
            };
            let new_identity_file = store_dir.join(new_identity_filename);
            if passphrase.is_empty() {
                File::create(new_identity_file)?.write_all(&keyfile_content)?;
                fs::remove_file(&identity_file)?;
            } else {
                let tmp_dir = tempdir()?;
                let tmp_identity_file = tmp_dir.path().join(new_identity_filename);
                let encryptor = age::Encryptor::with_user_passphrase(Secret::new(passphrase));
                let mut write_to = encryptor.wrap_output(File::create(&tmp_identity_file)?)?;
                write_to.write_all(&keyfile_content)?;
                write_to.finish()?;
                fs::copy(&tmp_identity_file, new_identity_file)?;
            }
            break;
        },
        "ssh" => {
            // ssh key (with or without passphrase)
            let old_passphrase = match ssh::Identity::from_buffer(
                BufReader::new(File::open(&identity_file)?),
                Some(identity_file.to_str().unwrap().to_owned()),
            )? {
                ssh::Identity::Encrypted(k) => loop {
                    let passphrase = rpassword::prompt_password("Enter the current passphrase: ")?;
                    match k.decrypt(Secret::new(passphrase.clone())) {
                        Ok(_) => {
                            break passphrase;
                        }
                        Err(age::DecryptError::KeyDecryptionFailed) => {
                            eprintln!("Decryption failed! Wrong passphrase? Please try again.");
                            continue;
                        }
                        Err(e) => return Err(Box::new(e)),
                    }
                },
                ssh::Identity::Unencrypted(_) => String::from(""),
                ssh::Identity::Unsupported(k) => {
                    return Err(format!(
                        "The ssh identity key type of {} is not supported by age! {:?}",
                        identity_file.display(),
                        k
                    )
                    .into())
                }
            };
            let new_passphrase = ask_passphrase_twice()?;
            if old_passphrase.is_empty() && new_passphrase.is_empty() {
                println!("Empty passphrase. No changes.");
                return Ok(());
            }
            Command::new("ssh-keygen")
                .args([
                    "-p",
                    "-f",
                    identity_file.to_str().unwrap(),
                    "-P",
                    &old_passphrase,
                    "-N",
                    &new_passphrase,
                ])
                .status()?
                .exit_ok()?;
            match (old_passphrase.is_empty(), new_passphrase.is_empty()) {
                (true, false) => fs::rename(&identity_file, store_dir.join(".identity.pass.ssh"))?,
                (false, true) => fs::rename(&identity_file, store_dir.join(".identity.ssh"))?,
                _ => {}
            }
        }
        _ => panic!(
            "Identity file with name {} not supported!",
            identity_file.file_name().unwrap().to_str().unwrap()
        ),
    };
    Ok(())
}

fn get_canonicalised_identity_file(
    store_dir: &Path,
    name: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let name_path = store_dir.join(name);
    let canon_name_path = canonicalise(&name_path)?;
    let senior_dir = store_dir.parent().unwrap();
    let canon_store = canon_name_path.strip_prefix(senior_dir).or(Err(format!(
        "Path {} is outside of the senior directory {}!",
        name_path.display(),
        senior_dir.display()
    )))?;
    let canon_store = canon_store.iter().next().ok_or(format!(
        "Path {} is the senior directory {}!",
        name_path.display(),
        senior_dir.display()
    ))?;
    let canon_store = senior_dir.join(canon_store);
    let mut identity_filenames = [
        ".identity.txt",
        ".identity.ssh",
        ".identity.age",
        ".identity.pass.ssh",
    ]
    .iter();
    loop {
        let candidate = canon_store.join(identity_filenames.next().ok_or(format!(
            "Cannot not find any identity file in store {}!",
            canon_store.display()
        ))?);
        if candidate.is_file() || candidate.is_symlink() {
            break Ok(candidate);
        }
    }
}

fn home() -> PathBuf {
    PathBuf::from(env::var_os("HOME").unwrap_or_else(|| {
        env::var_os("USERPROFILE").expect("Cannot get the users home directory!")
    }))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut cli = Cli::parse();

    let senior_dir = env::var_os("XDG_DATA_HOME")
        .map_or_else(|| home().join(".local/share/"), PathBuf::from)
        .join("senior/");

    // default store for `senior clone`
    if cli.store.is_none() {
        if let CliCommand::GitClone { ref address, .. } = cli.command {
            cli.store = Some(
                address
                    .rsplit('/')
                    .map(|name_dot_git| OsString::from(&name_dot_git[..(name_dot_git.len() - 4)]))
                    .next()
                    .unwrap(),
            );
        }
    }
    // default store and corresponding directory
    // the store is either the only directory in the senior directory, or "main"
    let store_dir = senior_dir.join(cli.store.get_or_insert_with(|| {
        if senior_dir.is_dir() {
            let mut entries = senior_dir
                .read_dir()
                .expect("Cannot read senior directory!")
                .filter(|entry| entry.as_ref().unwrap().file_type().unwrap().is_dir());
            match (entries.next(), entries.next()) {
                (Some(entry), None) => entry
                    .expect("Cannot open entry of senior directory!")
                    .file_name(),
                _ => OsString::from("main"),
            }
        } else {
            OsString::from("main")
        }
    }));

    // check existance / non-existance of store
    match cli.command {
        // print-dir: not relevant
        CliCommand::PrintDir => {}
        // init/clone: make sure the store does not exist already
        CliCommand::Init { .. } | CliCommand::GitClone { .. } => {
            if store_dir.exists() {
                return Err(format!(
                    "Store {} exists already! Use `-s` to specify another store.",
                    store_dir.display()
                )
                .into());
            }
        }
        // rest: make sure the store exists
        _ => {
            if !store_dir.exists() {
                return Err(format!(
                    "Store {} does not exist! Use `-s` to specify another store.",
                    store_dir.display()
                )
                .into());
            }
        }
    }

    // show/edit: get the correct identity file (respecting symbolic links)
    let canonicalised_identity_file = match cli.command {
        CliCommand::Show { ref name, .. }
        | CliCommand::Edit { ref name }
        | CliCommand::Rm { ref name, .. } => get_canonicalised_identity_file(&store_dir, name)?,
        CliCommand::Mv {
            ref old_name,
            ref new_name,
        } => {
            let old_canonicalised_identity_file =
                get_canonicalised_identity_file(&store_dir, old_name)?;
            let new_canonicalised_identity_file =
                get_canonicalised_identity_file(&store_dir, new_name)?;
            if old_canonicalised_identity_file == new_canonicalised_identity_file {
                old_canonicalised_identity_file
            } else {
                return Err(format!(
                    "{} and {} are not part of the same store!",
                    old_name, new_name
                )
                .into());
            }
        }
        CliCommand::AddRecipient { .. }
        | CliCommand::Reencrypt
        | CliCommand::ChangePassphrase
        | CliCommand::Unlock { .. } => get_canonicalised_identity_file(&store_dir, "")?,
        _ => PathBuf::new(),
    };

    match cli.command {
        CliCommand::Init {
            identity,
            recipient_alias,
        } => init(store_dir, identity, recipient_alias),
        CliCommand::GitClone { identity, address } => git_clone(store_dir, identity, address),
        CliCommand::Edit { name } => edit(canonicalised_identity_file, store_dir, name),
        CliCommand::Show { clip, key, name } => {
            show(canonicalised_identity_file, store_dir, clip, key, name)
        }
        CliCommand::Mv { old_name, new_name } => {
            move_name(canonicalised_identity_file, store_dir, old_name, new_name)
        }
        CliCommand::Rm { recursive, name } => {
            remove(canonicalised_identity_file, store_dir, recursive, name)
        }
        CliCommand::PrintDir => {
            println!("{}", store_dir.display());
            Ok(())
        }
        CliCommand::Git { args } => {
            Command::new("git")
                .arg("-C")
                .arg(store_dir)
                .args(args)
                .status()?
                .exit_ok()?;
            Ok(())
        }
        CliCommand::AddRecipient { public_key, alias } => {
            add_recipient(canonicalised_identity_file, public_key, alias)
        }
        CliCommand::Reencrypt => {
            if reencrypt(&canonicalised_identity_file)? {
                Command::new("git")
                    .arg("-C")
                    .arg(&store_dir)
                    .args(["commit", "-m", "Reencrypted store"])
                    .status()?
                    .exit_ok()?;
            }
            Ok(())
        }
        CliCommand::ChangePassphrase => change_passphrase(canonicalised_identity_file),
        CliCommand::Unlock { check } => unlock(&canonicalised_identity_file, check),
    }
}
