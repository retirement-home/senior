use std::collections::HashMap;
use std::error::Error;
use std::io::{self, prelude::*, BufReader};

use interprocess::local_socket::{LocalSocketListener, LocalSocketStream, NameTypeSupport};

fn handle_error(conn: io::Result<LocalSocketStream>) -> Option<LocalSocketStream> {
    match conn {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("Incoming connection failed: {e}");
            None
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let name = {
        use NameTypeSupport::*;
        match NameTypeSupport::query() {
            OnlyPaths => "/tmp/senior-agent.sock",
            OnlyNamespaced | Both => "@senior-agent.sock",
        }
    };

    let listener = match LocalSocketListener::bind(name) {
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            eprintln!(
                 "\
    Error: could not start server because the socket file is occupied. Please check if {name} is in \
    use by another process and try again."
             );
            return Err(e.into());
        }
        x => x?,
    };

    let mut passphrases = HashMap::<String, String>::new();
    let mut buffer = String::with_capacity(1024);

    println!("Ready for connections!");

    for conn in listener.incoming().filter_map(handle_error) {
        buffer.clear();
        let mut conn = BufReader::new(conn);

        match conn.read_line(&mut buffer) {
            Ok(0) => {
                println!("Read EOF. Closing.");
                break;
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                continue;
            }
            Ok(_) => {}
        }

        // Remove trailing newline
        buffer.pop();

        let mut conn = conn.get_mut();
        match &buffer[0..1] {
            "r" => {
                // read
                let key = &buffer[2..];
                match passphrases.contains_key(key) {
                    true => writeln!(&mut conn, "o: {}", &passphrases[key])?,
                    false => writeln!(&mut conn, "e: Key {} is not present!", key)?,
                }
            }
            "w" => {
                // write
                // the first space determines the split between key and passphrase
                // spaces in the key must be escaped with a backslash
                let mut prev_char_was_backslash = false;
                let mut separator_index = 0;
                for (i, c) in buffer[2..].char_indices() {
                    if c == ' ' && !prev_char_was_backslash {
                        separator_index = i;
                        break;
                    } else {
                        prev_char_was_backslash = c == '\\';
                    }
                }
                let key = buffer[2..(separator_index + 2)].to_owned();
                let pass = buffer[(separator_index + 3)..].to_owned();
                //println!("Writing passphrase {} for key {}.", &pass, &key);
                passphrases.insert(key, pass);
            }
            _ => {
                writeln!(&mut conn, "e: Command not implemented!")?;
                continue;
            }
        }
    }
    Ok(())
}
