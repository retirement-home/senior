use interprocess::local_socket::{self, prelude::*, GenericFilePath, GenericNamespaced};
use std::env;
use std::path::PathBuf;

#[link(name = "c")]
extern "C" {
    pub fn geteuid() -> u32;
}

pub fn get_socket_name() -> (String, local_socket::Name<'static>) {
    if let Some(runtime_dir) = env::var_os("XDG_RUNTIME_DIR") {
        if GenericFilePath::is_supported() {
            let mut path = PathBuf::from(runtime_dir);
            if path.is_dir() {
                path.push("senior-agent.sock");
                let path = path.to_str().unwrap().to_string();
                return (path.clone(), path.to_fs_name::<GenericFilePath>().unwrap());
            }
        }
    }

    let uid = unsafe { geteuid() };
    let name = format!("senior-agent-{}.sock", uid);
    if GenericNamespaced::is_supported() {
        (
            format!("{}{}", "@", &name),
            name.to_ns_name::<GenericNamespaced>().unwrap(),
        )
    } else {
        let name = format!("{}{}", "/tmp/", &name);
        (name.clone(), name.to_fs_name::<GenericFilePath>().unwrap())
    }
}
