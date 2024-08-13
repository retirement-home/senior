use interprocess::local_socket::{self, prelude::*, GenericFilePath, GenericNamespaced};
use std::path::PathBuf;

#[link(name = "c")]
extern "C" {
    fn geteuid() -> u32;
}

pub fn socket_name() -> (String, local_socket::Name<'static>) {
    let uid = unsafe { geteuid() };
    let mut run_user = PathBuf::from("/run/user");
    run_user.push(uid.to_string());
    if run_user.exists() {
        run_user.push("senior-agent.sock");
        let path = run_user.to_str().unwrap().to_string();
        return (path.clone(), path.to_fs_name::<GenericFilePath>().unwrap());
    }

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
