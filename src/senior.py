#!/usr/bin/env python3
import tomlkit
import os
import sys
import shutil
import subprocess
from getpass import getuser

# runs a subprocess and returns the output
# raises an Exception if returncode is not equal to 0
def run_subprocess(args):
    proc = subprocess.run(args, capture_output=True)
    if proc.returncode != 0:
        raise Exception("Error occured when running {}\n{}\n{}".format(" ".join(args), proc.stdout, proc.stderr))
    return proc.stdout

def init():
    xdg_config = os.getenv("XDG_CONFIG_HOME", default=os.path.expanduser("~/.config/"))
    xdg_data = os.getenv("XDG_DATA_HOME", default=os.path.expanduser("~/.local/share/"))
    config_path = os.path.join(xdg_config, "senior/config.toml")
    stores_path = os.path.join(xdg_data, "senior/stores/")
    keys_path = os.path.join(xdg_data, "senior/keys/")

    if os.path.exists(config_path):
        raise Exception("{} exists already!".format(config_path))

    for dir_path in (stores_path, keys_path):
        if os.path.isdir(dir_path) and len(os.listdir(dir_path)) != 0:
            raise Exception("There are already files/directories in {}!".format(dir_path))

    # find a working age backend
    age_backends = ["age", "rage"]
    age_backends_iter = iter(age_backends)
    age_backend = next(age_backends_iter)
    while shutil.which(age_backend) is None:
        age_backend = next(age_backends_iter)
        if age_backend is None:
            break

    # non of the basic list found; let the user specify one
    if age_backend is None:
        print("Could not find any age backend: {}".format(age_backends))
        while True:
            age_backend = input("Specify an age backend manually: ")
            if shutil.which(age_backend) is not None:
                break
            print("Could not find executable {}".format(age_backend))


    os.makedirs(keys_path, exist_ok=True)
    main_store_path = os.path.join(stores_path, "main/")
    recipients_path = os.path.join(main_store_path, ".recipients/")
    os.makedirs(recipients_path, exist_ok=True)

    inp = "0"
    while inp not in ["", "g", "s"]:
        inp = input("Want to [g]enerate a new key pair, or [s]pecify one yourself? [G/s] ").strip().lower()

    alias = input("Add an alias [{}]: ".format(getuser())).strip()
    if alias == "":
        alias = getuser()

    privkeyfile = os.path.join(keys_path, "main.key")
    pubkeyfile = os.path.join(recipients_path, "main.pubkeys")
    # generate
    if inp == "" or inp == "g":
        pubkey = run_subprocess(["{}-keygen".format(age_backend), "-o", privkeyfile])[len("Public key: "):]
        with open(pubkeyfile, "w") as f:
            f.write("# {}\n".format(alias))
            f.write("{}\n".format(pubkey))
    # specify an existing one
    elif inp == "s":
        # specify
        pubkey = None
        inp = input("Please enter the private key [file/cleartext]: ")
        if os.path.isfile(os.path.expanduser(inp)):
            inp = os.path.expanduser(inp)
            for line in open(inp, "r"):
                if line.startswith("# public key: "):
                    pubkey = line[len("# public key: "):]
                    break
            shutil.copyfile(inp, privkeyfile)
        else:
            with open(privkeyfile, "w") as f:
                f.write(inp)

        if pubkey is None:
            inp = input("Please enter the public key [file/cleartext]: ")
            if os.path.isfile(os.path.expanduser(inp)):
                with open(os.path.expanduser(inp)) as f:
                    pubkey = "".join(f.readlines()).strip()

        with open(pubkeyfile, "w") as f:
            f.write("# {}\n".format(alias))
            f.write("{}\n".format(pubkey))
    else:
        raise Exception("Input '{}' invalid".format(inp))

    config = tomlkit.document()
    config.add("age_backend", age_backend)
    config.add(tomlkit.nl())
    main_store = tomlkit.table()
    main_store["privkey_command"] = ["cat", privkeyfile]
    config.add("main", main_store)

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        f.write(config.as_string())

def main():
    if len(sys.argv) < 2:
        print("Please specify a command.")
        return

    if sys.argv[1].strip() == "init":
        init()

if __name__ == "__main__":
    main()
