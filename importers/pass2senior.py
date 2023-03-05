#!/usr/bin/env python3
import os
import sys
import tempfile
import subprocess
import shutil

def find_age_backend():
    known_backends = ["rage", "age"]
    for backend in known_backends:
        s = subprocess.run(["which", backend], capture_output=True)
        if s.returncode == 0:
            return backend
    raise Exception("No valid age backend installed? Please install one of the following: {}".format(known_backends))

def main():
    src_dir = None
    target_dir = None
    identity = None
    public_key = None

    arg_iter = iter(sys.argv[1:])
    while (arg := next(arg_iter, None)) is not None:
        if arg == "-i":
            identity = next(arg_iter, None)
            continue
        if src_dir is None:
            src_dir = arg
        else:
            target_dir = arg

    if (src_dir is None) or (target_dir is None):
        print("Usage: {} [-i identity_file] <src_dir> <target_dir>".format(sys.argv[0]))

    age = find_age_backend()
    tmpdir = tempfile.TemporaryDirectory(suffix="pass2senior")
    if identity is None:
        identity = os.path.join(tmpdir.name, "identity.txt")
        s = subprocess.run(["{}-keygen".format(age), "-o", identity], capture_output=True, text=True)
        public_key = s.stderr.strip()[len("Public key: "):]
    else:
        with open(identity, "r") as f:
            for line in f.read().strip().split("\n"):
                if "public key:" in line.lower():
                    public_key = line[len("# public key: "):]
                    break
                elif "openssh" in line.lower():
                    public_key = subprocess.run(["ssh-keygen", "-y", "-f", identity], capture_output=True, text=True).stdout.strip()
                    break

    recipients_dir = os.path.join(target_dir, ".recipients")
    os.makedirs(recipients_dir, exist_ok=True)
    target_identity = os.path.join(target_dir, ".identity.txt")
    shutil.copyfile(identity, os.path.join(target_dir, ".identity.txt"))
    tmpdir.cleanup()
    recipients_main = os.path.join(recipients_dir, "main.txt")
    with open(recipients_main, "w") as f:
        f.write("# {}\n".format(os.environ["USER"]))
        f.write("{}\n".format(public_key))

    def copy_and_encrypt(dir_path):
        for filename in os.listdir(dir_path):
            if filename.startswith("."):
                continue
            filepath = os.path.join(dir_path, filename)
            if os.path.isdir(filepath):
                copy_and_encrypt(filepath)
                continue
            target_parent = os.path.join(target_dir, dir_path[len(src_dir) + 1:])
            os.makedirs(target_parent, exist_ok=True)
            target_path = os.path.join(target_parent, filename[:-4] + ".age")
            print("gpg --decrypt {} | {} -e -R {} -o {}".format(filepath, age, recipients_main, target_path))
            gpg_decrypt = subprocess.Popen(["gpg", "--decrypt", filepath], stdout=subprocess.PIPE)
            age_encrypt = subprocess.run([age, "-e", "-R", recipients_main, "-o", target_path], stdin=gpg_decrypt.stdout)
            if age_encrypt.returncode != 0:
                raise Exception("Non-zero return code: {}".format(age_encrypt.stderr))

    copy_and_encrypt(src_dir)

if __name__ == "__main__":
    main()
