# senior

A Password Manager Using [age](https://github.com/FiloSottile/age) for Encryption

![senior demonstration](other/senior-demo.svg)

## Contents
- [Features](#features)
- [Usage](#usage)
- [Install](#install)
- [How It Works](#how-it-works)

## Features
It is inspired by [pass](https://git.zx2c4.com/password-store/).
senior's features are
- Multiple stores
- OTP support
- Clipboard support
- Select and automatically type a password via `seniormenu`
- git support
- Passphrase protected identities
- Passphrases only need to be entered once per session and then get cached by `senior-agent`
- A store can be shared among a group (encryption for multiple recipients)
- Symlinks between stores are supported
- No config files
- Supported environments: [Linux](https://kernel.org/) ([Wayland](https://wayland.freedesktop.org/) and [X11](https://www.x.org/wiki/)), [Termux](https://termux.dev/en/), [WSL](https://learn.microsoft.com/en-us/windows/wsl/about), [Darwin](https://opensource.apple.com/) ([macOS](https://www.apple.com/macos/))

To do:
- man page
- Android app

## Usage
### Create a New Store
```sh
senior init
# optionally initalise for git use:
senior git init
senior git add '*'
senior git commit -m "init"
```
The default store name is `main`. You can use `senior -s <NAME> <command>` to use another name.

### git-clone an Existing Store
```sh
senior clone git@gitlab.com:exampleuser/mystore.git
```
Without specifying another store name (using `-s`), the default name will be `mystore` in this example.
Someone who already has access to the store can then add you to the recipients via
```sh
senior add-recipient "<PUBLIC KEY>" "<ALIAS>"
```

### Use an Existing Identity
Both `senior create` and `senior clone` support the optional flag `-i <FILE>` or `--identity <FILE>`
to use an existing identity instead of generating a new one.
Supported are
- Cleartext age identity
- Passphrase encrypted age identity
- ssh key of type ed25519 or rsa

### Edit/Show/Move/Remove a Password
```sh
senior edit example.com
senior show example.com
senior mv example.com example2.com
senior rm example2.com
```
`senior show` has the option `-k` or `--key` to only print the value of a `key: value` pair.
The special key `otp` creates the one-time password from the otpauth-string.
```sh
$ senior show example.com
mysecretpassword
login: myusername
otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
# use `-c` or `--clip` to also add it to the clipboard
$ senior show -c -k login example.com
myusername
$ senior show -k otp example.com
118250
```

### git Support
With `senior git` you can run git commands in the `senior print-dir` directory.
If you have initalised your store for git use then
any `senior edit` creates a git-commit.
To sync it with remote, run
```sh
senior git pull
senior git push
```

### Multiple Stores
You can use multiple stores by using `-s` or `--store`
```sh
$ ls "$(senior print-dir)"/..
friends  main  work
# the default store is `main`
$ senior show
/home/bob/.local/share/senior/main
├── example.com
├── friends -> ../friends
│   ├── amazon.com
│   └── netflix.com
└── gitlab.com
$ senior -s friends show
/home/bob/.local/share/senior/friends
├── amazon.com
└── netflix.com
$ senior -s work show
/home/bob/.local/share/senior/work
├── server1
└── workstation
```
Notice the symlink `main/friends -> ../friends`. This makes the two commands
```sh
$ senior -s friends show example.com
$ senior show friends/example.com
```
equivalent.
senior recognises that `main/friends/example.com` is actually at `friends/example.com` and therefore uses
`friends/.identity.age` to decrypt.
Same goes for `senior edit` and using `friends/.recipients/*` to encrypt.
This is very practical for [seniormenu](#seniormenu), as it only looks inside the default store.

If only one store exists then this is the default store. Otherwise `main` is the default store.

### seniormenu
```
seniormenu [--menu <dmenu-wl>] [--dotool <ydotool>] [--type] [<key1> <key2> ...]
```
seniormenu uses `dmenu-wl` or `dmenu` (can be changed with `--menu <othermenu>`) to let you select a password for the clipboard.
You can provide a `<key>` to get another value from the password file (like login, email, ...).

With `--type` the password gets typed using [ydotool](https://github.com/ReimuNotMoe/ydotool) (for Wayland) / [xdotool](https://github.com/jordansissel/xdotool) (for X11). The default can be changed with `--dotool <otherdotool>`.

ydotool feature only: You can specify multiple keys. Inbetween keys, a TAB is typed. After typing the password or the otp, the ENTER key gets pressed.

Set up some keybindings in your window manager to quickly clip/type passwords.
An example for sway/i3 is
```
bindsym $mod+u exec seniormenu --menu bemenu --type
bindsym $mod+y exec seniormenu --menu bemenu --type otp
bindsym $mod+t exec seniormenu --menu bemenu --type login password
```

### senior-agent
If you have set a passphrase to protect your identity file, then running
`age -d -i .identity.age example.com.age`
would require you to enter the passphrase each time.
Because this is very cumbersome, senior provides an agent.

Upon receiving your passphrase once,
`senior` starts `senior-agent` to cache your identity.
This way you only have to enter your passphrase once per session.

## Install
### Arch BASED Systems
Simply use the provided [PKGBUILD](PKGBUILD)
```sh
# Download the PKGBUILD into an empty directory
curl -O "https://gitlab.com/retirement-home/senior/-/raw/main/PKGBUILD"
# Install the package with all its dependencies
makepkg -sic
```

### Other Systems
```sh
# installing:
make build
sudo make install

# uninstalling:
sudo make uninstall
```
Make sure you have the dependencies installed (look at `depends` and `makedepends` in the [PKGBUILD](PKGBUILD)).

## How It Works
Your store is just a directory, usually `~/.local/share/senior/main/`. Run `senior print-dir` to find out.
Let us look at the directory tree.
```sh
$ tree -a "$(senior print-dir)"
/home/bob/.local/share/senior/main
├── example.com.age
├── .gitignore
├── gitlab.com.age
├── .identity.age
└── .recipients
    └── main.txt
```
Apart from `.gitignore` there are two special entries: `.identity.age` and `.recipients/`.

- `.identity.age` is your age identity that is used to decrypt the passwords.

- `.recipients/main.txt` contains the public keys used for encrypting the passwords.

The passwords are age-encrypted text files.
Let us look at a password:
```sh
$ senior show gitlab.com
mysupersafepassword
login: myuser
```
The `show` command is equivalent to
```sh
$ age -d -i .identity.age gitlab.com.age
mysupersafepassword
login: myuser
```

With `senior edit ...`, after editing the decrypted text file, it gets encrypted via
```sh
$ age -e -R .recipients/main.txt -o gitlab.com.age /tmp/gitlab.com.txt
```

