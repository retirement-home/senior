#compdef senior

_senior_stores() {
	local prefix=$(senior print-dir)/..
	local stores=( ${prefix}/* )
	stores=( ${stores[@]#"$prefix"/} )
	_describe 'command' stores
}

_senior_store_from_arg() {
	local store_arg
	if [[ -n $opt_args_copy[-s] ]]; then
		store_arg=( --store $opt_args_copy[-s] )
	elif [[ -n $opt_args_copy[--store] ]]; then
		store_arg=( --store $opt_args_copy[--store] )
	fi
	REPLY="$(senior $store_arg print-dir)"
}

_senior_complete_entries_helper() {
	local IFS=$'\n'
	local prefix
	_senior_store_from_arg
	zstyle -s ":completion:${curcontext}:" prefix prefix || prefix="$REPLY"
	_values -C 'passwords' ${$(find -L "$prefix" \( -name '.*' \) -prune -o $@ -print 2>/dev/null | sed -e "s#${prefix}/\{0,1\}##" -e 's#\.age##' -e 's#\\#\\\\#g' -e 's#:#\\:#g' | sort):-""}
}

_senior_complete_entries_with_subdirs () {
	_senior_complete_entries_helper
}

_senior_complete_entries () {
	_senior_complete_entries_helper -type f
}

autoload -U is-at-least

_senior() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" \
'-s[Alias for the store; default: "main", or the only existing one, or for `senior clone` the name of the repository]:STORE:_senior_stores' \
'--store=[Alias for the store; default: "main", or the only existing one, or for `senior clone` the name of the repository]:STORE:_senior_stores' \
'-h[Print help]' \
'--help[Print help]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_senior_commands" \
"*::: :->senior" \
&& ret=0

    typeset -A opt_args_copy
    set -A opt_args_copy ${(kv)opt_args}

    case $state in
    (senior)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:senior-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" \
'-i[Path of the identity used for decrypting; default: generate a new one]:FILE:_files' \
'--identity=[Path of the identity used for decrypting; default: generate a new one]:FILE:_files' \
'-a[Alias for the recipient; default: your username]:USERNAME: ' \
'--recipient-alias=[Alias for the recipient; default: your username]:USERNAME: ' \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(clone)
_arguments "${_arguments_options[@]}" \
'-i[Path of the identity used for decrypting; default: generate a new one]:FILE:_files' \
'--identity=[Path of the identity used for decrypting; default: generate a new one]:FILE:_files' \
'-h[Print help]' \
'--help[Print help]' \
':address -- Address of the remote git repository:_urls' \
&& ret=0
;;
(edit)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
':name -- Name of the password:_senior_complete_entries' \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" \
'-k[Show only this key; "password" shows the first line; "otp" generates the one-time password]:otp|login|email|...: ' \
'--key=[Show only this key; "password" shows the first line; "otp" generates the one-time password]:otp|login|email|...: ' \
'-c[Add the value to the clipboard]' \
'--clip[Add the value to the clipboard]' \
'-h[Print help]' \
'--help[Print help]' \
'::name -- Name of the password or directory:_senior_complete_entries' \
&& ret=0
;;
(mv)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
':old_name -- Old name of the password or directory:_senior_complete_entries_with_subdirs' \
':new_name -- New name of the password or directory:_senior_complete_entries_with_subdirs' \
&& ret=0
;;
(rm)
_arguments "${_arguments_options[@]}" \
'-r[For directories]' \
'--recursive[For directories]' \
'-h[Print help]' \
'--help[Print help]' \
':name -- Name of the password or directory:_senior_complete_entries_with_subdirs' \
&& ret=0
;;
(print-dir)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(git)
	local -a subcommands
	subcommands=(
		"init:Initialize git repository"
		"push:Push to remote repository"
		"pull:Pull from remote repository"
		"config:Show git config"
		"log:Show git log"
		"reflog:Show git reflog"
	)
	_describe -t commands 'senior git' subcommands
;;
(add-recipient)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
':public_key -- Public key of the new recipient:' \
':alias -- Name of the new recipient:' \
&& ret=0
;;
(reencrypt)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(change-passphrase)
_arguments "${_arguments_options[@]}" \
'-h[Print help]' \
'--help[Print help]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" \
":: :_senior__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:senior-help-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(clone)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(edit)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(mv)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(rm)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(print-dir)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(git)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(add-recipient)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(reencrypt)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(change-passphrase)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_senior_commands] )) ||
_senior_commands() {
    local commands; commands=(
'init:Initialises a new store' \
'clone:Clones a store from a git repository' \
'edit:Edit/create a password' \
'show:Show a password' \
'mv:Move a password' \
'rm:Remove a password' \
'print-dir:Print the directory of the store' \
'git:Run git commands in the store' \
'add-recipient:Add recipient' \
'reencrypt:Reencrypt the entire store' \
'change-passphrase:Change the store'\''s passphrase' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'senior commands' commands "$@"
}
(( $+functions[_senior__add-recipient_commands] )) ||
_senior__add-recipient_commands() {
    local commands; commands=()
    _describe -t commands 'senior add-recipient commands' commands "$@"
}
(( $+functions[_senior__help__add-recipient_commands] )) ||
_senior__help__add-recipient_commands() {
    local commands; commands=()
    _describe -t commands 'senior help add-recipient commands' commands "$@"
}
(( $+functions[_senior__change-passphrase_commands] )) ||
_senior__change-passphrase_commands() {
    local commands; commands=()
    _describe -t commands 'senior change-passphrase commands' commands "$@"
}
(( $+functions[_senior__help__change-passphrase_commands] )) ||
_senior__help__change-passphrase_commands() {
    local commands; commands=()
    _describe -t commands 'senior help change-passphrase commands' commands "$@"
}
(( $+functions[_senior__clone_commands] )) ||
_senior__clone_commands() {
    local commands; commands=()
    _describe -t commands 'senior clone commands' commands "$@"
}
(( $+functions[_senior__help__clone_commands] )) ||
_senior__help__clone_commands() {
    local commands; commands=()
    _describe -t commands 'senior help clone commands' commands "$@"
}
(( $+functions[_senior__edit_commands] )) ||
_senior__edit_commands() {
    local commands; commands=()
    _describe -t commands 'senior edit commands' commands "$@"
}
(( $+functions[_senior__help__edit_commands] )) ||
_senior__help__edit_commands() {
    local commands; commands=()
    _describe -t commands 'senior help edit commands' commands "$@"
}
(( $+functions[_senior__git_commands] )) ||
_senior__git_commands() {
    local commands; commands=()
    _describe -t commands 'senior git commands' commands "$@"
}
(( $+functions[_senior__help__git_commands] )) ||
_senior__help__git_commands() {
    local commands; commands=()
    _describe -t commands 'senior help git commands' commands "$@"
}
(( $+functions[_senior__help_commands] )) ||
_senior__help_commands() {
    local commands; commands=(
'init:Initialises a new store' \
'clone:Clones a store from a git repository' \
'edit:Edit/create a password' \
'show:Show a password' \
'mv:Move a password' \
'rm:Remove a password' \
'print-dir:Print the directory of the store' \
'git:Run git commands in the store' \
'add-recipient:Add recipient' \
'reencrypt:Reencrypt the entire store' \
'change-passphrase:Change the store'\''s passphrase' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'senior help commands' commands "$@"
}
(( $+functions[_senior__help__help_commands] )) ||
_senior__help__help_commands() {
    local commands; commands=()
    _describe -t commands 'senior help help commands' commands "$@"
}
(( $+functions[_senior__help__init_commands] )) ||
_senior__help__init_commands() {
    local commands; commands=()
    _describe -t commands 'senior help init commands' commands "$@"
}
(( $+functions[_senior__init_commands] )) ||
_senior__init_commands() {
    local commands; commands=()
    _describe -t commands 'senior init commands' commands "$@"
}
(( $+functions[_senior__help__mv_commands] )) ||
_senior__help__mv_commands() {
    local commands; commands=()
    _describe -t commands 'senior help mv commands' commands "$@"
}
(( $+functions[_senior__mv_commands] )) ||
_senior__mv_commands() {
    local commands; commands=()
    _describe -t commands 'senior mv commands' commands "$@"
}
(( $+functions[_senior__help__print-dir_commands] )) ||
_senior__help__print-dir_commands() {
    local commands; commands=()
    _describe -t commands 'senior help print-dir commands' commands "$@"
}
(( $+functions[_senior__print-dir_commands] )) ||
_senior__print-dir_commands() {
    local commands; commands=()
    _describe -t commands 'senior print-dir commands' commands "$@"
}
(( $+functions[_senior__help__reencrypt_commands] )) ||
_senior__help__reencrypt_commands() {
    local commands; commands=()
    _describe -t commands 'senior help reencrypt commands' commands "$@"
}
(( $+functions[_senior__reencrypt_commands] )) ||
_senior__reencrypt_commands() {
    local commands; commands=()
    _describe -t commands 'senior reencrypt commands' commands "$@"
}
(( $+functions[_senior__help__rm_commands] )) ||
_senior__help__rm_commands() {
    local commands; commands=()
    _describe -t commands 'senior help rm commands' commands "$@"
}
(( $+functions[_senior__rm_commands] )) ||
_senior__rm_commands() {
    local commands; commands=()
    _describe -t commands 'senior rm commands' commands "$@"
}
(( $+functions[_senior__help__show_commands] )) ||
_senior__help__show_commands() {
    local commands; commands=()
    _describe -t commands 'senior help show commands' commands "$@"
}
(( $+functions[_senior__show_commands] )) ||
_senior__show_commands() {
    local commands; commands=()
    _describe -t commands 'senior show commands' commands "$@"
}

if [ "$funcstack[1]" = "_senior" ]; then
    _senior "$@"
else
    compdef _senior senior
fi
