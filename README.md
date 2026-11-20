# ssh

An SSH client for [polpo](https://github.com/polpo-system/polpo), written in Oberon on the
cryptography of polpo's TLS library: it runs commands on a server and gives an interactive shell
in the terminal.

```
loksh ssh.Exec me@example.org uname -a
loksh ssh.Connect me@example.org
```

```
ssh.Exec [options] [user@]host command ...   runs the command on host, its output here
ssh.Connect [options] [user@]host             a shell on host in this terminal
ssh.Help
options: /p port (22), /i key file (~/.ssh/id_ed25519), /l user ($USER),
         /y accepts an unknown host key and adds it to ~/.ssh/known_hosts
```

`ssh.Exec` passes the output and the errors of the command on, and reports an exit status other
than 0 or the signal that ended the command. `ssh.Connect` asks the server for a terminal of the
type `$TERM` and the size of this one, follows changes of its size, and puts this terminal in raw
mode until the shell ends; it needs a terminal.

The user logs in with an Ed25519 key in the format of OpenSSH (as `ssh-keygen -t ed25519` writes it,
without a passphrase), and when that does not work and the server offers it, with a password,
asked for without echo. Host keys are checked against `~/.ssh/known_hosts`, the file of OpenSSH: a
known key passes, a changed key is refused, and an unknown key is shown with its fingerprint and
asked about (with `/y` it is taken), then added to the file as OpenSSH would add it.

## In the desktop

The package ssh-desktop adds a viewer: `SSH.Open` takes the same options and opens a VT100 terminal
of 80 columns and 24 lines (the package terminals) with a shell of the server; `SSH.Close` in its
menu, or closing the viewer, ends the connection. When the server does not take the key and offers
passwords, the viewer asks for the password. Messages about host keys go to System.Log; an unknown
host key is taken only with `/y`. `tools/SSH.Tool` lists the commands.

```
portia.Install ssh-desktop
SSH.Open me@example.org
```

## What it speaks

- key exchange curve25519-sha256 (RFC 8731) with the strict key exchange of OpenSSH, which closes
  the Terrapin attack; key exchanges the server starts during the connection are answered
- host keys ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-512 and rsa-sha2-256
- the cipher aes128-gcm@openssh.com
- user authentication with ssh-ed25519 keys and passwords
- one session channel: a command or a shell, with a terminal if wanted, the exit status

Not yet: keys with a passphrase and the ssh-agent, other kinds of user keys, port forwarding, file
transfer (scp, sftp), more channels on one connection. The arithmetic is not constant time, as
with the TLS library it uses; the data rate is some 80 KB a second on x86.

## What is here

    src/SSHWire.Mod          the data types of SSH: uint32, strings, mpints, name-lists; Base64
    src/SSHKeys.Mod          host keys checked, fingerprints, known_hosts, Ed25519 keys of users
    src/SSHTransport.Mod     version lines, packets, key exchange, encryption
    src/SSHAuth.Mod          user authentication
    src/SSHChannels.Mod      the session channel
    src/ssh.Mod              the console commands
    src/SSH.Mod              the viewer of the desktop (package ssh-desktop)
    tools/SSH.Tool
    test/SSHTest.Mod         the test, with msg.txt and its signatures msg-*.sig
    test/SSHDesktopTest.Mod  the test of the viewer

Programs use the modules directly: `SSHTransport.Connect`, `SSHAuth.Start` and `SSHAuth.Key` or
`SSHAuth.Password`, then `SSHChannels.OpenSession` and `Exec` or `Shell`, and `Step` until the
session is closed.

## Tests

    SSHTest.Run      39 checks: the data types, a key of OpenSSH loaded with its fingerprint,
                     signatures made by ssh-keygen -Y sign (Ed25519, ECDSA P-256, RSA) checked,
                     known_hosts; no server is needed
    SSHDesktopTest.Run  3 checks: SSH loaded, its usage line, a host without a server;
                     needs the desktop's display (DISPLAY set; an Xvnc will do)

Against a server, an sshd of OpenSSH started as an ordinary user on a free port (with its own host
keys, `AuthorizedKeysFile` and `PidFile`) and `ssh.Exec /p port /i key 127.0.0.1 ...` do.

The license is GPL-3 (`LICENSE`).
