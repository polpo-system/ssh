SSH - a shell of a server in a viewer, a VT100 terminal of 80 columns and 24 lines

  SSH.Open [options] [user@]host    a connection in a new viewer
  SSH.Close                         (in its menu) ends the connection

  options: /p port (22), /i key file (~/.ssh/id_ed25519), /l user ($USER),
           /y accepts an unknown host key and adds it to ~/.ssh/known_hosts

  SSH.Open me@example.org
  SSH.Open /p 2222 /i /home/me/.ssh/other_ed25519 me@example.org

The user logs in with the Ed25519 key; when the server does not take it and offers passwords, the
viewer asks for the password (three tries, no echo). Messages about the host key and errors go to
System.Log. Closing the viewer ends the connection too.

  ssh.Help          the console commands (ssh.Exec, ssh.Connect)
