MODULE ssh;  (** an SSH client in the console: commands on a server, an interactive shell *)

(* ssh.Exec [options] [user@]host command ...   runs the command on host, its output here
   ssh.Connect [options] [user@]host             a shell on host in this terminal
   options: /p port, /i key file (default ~/.ssh/id_ed25519), /l user (default $USER),
   /y: accept an unknown host key and add it to ~/.ssh/known_hosts *)

IMPORT SYSTEM, Kernel, Files, Texts, Out, Oberon0, termios, unixNet, TLSBytes, W := SSHWire,
  T := SSHTransport, A := SSHAuth, Ch := SSHChannels, K := SSHKeys;

CONST
  MaxArg = 1024;

TYPE
  Arg = ARRAY MaxArg OF CHAR;

VAR
  host, user, port, keyFile: Arg;
  accept: BOOLEAN;         (* /y *)
  saved: termios.Termios;  (* the terminal before the shell *)
  raw: BOOLEAN;            (* the terminal is in raw mode *)

PROCEDURE Append(VAR s: ARRAY OF CHAR; t: ARRAY OF CHAR);
VAR i, j: LONGINT;
BEGIN
  i := 0; WHILE s[i] # 0X DO INC(i) END;
  j := 0; WHILE (t[j] # 0X) & (i < LEN(s) - 1) DO s[i] := t[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE IntStr(n: LONGINT; VAR s: ARRAY OF CHAR);
VAR d: ARRAY 12 OF CHAR; i, k: LONGINT;
BEGIN
  i := 0; REPEAT d[i] := CHR(n MOD 10 + ORD("0")); n := n DIV 10; INC(i) UNTIL n = 0;
  k := 0; WHILE i > 0 DO DEC(i); s[k] := d[i]; INC(k) END; s[k] := 0X
END IntStr;

(* n bytes of b from pos on to the file descriptor fd, or to Out when its output goes elsewhere *)
PROCEDURE Emit(fd: LONGINT; VAR b: ARRAY OF CHAR; pos, n: LONGINT);
VAR r: LONGINT;
BEGIN
  IF Out.writer # NIL THEN
    WHILE n > 0 DO Out.Char(b[pos]); INC(pos); DEC(n) END
  ELSE
    WHILE n > 0 DO
      r := unixNet.Write0(fd, SYSTEM.ADR(b[pos]), n);
      IF r <= 0 THEN n := 0 ELSE INC(pos, r); DEC(n, r) END
    END
  END
END Emit;

PROCEDURE Output(s: Ch.Session; stream: LONGINT; VAR data: TLSBytes.Buffer; pos, n: LONGINT);
BEGIN
  IF stream = Ch.Stderr THEN Emit(2, data.data, pos, n) ELSE Emit(1, data.data, pos, n) END
END Output;

PROCEDURE ShowBanner(VAR text: ARRAY OF CHAR);
VAR n: LONGINT;
BEGIN
  n := 0; WHILE text[n] # 0X DO INC(n) END;
  Emit(2, text, 0, n)
END ShowBanner;

(* a line typed on the terminal, without echo if hidden *)
PROCEDURE Ask(prompt: ARRAY OF CHAR; hidden: BOOLEAN; VAR line: ARRAY OF CHAR): BOOLEAN;
VAR t, old: termios.Termios; ch: ARRAY 1 OF CHAR; i, r, n: LONGINT; nl: ARRAY 2 OF CHAR;
BEGIN
  n := 0; WHILE prompt[n] # 0X DO INC(n) END;
  Emit(2, prompt, 0, n);
  IF termios.Get(0, old) # 0 THEN line[0] := 0X; RETURN FALSE END;
  IF hidden THEN t := old; EXCL(t.lflag, termios.ECHO); r := termios.Set(0, t) END;
  i := 0;
  LOOP
    r := unixNet.Read0(0, SYSTEM.ADR(ch[0]), 1);
    IF (r <= 0) OR (ch[0] = 0AX) THEN EXIT END;
    IF (ch[0] # 0DX) & (i < LEN(line) - 1) THEN line[i] := ch[0]; INC(i) END
  END;
  line[i] := 0X;
  IF hidden THEN r := termios.Set(0, old); nl[0] := 0AX; Emit(2, nl, 0, 1) END;
  RETURN r >= 0
END Ask;

PROCEDURE Message(s: ARRAY OF CHAR);
VAR n: LONGINT; t: ARRAY 400 OF CHAR;
BEGIN
  COPY("ssh: ", t); Append(t, s); n := 0; WHILE t[n] # 0X DO INC(n) END;
  t[n] := 0AX; Emit(2, t, 0, n + 1)
END Message;

(* the host key of c against known_hosts: known passes, changed fails, unknown is asked about (or
  passes with /y) and then added *)
PROCEDURE CheckHost(c: T.Connection): BOOLEAN;
VAR file: Arg; fp: ARRAY 80 OF CHAR; answer: ARRAY 16 OF CHAR; m: ARRAY 300 OF CHAR; type: ARRAY 64 OF CHAR; res: LONGINT;
BEGIN
  K.KnownHostsFile(file); res := K.Check(file, c.host, c.port, c.hostKey);
  IF res = K.Known THEN RETURN TRUE END;
  K.Fingerprint(c.hostKey, fp); K.Type(c.hostKey, type);
  IF res = K.Changed THEN
    COPY("the host key of ", m); Append(m, c.host); Append(m, " changed: it is now "); Append(m, type);
    Append(m, " "); Append(m, fp); Message(m);
    Message("if that is right, remove its old line from ~/.ssh/known_hosts");
    RETURN FALSE
  END;
  COPY("the host key of ", m); Append(m, c.host); Append(m, " is not known: "); Append(m, type);
  Append(m, " "); Append(m, fp); Message(m);
  IF ~accept THEN
    IF ~Ask("accept it and remember it (yes/no)? ", FALSE, answer) OR (answer # "yes") THEN
      Message("not accepted (with /y it would be)"); RETURN FALSE
    END
  END;
  IF ~K.Add(file, c.host, c.port, c.hostKey) THEN Message(K.lastError) END;
  RETURN TRUE
END CheckHost;

(* the options and [user@]host of the arguments; the rest stays in the reader *)
PROCEDURE Options(VAR R: Texts.Reader): BOOLEAN;
VAR a: Arg; i, j: LONGINT;
BEGIN
  host := ""; user := ""; port := "22"; keyFile := ""; accept := FALSE;
  LOOP
    IF ~Texts.Arg(R, a) THEN RETURN FALSE END;
    IF a = "/p" THEN IF ~Texts.Arg(R, port) THEN RETURN FALSE END
    ELSIF a = "/i" THEN IF ~Texts.Arg(R, keyFile) THEN RETURN FALSE END
    ELSIF a = "/l" THEN IF ~Texts.Arg(R, user) THEN RETURN FALSE END
    ELSIF a = "/y" THEN accept := TRUE
    ELSE EXIT
    END
  END;
  i := 0; WHILE (a[i] # 0X) & (a[i] # "@") DO INC(i) END;
  IF a[i] = "@" THEN
    j := 0; WHILE j < i DO user[j] := a[j]; INC(j) END; user[j] := 0X;
    j := 0; INC(i); WHILE a[i] # 0X DO host[j] := a[i]; INC(i); INC(j) END; host[j] := 0X
  ELSE COPY(a, host)
  END;
  IF user = "" THEN Kernel.GetConfig("USER", user) END;
  IF user = "" THEN Kernel.GetConfig("LOGNAME", user) END;
  RETURN host # ""
END Options;

(* connected and logged in: with the key, then with a password if the server offers it *)
PROCEDURE Login(VAR c: T.Connection): BOOLEAN;
VAR k: K.Key; file, pw: Arg; f: Files.File; tries: LONGINT;
BEGIN
  IF ~T.Connect(host, port, CheckHost, c) THEN Message(T.lastError); RETURN FALSE END;
  A.showBanner := ShowBanner;
  IF ~A.Start(c) THEN Message(A.lastError); T.Close(c); RETURN FALSE END;
  IF keyFile # "" THEN COPY(keyFile, file)
  ELSE Kernel.GetConfig("HOME", file); Append(file, "/.ssh/id_ed25519")
  END;
  f := Files.Old(file);
  IF f # NIL THEN
    Files.Close(f);
    IF K.Load(file, k) THEN
      IF A.Key(c, user, k) THEN RETURN TRUE END
    ELSIF keyFile # "" THEN Message(K.lastError)
    END
  ELSIF keyFile # "" THEN Message("no such key file")
  ELSIF A.None(c, user) THEN RETURN TRUE
  END;
  tries := 0;
  WHILE c.open & W.Has(A.methods, "password") & (tries < 3) DO
    COPY(user, pw); Append(pw, "@"); Append(pw, host); Append(pw, "'s password: ");
    IF ~Ask(pw, TRUE, pw) THEN tries := 3
    ELSIF A.Password(c, user, pw) THEN RETURN TRUE
    ELSE Message(A.lastError); INC(tries)
    END
  END;
  IF c.open THEN Message("not logged in") ELSE Message(A.lastError) END;
  T.Close(c);
  RETURN FALSE
END Login;

(** ssh.Exec [options] [user@]host command ... *)
PROCEDURE Exec*;
VAR R: Texts.Reader; a, cmd: Arg; c: T.Connection; s: Ch.Session; m: ARRAY 64 OF CHAR;
BEGIN
  Texts.OpenArgs(R);
  IF ~Options(R) THEN
    Out.String("usage: ssh.Exec [/p port] [/i key] [/l user] [/y] [user@]host command ...   runs the command on host"); Out.Ln;
    RETURN
  END;
  cmd := "";
  WHILE Texts.Arg(R, a) DO IF cmd # "" THEN Append(cmd, " ") END; Append(cmd, a) END;
  IF cmd = "" THEN Message("no command (ssh.Connect gives a shell)"); RETURN END;
  IF ~Login(c) THEN RETURN END;
  IF ~Ch.OpenSession(c, Output, s) OR ~Ch.Exec(s, cmd) THEN Message(Ch.lastError); T.Close(c); RETURN END;
  WHILE ~s.closed DO IF ~Ch.Step(s) THEN Message(Ch.lastError) END END;
  T.Close(c);
  IF s.exitSignal # "" THEN COPY("ended by the signal ", m); Append(m, s.exitSignal); Message(m)
  ELSIF s.exitStatus > 0 THEN
    COPY("exit status ", m); IntStr(s.exitStatus, a); Append(m, a); Message(m)
  END
END Exec;

(* the terminal back as it was (also after a trap: Oberon0.OnStop) *)
PROCEDURE Restore;
VAR r: LONGINT;
BEGIN
  IF raw THEN r := termios.Set(0, saved); raw := FALSE END
END Restore;

(** ssh.Connect [options] [user@]host *)
PROCEDURE Connect*;
VAR R: Texts.Reader; c: T.Connection; s: Ch.Session; t: termios.Termios; term: ARRAY 64 OF CHAR;
  rows, cols, r2, c2, n, fd, max: LONGINT; rd: ARRAY 32 OF SET; tv: ARRAY 2 OF LONGINT; buf: ARRAY 4096 OF CHAR;
BEGIN
  Texts.OpenArgs(R);
  IF ~Options(R) THEN
    Out.String("usage: ssh.Connect [/p port] [/i key] [/l user] [/y] [user@]host   a shell on host"); Out.Ln;
    RETURN
  END;
  IF termios.Get(0, saved) # 0 THEN Message("no terminal: ssh.Connect needs one (ssh.Exec runs commands)"); RETURN END;
  IF ~termios.WinSize(1, rows, cols) THEN rows := 24; cols := 80 END;
  Kernel.GetConfig("TERM", term); IF term = "" THEN term := "xterm" END;
  IF ~Login(c) THEN RETURN END;
  IF ~Ch.OpenSession(c, Output, s) OR ~Ch.Pty(s, term, cols, rows) OR ~Ch.Shell(s) THEN
    Message(Ch.lastError); T.Close(c); RETURN
  END;
  t := saved; termios.MakeRaw(t); Oberon0.OnStop(Restore);
  IF termios.Set(0, t) = 0 THEN raw := TRUE END;
  fd := c.fd; max := fd; IF max < 1 THEN max := 1 END;
  WHILE ~s.closed & c.open DO
    n := 0; WHILE n < 32 DO rd[n] := {}; INC(n) END;
    INCL(rd[0], 0); INCL(rd[fd DIV 32], fd MOD 32);
    tv[0] := 0; tv[1] := 500000;
    n := unixNet.Select0(max + 1, SYSTEM.ADR(rd[0]), 0, 0, SYSTEM.ADR(tv[0]));
    IF n > 0 THEN
      IF (fd MOD 32) IN rd[fd DIV 32] THEN IF ~Ch.Step(s) THEN END END;
      IF ~s.closed & (0 IN rd[0]) THEN
        n := unixNet.Read0(0, SYSTEM.ADR(buf[0]), LEN(buf));
        IF n > 0 THEN IF ~Ch.Write(s, buf, 0, n) THEN END
        ELSIF n = 0 THEN IF Ch.SendEof(s) THEN END
        END
      END
    END;
    IF termios.WinSize(1, r2, c2) & ((r2 # rows) OR (c2 # cols)) THEN
      rows := r2; cols := c2; IF Ch.Resize(s, cols, rows) THEN END
    END
  END;
  Restore;
  T.Close(c);
  COPY("connection to ", buf); Append(buf, host); Append(buf, " closed"); Message(buf)
END Connect;

(** ssh.Help *)
PROCEDURE Help*;
BEGIN
  Out.String("ssh.Exec [options] [user@]host command ...   runs the command on host, its output here"); Out.Ln;
  Out.String("ssh.Connect [options] [user@]host             a shell on host in this terminal"); Out.Ln;
  Out.String("options: /p port (22), /i key file (~/.ssh/id_ed25519), /l user ($USER),"); Out.Ln;
  Out.String("  /y accepts an unknown host key and adds it to ~/.ssh/known_hosts"); Out.Ln;
  Out.String("Keys: Ed25519 in the format of OpenSSH, without a passphrase. Without a key that works,"); Out.Ln;
  Out.String("a password is asked for. Host keys are checked against ~/.ssh/known_hosts."); Out.Ln;
  Out.String("example: ssh.Exec /p 2222 me@example.org uname -a"); Out.Ln
END Help;

BEGIN
  raw := FALSE
END ssh.
