MODULE SSH;  (** an SSH client in the desktop: a shell of a server in a VT100 terminal viewer *)

(* SSH.Open [options] [user@]host   a viewer with a shell on host
   SSH.Close                        (in its menu) ends the connection
   options: /p port, /i key file (default ~/.ssh/id_ed25519), /l user (default $USER),
   /y: accept an unknown host key and add it to ~/.ssh/known_hosts *)

IMPORT Input, Fonts, Texts, Oberon, Viewers, MenuViewers, TextFrames, TerminalFrames, Terminals, Kernel, Files,
  TLSBytes, W := SSHWire, T := SSHTransport, A := SSHAuth, Ch := SSHChannels, K := SSHKeys;

CONST
  Rows = 24; Cols = 80;
  Menu = "System.Close  System.Grow  SSH.Close";
  AskPassword = 1; Running = 2; Closed = 3;  (* the states of a terminal *)

TYPE
  Arg = ARRAY 1024 OF CHAR;

  Terminal = POINTER TO TerminalDesc;
  Task = POINTER TO TaskDesc;

  TerminalDesc = RECORD (Terminals.TerminalDesc)
    c: T.Connection;
    s: Ch.Session;
    state, tries, pwLen: LONGINT;
    user: ARRAY 256 OF CHAR;
    pw: ARRAY 256 OF CHAR;
    task: Task;
    viewer: Viewers.Viewer;
    next: Terminal
  END;

  TaskDesc = RECORD (Oberon.TaskDesc)
    t: Terminal
  END;

VAR
  log: Texts.Writer;
  terminals: Terminal;  (* the open ones, for Output *)
  host, user, port, keyFile: Arg;
  accept: BOOLEAN;

PROCEDURE Append(VAR s: ARRAY OF CHAR; t: ARRAY OF CHAR);
VAR i, j: LONGINT;
BEGIN
  i := 0; WHILE s[i] # 0X DO INC(i) END;
  j := 0; WHILE (t[j] # 0X) & (i < LEN(s) - 1) DO s[i] := t[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE Log(s: ARRAY OF CHAR);
BEGIN Texts.WriteString(log, "SSH: "); Texts.WriteString(log, s); Texts.WriteLn(log); Texts.Append(Oberon.Log, log.buf)
END Log;

(* the text s in the terminal t, then a line end if ln *)
PROCEDURE Show(t: Terminal; s: ARRAY OF CHAR; ln: BOOLEAN);
VAR i: LONGINT;
BEGIN
  i := 0; WHILE s[i] # 0X DO Terminals.Receive(t, s[i]); INC(i) END;
  IF ln THEN Terminals.Receive(t, 0DX); Terminals.Receive(t, 0AX) END;
  Terminals.Flush(t)
END Show;

PROCEDURE Output(s: Ch.Session; stream: LONGINT; VAR data: TLSBytes.Buffer; pos, n: LONGINT);
VAR t: Terminal;
BEGIN
  t := terminals; WHILE (t # NIL) & (t.s # s) DO t := t.next END;
  IF t # NIL THEN
    WHILE n > 0 DO Terminals.Receive(t, data.data[pos]); INC(pos); DEC(n) END;
    Terminals.Flush(t)
  END
END Output;

PROCEDURE ShowBanner(VAR text: ARRAY OF CHAR);
BEGIN Texts.WriteString(log, text); Texts.Append(Oberon.Log, log.buf)
END ShowBanner;

(* the host key of c against known_hosts: known passes, changed fails, unknown passes with /y and
  is added *)
PROCEDURE CheckHost(c: T.Connection): BOOLEAN;
VAR file: Arg; fp: ARRAY 80 OF CHAR; m: ARRAY 300 OF CHAR; type: ARRAY 64 OF CHAR; res: LONGINT;
BEGIN
  K.KnownHostsFile(file); res := K.Check(file, c.host, c.port, c.hostKey);
  IF res = K.Known THEN RETURN TRUE END;
  K.Fingerprint(c.hostKey, fp); K.Type(c.hostKey, type);
  COPY("the host key of ", m); Append(m, c.host);
  IF res = K.Changed THEN Append(m, " changed: it is now ") ELSE Append(m, " is not known: ") END;
  Append(m, type); Append(m, " "); Append(m, fp); Log(m);
  IF res = K.Changed THEN Log("if that is right, remove its old line from ~/.ssh/known_hosts"); RETURN FALSE END;
  IF ~accept THEN Log("SSH.Open /y ... accepts it"); RETURN FALSE END;
  IF ~K.Add(file, c.host, c.port, c.hostKey) THEN Log(K.lastError) END;
  RETURN TRUE
END CheckHost;

(* the end of the connection of t *)
PROCEDURE Finish(t: Terminal);
VAR p, q: Terminal;
BEGIN
  IF t.state = Closed THEN RETURN END;
  t.state := Closed; T.Close(t.c);
  Show(t, "", TRUE); Show(t, "connection closed", TRUE);
  IF terminals = t THEN terminals := t.next
  ELSE p := terminals; q := NIL; WHILE (p # NIL) & (p # t) DO q := p; p := p.next END;
    IF (p # NIL) & (q # NIL) THEN q.next := p.next END
  END;
  IF t.task # NIL THEN Oberon.Remove(t.task); t.task := NIL END
END Finish;

(* the shell of the session of t: a terminal of the size of t, VT100 *)
PROCEDURE StartShell(t: Terminal);
BEGIN
  IF Ch.OpenSession(t.c, Output, t.s) & Ch.Pty(t.s, "vt100", Cols, Rows) & Ch.Shell(t.s) THEN t.state := Running
  ELSE Show(t, Ch.lastError, TRUE); Finish(t)
  END
END StartShell;

PROCEDURE Prompt(t: Terminal);
VAR m: ARRAY 600 OF CHAR;
BEGIN
  COPY(t.user, m); Append(m, "@"); Append(m, t.c.host); Append(m, "'s password: ");
  Show(t, m, FALSE); t.pwLen := 0; t.state := AskPassword
END Prompt;

PROCEDURE Send0(tt: Terminals.Terminal; ch: CHAR);
VAR b: ARRAY 1 OF CHAR; i: LONGINT;
BEGIN
  WITH tt: Terminal DO
    IF tt.state = Running THEN
      b[0] := ch; IF ~Ch.Write(tt.s, b, 0, 1) THEN Finish(tt) END
    ELSIF tt.state = AskPassword THEN
      IF ch = 0DX THEN
        tt.pw[tt.pwLen] := 0X; Show(tt, "", TRUE);
        IF A.Password(tt.c, tt.user, tt.pw) THEN StartShell(tt)
        ELSE
          Show(tt, A.lastError, TRUE); INC(tt.tries);
          IF tt.c.open & (tt.tries < 3) THEN Prompt(tt) ELSE Finish(tt) END
        END;
        i := 0; WHILE i < LEN(tt.pw) DO tt.pw[i] := 0X; INC(i) END
      ELSIF (ch = 7FX) OR (ch = 08X) THEN IF tt.pwLen > 0 THEN DEC(tt.pwLen) END
      ELSIF (ch >= " ") & (tt.pwLen < LEN(tt.pw) - 1) THEN tt.pw[tt.pwLen] := ch; INC(tt.pwLen)
      END
    END
  END
END Send0;

PROCEDURE Break0(t: Terminals.Terminal);
END Break0;

PROCEDURE Receiver(me: Oberon.Task);
VAR t: Terminal;
BEGIN
  WITH me: Task DO
    t := me.t;
    IF t.viewer.state = 0 THEN Finish(t)  (* the viewer was closed *)
    ELSIF t.state = Running THEN
      WHILE (t.state = Running) & t.c.open & ~t.s.closed & T.Ready(t.c) DO
        IF ~Ch.Step(t.s) THEN END
      END;
      IF (t.state = Running) & (t.s.closed OR ~t.c.open) THEN Finish(t) END
    ELSIF t.state = AskPassword THEN
      IF ~t.c.open THEN Finish(t) END
    END;
    me.time := Oberon.Time() + Input.TimeUnit DIV 50
  END
END Receiver;

(* the options and [user@]host of the arguments *)
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

(** SSH.Open [/p port] [/i key] [/l user] [/y] [user@]host *)
PROCEDURE Open*;
VAR R: Texts.Reader; c: T.Connection; t: Terminal; F: TerminalFrames.Frame; V: MenuViewers.Viewer;
  task: Task; k: K.Key; file: Arg; f: Files.File; x, y: INTEGER; in: BOOLEAN;
BEGIN
  Texts.OpenArgs(R);
  IF ~Options(R) THEN Log("usage: SSH.Open [/p port] [/i key] [/l user] [/y] [user@]host"); RETURN END;
  IF ~T.Connect(host, port, CheckHost, c) THEN Log(T.lastError); RETURN END;
  A.showBanner := ShowBanner;
  IF ~A.Start(c) THEN Log(A.lastError); T.Close(c); RETURN END;
  IF keyFile # "" THEN COPY(keyFile, file) ELSE Kernel.GetConfig("HOME", file); Append(file, "/.ssh/id_ed25519") END;
  in := FALSE; f := Files.Old(file);
  IF f # NIL THEN
    Files.Close(f);
    IF K.Load(file, k) THEN in := A.Key(c, user, k) ELSIF keyFile # "" THEN Log(K.lastError) END
  ELSIF keyFile # "" THEN Log("no such key file")
  ELSE in := A.None(c, user)
  END;
  IF ~in & (~c.open OR ~W.Has(A.methods, "password")) THEN Log("not logged in"); T.Close(c); RETURN END;
  NEW(t); Terminals.Open(t, TextFrames.Text(""), Send0, Break0, TerminalFrames.NotifyDisplay, Rows);
  t.c := c; COPY(user, t.user); t.tries := 0; t.next := terminals; terminals := t;
  NEW(F); TerminalFrames.Open(F, TerminalFrames.Handle, t, Fonts.This("Ttyp0-16-Unicode.Scn.Fnt"));
  Oberon.AllocateUserViewer(Oberon.Mouse.X, x, y);
  COPY(user, file); Append(file, "@"); Append(file, host);
  V := MenuViewers.New(TextFrames.NewMenu(file, Menu), F, TextFrames.menuH, x, y); t.viewer := V;
  NEW(task); task.safe := FALSE; task.handle := Receiver; task.time := Oberon.Time(); task.t := t; t.task := task;
  Oberon.Install(task);
  IF in THEN StartShell(t) ELSE Prompt(t) END
END Open;

(** SSH.Close: ends the connection of the viewer of the command *)
PROCEDURE Close*;
VAR F: TerminalFrames.Frame;
BEGIN
  IF (Oberon.Par.vwr # NIL) & (Oberon.Par.vwr.dsc # NIL) & (Oberon.Par.vwr.dsc.next IS TerminalFrames.Frame) THEN
    F := Oberon.Par.vwr.dsc.next(TerminalFrames.Frame);
    IF F.text IS Terminal THEN Finish(F.text(Terminal)) END
  END
END Close;

BEGIN
  Texts.OpenWriter(log); terminals := NIL
END SSH.
