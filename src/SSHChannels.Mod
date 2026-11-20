MODULE SSHChannels;  (** a session of the connection protocol of SSH (RFC 4254): a command or a shell,
  with a terminal if wanted; data both ways within the windows, the exit status *)

IMPORT TLSBytes, W := SSHWire, T := SSHTransport;

CONST
  GlobalRequest = 80; RequestFailure = 82; Open = 90; OpenConfirmation = 91; OpenFailure = 92;
  WindowAdjust = 93; Data = 94; ExtendedData = 95; Eof = 96; Close = 97; Request = 98;
  Success = 99; Failure = 100;
  Window = 200000H;  (* the window we give the server *)
  MaxData = 16384;   (* the largest data packet we take *)
  Stdout* = 0; Stderr* = 1;  (** the streams of a session *)

TYPE
  Session* = POINTER TO SessionDesc;

  Output* = PROCEDURE (s: Session; stream: LONGINT; VAR data: TLSBytes.Buffer; pos, n: LONGINT);
    (** takes n bytes of data, from pos on, of the stream Stdout or Stderr *)

  SessionDesc* = RECORD
    c*: T.Connection;
    output*: Output;
    exitStatus*: LONGINT;          (** the exit status of the command, -1 before or with a signal *)
    exitSignal*: ARRAY 32 OF CHAR;  (** the signal that ended it, or "" *)
    eof*, closed*: BOOLEAN;        (** the server sent EOF, the channel is closed *)
    remote, window, remoteWindow, remoteMax: LONGINT;
    closeSent: BOOLEAN
  END;

VAR
  lastError*: ARRAY 256 OF CHAR;

PROCEDURE SetError(s: ARRAY OF CHAR);
BEGIN COPY(s, lastError)
END SetError;

(* answers a global request or a channel request the session does not know: a failure if a reply is
  wanted *)
PROCEDURE Refuse(s: Session; VAR p: TLSBytes.Buffer; channel: BOOLEAN): BOOLEAN;
VAR r: W.Reader; name: ARRAY 64 OF CHAR; want: BOOLEAN; q: TLSBytes.Buffer;
BEGIN
  W.Open(r, 1);
  IF channel THEN IF W.Uint32(p, r) = 0 THEN END END;
  W.Text(p, r, name); want := W.Bool(p, r);
  IF r.ok & want THEN
    TLSBytes.Init(q);
    IF channel THEN W.PutByte(q, Failure); W.PutUint32(q, s.remote) ELSE W.PutByte(q, RequestFailure) END;
    RETURN T.Send(s.c, q)
  END;
  RETURN TRUE
END Refuse;

(* a request on the channel: exit-status and exit-signal are kept, others refused *)
PROCEDURE ChannelRequest(s: Session; VAR p: TLSBytes.Buffer): BOOLEAN;
VAR r: W.Reader; name: ARRAY 64 OF CHAR;
BEGIN
  W.Open(r, 5); W.Text(p, r, name);
  IF name = "exit-status" THEN
    IF W.Bool(p, r) THEN END; s.exitStatus := W.Uint32(p, r); RETURN TRUE
  ELSIF name = "exit-signal" THEN
    IF W.Bool(p, r) THEN END; W.Text(p, r, s.exitSignal); RETURN TRUE
  END;
  RETURN Refuse(s, p, TRUE)
END ChannelRequest;

PROCEDURE SendClose(s: Session): BOOLEAN;
VAR q: TLSBytes.Buffer;
BEGIN
  IF s.closeSent THEN RETURN TRUE END;
  s.closeSent := TRUE;
  TLSBytes.Init(q); W.PutByte(q, Close); W.PutUint32(q, s.remote);
  RETURN T.Send(s.c, q)
END SendClose;

(* the message p of the server: data goes to s.output, window adjustments, EOF, CLOSE and requests
  change the session *)
PROCEDURE Dispatch(s: Session; VAR p: TLSBytes.Buffer): BOOLEAN;
VAR q: TLSBytes.Buffer; r: W.Reader; t, n, stream: LONGINT;
BEGIN
  t := ORD(p.data[0]); W.Open(r, 5);
  IF (t = Data) OR (t = ExtendedData) THEN
    stream := Stdout; IF t = ExtendedData THEN stream := W.Uint32(p, r) END;
    n := W.Uint32(p, r);
    IF ~r.ok OR (n < 0) OR (n > p.len - r.pos) THEN SetError("malformed data"); RETURN FALSE END;
    IF s.output # NIL THEN s.output(s, stream, p, r.pos, n) END;
    DEC(s.window, n);
    IF s.window < Window DIV 2 THEN
      TLSBytes.Init(q); W.PutByte(q, WindowAdjust); W.PutUint32(q, s.remote); W.PutUint32(q, Window - s.window);
      s.window := Window;
      IF ~T.Send(s.c, q) THEN COPY(T.lastError, lastError); RETURN FALSE END
    END
  ELSIF t = WindowAdjust THEN s.remoteWindow := TLSBytes.Add32(s.remoteWindow, W.Uint32(p, r))
  ELSIF t = Eof THEN s.eof := TRUE
  ELSIF t = Close THEN
    s.closed := TRUE;
    IF ~SendClose(s) THEN COPY(T.lastError, lastError); RETURN FALSE END
  ELSIF t = Request THEN
    IF ~ChannelRequest(s, p) THEN COPY(T.lastError, lastError); RETURN FALSE END
  ELSIF t = GlobalRequest THEN
    IF ~Refuse(s, p, FALSE) THEN COPY(T.lastError, lastError); RETURN FALSE END
  END;
  RETURN TRUE
END Dispatch;

(** takes the next message of the server (see Dispatch); FALSE when the connection ended *)
PROCEDURE Step*(s: Session): BOOLEAN;
VAR p: TLSBytes.Buffer;
BEGIN
  IF ~T.Receive(s.c, p) THEN COPY(T.lastError, lastError); s.closed := TRUE; RETURN FALSE END;
  RETURN Dispatch(s, p)
END Step;

(* the answer to a channel request with want reply: TRUE for success *)
PROCEDURE Reply(s: Session): BOOLEAN;
VAR p: TLSBytes.Buffer; t: LONGINT;
BEGIN
  LOOP
    IF ~T.Receive(s.c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
    t := ORD(p.data[0]);
    IF t = Success THEN RETURN TRUE
    ELSIF t = Failure THEN SetError("the server refused the request"); RETURN FALSE
    ELSIF ~Dispatch(s, p) THEN RETURN FALSE
    END
  END
END Reply;

(** a session channel on the connection c, its output to output *)
PROCEDURE OpenSession*(c: T.Connection; output: Output; VAR s: Session): BOOLEAN;
VAR p: TLSBytes.Buffer; r: W.Reader; t: LONGINT;
BEGIN
  lastError := ""; s := NIL;
  TLSBytes.Init(p); W.PutByte(p, Open); W.PutText(p, "session");
  W.PutUint32(p, 0); W.PutUint32(p, Window); W.PutUint32(p, MaxData);
  IF ~T.Send(c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
  NEW(s); s.c := c; s.output := output; s.exitStatus := -1; s.exitSignal := "";
  s.eof := FALSE; s.closed := FALSE; s.closeSent := FALSE; s.window := Window;
  LOOP
    IF ~T.Receive(c, p) THEN COPY(T.lastError, lastError); s := NIL; RETURN FALSE END;
    t := ORD(p.data[0]);
    IF t = OpenConfirmation THEN EXIT
    ELSIF t = OpenFailure THEN SetError("the server refused a session"); s := NIL; RETURN FALSE
    ELSIF t = GlobalRequest THEN
      IF ~Refuse(s, p, FALSE) THEN COPY(T.lastError, lastError); s := NIL; RETURN FALSE END
    END
  END;
  W.Open(r, 5); s.remote := W.Uint32(p, r); s.remoteWindow := W.Uint32(p, r); s.remoteMax := W.Uint32(p, r);
  IF ~r.ok THEN SetError("a malformed confirmation"); s := NIL; RETURN FALSE END;
  IF s.remoteMax > MaxData THEN s.remoteMax := MaxData END;
  RETURN TRUE
END OpenSession;

PROCEDURE RequestHead(s: Session; VAR p: TLSBytes.Buffer; name: ARRAY OF CHAR; want: BOOLEAN);
BEGIN
  TLSBytes.Init(p); W.PutByte(p, Request); W.PutUint32(p, s.remote); W.PutText(p, name); W.PutBool(p, want)
END RequestHead;

(** a terminal for the session: its type (TERM), columns and rows *)
PROCEDURE Pty*(s: Session; term: ARRAY OF CHAR; cols, rows: LONGINT): BOOLEAN;
VAR p, modes: TLSBytes.Buffer;
BEGIN
  RequestHead(s, p, "pty-req", TRUE); W.PutText(p, term);
  W.PutUint32(p, cols); W.PutUint32(p, rows); W.PutUint32(p, 0); W.PutUint32(p, 0);
  TLSBytes.Init(modes); W.PutByte(modes, 0); W.PutString(p, modes);
  IF ~T.Send(s.c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
  RETURN Reply(s)
END Pty;

(** runs the command on the server *)
PROCEDURE Exec*(s: Session; command: ARRAY OF CHAR): BOOLEAN;
VAR p: TLSBytes.Buffer;
BEGIN
  RequestHead(s, p, "exec", TRUE); W.PutText(p, command);
  IF ~T.Send(s.c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
  RETURN Reply(s)
END Exec;

(** starts the shell of the user *)
PROCEDURE Shell*(s: Session): BOOLEAN;
VAR p: TLSBytes.Buffer;
BEGIN
  RequestHead(s, p, "shell", TRUE);
  IF ~T.Send(s.c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
  RETURN Reply(s)
END Shell;

(** tells the server the new size of the terminal *)
PROCEDURE Resize*(s: Session; cols, rows: LONGINT): BOOLEAN;
VAR p: TLSBytes.Buffer;
BEGIN
  RequestHead(s, p, "window-change", FALSE);
  W.PutUint32(p, cols); W.PutUint32(p, rows); W.PutUint32(p, 0); W.PutUint32(p, 0);
  RETURN T.Send(s.c, p)
END Resize;

(** sends n bytes of data, from pos on, waiting for room in the window of the server *)
PROCEDURE Write*(s: Session; VAR data: ARRAY OF CHAR; pos, n: LONGINT): BOOLEAN;
VAR p: TLSBytes.Buffer; k, i: LONGINT;
BEGIN
  WHILE n > 0 DO
    WHILE (s.remoteWindow <= 0) & ~s.closed DO
      IF ~Step(s) THEN RETURN FALSE END
    END;
    IF s.closed THEN SetError("the session is closed"); RETURN FALSE END;
    k := n; IF k > s.remoteMax THEN k := s.remoteMax END; IF k > s.remoteWindow THEN k := s.remoteWindow END;
    TLSBytes.Init(p); W.PutByte(p, Data); W.PutUint32(p, s.remote); W.PutUint32(p, k);
    i := 0; WHILE i < k DO TLSBytes.AppendChar(p, data[pos + i]); INC(i) END;
    INC(pos, k); DEC(n, k); DEC(s.remoteWindow, k);
    IF ~T.Send(s.c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END
  END;
  RETURN TRUE
END Write;

(** tells the server that no more data comes *)
PROCEDURE SendEof*(s: Session): BOOLEAN;
VAR p: TLSBytes.Buffer;
BEGIN
  TLSBytes.Init(p); W.PutByte(p, Eof); W.PutUint32(p, s.remote);
  RETURN T.Send(s.c, p)
END SendEof;

(** closes the channel and waits for the server to close it too *)
PROCEDURE CloseSession*(s: Session);
BEGIN
  IF (s = NIL) OR s.closed & s.closeSent THEN RETURN END;
  IF SendClose(s) THEN
    WHILE ~s.closed DO IF ~Step(s) THEN s.closed := TRUE END END
  END
END CloseSession;

BEGIN
  lastError := ""
END SSHChannels.
