MODULE SSHAuth;  (** the user authentication of SSH (RFC 4252): with an Ed25519 key of the user or with a
  password *)

IMPORT TLSBytes, W := SSHWire, T := SSHTransport, Keys := SSHKeys;

CONST
  Request = 50; Failure = 51; Success = 52; Banner = 53; PkOk = 60;

TYPE
  BannerProc* = PROCEDURE (VAR text: ARRAY OF CHAR);

VAR
  lastError*: ARRAY 256 OF CHAR;
  methods*: ARRAY 256 OF CHAR;  (** the methods the server named when it last refused *)
  showBanner*: BannerProc;      (** shows the banner of a server; NIL: it is not shown *)

PROCEDURE SetError(s: ARRAY OF CHAR);
BEGIN COPY(s, lastError)
END SetError;

(** asks for the service of user authentication; the first step *)
PROCEDURE Start*(c: T.Connection): BOOLEAN;
BEGIN
  IF ~T.Service(c, "ssh-userauth") THEN COPY(T.lastError, lastError); RETURN FALSE END;
  RETURN TRUE
END Start;

(* the answer to a request: Success, Failure (methods set) or PkOk; banners are shown on the way *)
PROCEDURE Answer(c: T.Connection): LONGINT;
VAR p: TLSBytes.Buffer; r: W.Reader; t: LONGINT; text: ARRAY 4096 OF CHAR;
BEGIN
  LOOP
    IF ~T.Receive(c, p) THEN COPY(T.lastError, lastError); RETURN -1 END;
    t := ORD(p.data[0]);
    IF t = Banner THEN
      W.Open(r, 1); W.Text(p, r, text);
      IF r.ok & (showBanner # NIL) THEN showBanner(text) END
    ELSIF t = Failure THEN
      W.Open(r, 1); W.Text(p, r, methods); RETURN Failure
    ELSIF (t = Success) OR (t = PkOk) THEN RETURN t
    ELSE SetError("an unexpected message during authentication"); RETURN -1
    END
  END
END Answer;

PROCEDURE Head(VAR p: TLSBytes.Buffer; user, method: ARRAY OF CHAR);
BEGIN
  TLSBytes.Init(p); W.PutByte(p, Request); W.PutText(p, user); W.PutText(p, "ssh-connection"); W.PutText(p, method)
END Head;

(** the methods of authentication the server offers to user (in methods); TRUE if it lets the user in
  without any *)
PROCEDURE None*(c: T.Connection; user: ARRAY OF CHAR): BOOLEAN;
VAR p: TLSBytes.Buffer;
BEGIN
  Head(p, user, "none");
  IF ~T.Send(c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
  RETURN Answer(c) = Success
END None;

(** user with the key k; FALSE (lastError says why) if the server does not let the user in *)
PROCEDURE Key*(c: T.Connection; user: ARRAY OF CHAR; k: Keys.Key): BOOLEAN;
VAR p, data, blob, sig: TLSBytes.Buffer;
BEGIN
  lastError := "";
  Keys.PublicBlob(k, blob);
  TLSBytes.Init(data); W.PutString(data, c.sessionId);
  Head(p, user, "publickey"); W.PutBool(p, TRUE); W.PutText(p, k.type); W.PutString(p, blob);
  TLSBytes.Append(data, p);
  IF ~Keys.Sign(k, data, sig) THEN COPY(Keys.lastError, lastError); RETURN FALSE END;
  W.PutString(p, sig);
  IF ~T.Send(c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
  IF Answer(c) = Success THEN RETURN TRUE END;
  IF lastError = "" THEN SetError("the server does not take the key") END;
  RETURN FALSE
END Key;

(** user with password; FALSE (lastError says why) if the server does not let the user in *)
PROCEDURE Password*(c: T.Connection; user, password: ARRAY OF CHAR): BOOLEAN;
VAR p: TLSBytes.Buffer; a: LONGINT;
BEGIN
  lastError := "";
  Head(p, user, "password"); W.PutBool(p, FALSE); W.PutText(p, password);
  IF ~T.Send(c, p) THEN COPY(T.lastError, lastError); RETURN FALSE END;
  a := Answer(c);
  IF a = Success THEN RETURN TRUE
  ELSIF a = PkOk THEN SetError("the server wants the password changed")
  ELSIF lastError = "" THEN SetError("wrong user or password")
  END;
  RETURN FALSE
END Password;

BEGIN
  lastError := ""; methods := ""; showBanner := NIL
END SSHAuth.
