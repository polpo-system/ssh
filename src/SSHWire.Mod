MODULE SSHWire;  (** the data types of SSH (RFC 4251) on TLSBytes buffers: bytes, uint32, booleans,
  strings, mpints and name-lists, read and written; Base64 of binary data *)

IMPORT TLSBytes;

CONST
  NameLen* = 1024;  (** room for a name-list of KEXINIT *)

TYPE
  Reader* = RECORD
    pos*: LONGINT;  (** the next byte *)
    ok*: BOOLEAN    (** FALSE once a read went past the end *)
  END;

VAR
  b64: ARRAY 65 OF CHAR;

PROCEDURE Open*(VAR r: Reader; pos: LONGINT);
BEGIN r.pos := pos; r.ok := TRUE
END Open;

PROCEDURE Byte*(VAR b: TLSBytes.Buffer; VAR r: Reader): LONGINT;
BEGIN
  IF ~r.ok OR (r.pos >= b.len) THEN r.ok := FALSE; RETURN 0 END;
  INC(r.pos); RETURN ORD(b.data[r.pos - 1])
END Byte;

PROCEDURE Bool*(VAR b: TLSBytes.Buffer; VAR r: Reader): BOOLEAN;
BEGIN RETURN Byte(b, r) # 0
END Bool;

PROCEDURE Uint32*(VAR b: TLSBytes.Buffer; VAR r: Reader): LONGINT;
BEGIN
  IF ~r.ok OR (r.pos + 4 > b.len) THEN r.ok := FALSE; RETURN 0 END;
  INC(r.pos, 4); RETURN TLSBytes.GetBE32(b, r.pos - 4)
END Uint32;

(** a string, its bytes into s *)
PROCEDURE String*(VAR b: TLSBytes.Buffer; VAR r: Reader; VAR s: TLSBytes.Buffer);
VAR n: LONGINT;
BEGIN
  n := Uint32(b, r); TLSBytes.Init(s);
  IF ~r.ok OR (n < 0) OR (n > b.len - r.pos) THEN r.ok := FALSE; RETURN END;
  TLSBytes.Slice(b, r.pos, n, s); INC(r.pos, n)
END String;

(** a string as text into s, cut at LEN(s) - 1 characters *)
PROCEDURE Text*(VAR b: TLSBytes.Buffer; VAR r: Reader; VAR s: ARRAY OF CHAR);
VAR n, i: LONGINT;
BEGIN
  n := Uint32(b, r); s[0] := 0X;
  IF ~r.ok OR (n < 0) OR (n > b.len - r.pos) THEN r.ok := FALSE; RETURN END;
  i := 0; WHILE (i < n) & (i < LEN(s) - 1) DO s[i] := b.data[r.pos + i]; INC(i) END;
  s[i] := 0X; INC(r.pos, n)
END Text;

(** an mpint, its magnitude without leading zeros into s; FALSE for a negative number *)
PROCEDURE Mpint*(VAR b: TLSBytes.Buffer; VAR r: Reader; VAR s: TLSBytes.Buffer): BOOLEAN;
VAR raw: TLSBytes.Buffer; i: LONGINT;
BEGIN
  String(b, r, raw); TLSBytes.Init(s);
  IF ~r.ok THEN RETURN FALSE END;
  IF (raw.len > 0) & (ORD(raw.data[0]) >= 80H) THEN RETURN FALSE END;
  i := 0; WHILE (i < raw.len) & (raw.data[i] = 0X) DO INC(i) END;
  TLSBytes.Slice(raw, i, raw.len - i, s);
  RETURN TRUE
END Mpint;

PROCEDURE PutByte*(VAR b: TLSBytes.Buffer; x: LONGINT);
BEGIN TLSBytes.AppendByte(b, x)
END PutByte;

PROCEDURE PutBool*(VAR b: TLSBytes.Buffer; x: BOOLEAN);
BEGIN IF x THEN TLSBytes.AppendByte(b, 1) ELSE TLSBytes.AppendByte(b, 0) END
END PutBool;

PROCEDURE PutUint32*(VAR b: TLSBytes.Buffer; x: LONGINT);
BEGIN TLSBytes.PutBE32(b, x)
END PutUint32;

(** the text s (up to its 0X) as a string *)
PROCEDURE PutText*(VAR b: TLSBytes.Buffer; s: ARRAY OF CHAR);
VAR n: LONGINT;
BEGIN
  n := 0; WHILE (n < LEN(s)) & (s[n] # 0X) DO INC(n) END;
  TLSBytes.PutBE32(b, n); TLSBytes.AppendOpen(b, s, n)
END PutText;

(** the bytes of s as a string *)
PROCEDURE PutString*(VAR b, s: TLSBytes.Buffer);
BEGIN TLSBytes.PutBE32(b, s.len); TLSBytes.Append(b, s)
END PutString;

(** the unsigned big-endian number s as an mpint: no leading zeros, a 0 byte before a high bit *)
PROCEDURE PutMpint*(VAR b, s: TLSBytes.Buffer);
VAR i, n: LONGINT;
BEGIN
  i := 0; WHILE (i < s.len) & (s.data[i] = 0X) DO INC(i) END;
  n := s.len - i;
  IF (n > 0) & (ORD(s.data[i]) >= 80H) THEN
    TLSBytes.PutBE32(b, n + 1); TLSBytes.AppendByte(b, 0)
  ELSE TLSBytes.PutBE32(b, n)
  END;
  WHILE i < s.len DO TLSBytes.AppendChar(b, s.data[i]); INC(i) END
END PutMpint;

(* the name number k (0 the first) of the comma-separated list into name; FALSE if there is none *)
PROCEDURE Nth(VAR list: ARRAY OF CHAR; k: LONGINT; VAR name: ARRAY OF CHAR): BOOLEAN;
VAR i, j: LONGINT;
BEGIN
  i := 0;
  WHILE k > 0 DO
    WHILE (i < LEN(list)) & (list[i] # 0X) & (list[i] # ",") DO INC(i) END;
    IF (i >= LEN(list)) OR (list[i] = 0X) THEN RETURN FALSE END;
    INC(i); DEC(k)
  END;
  IF (i >= LEN(list)) OR (list[i] = 0X) THEN RETURN FALSE END;
  j := 0;
  WHILE (i < LEN(list)) & (list[i] # 0X) & (list[i] # ",") & (j < LEN(name) - 1) DO name[j] := list[i]; INC(i); INC(j) END;
  name[j] := 0X;
  RETURN TRUE
END Nth;

(** name is one of the names of list *)
PROCEDURE Has*(list, name: ARRAY OF CHAR): BOOLEAN;
VAR k: LONGINT; n: ARRAY 256 OF CHAR;
BEGIN
  k := 0;
  WHILE Nth(list, k, n) DO
    IF n = name THEN RETURN TRUE END;
    INC(k)
  END;
  RETURN FALSE
END Has;

(** the first name of client that server has too, into name; FALSE if they have none in common *)
PROCEDURE Choose*(client, server: ARRAY OF CHAR; VAR name: ARRAY OF CHAR): BOOLEAN;
VAR k: LONGINT;
BEGIN
  k := 0;
  WHILE Nth(client, k, name) DO
    IF Has(server, name) THEN RETURN TRUE END;
    INC(k)
  END;
  name[0] := 0X;
  RETURN FALSE
END Choose;

(** the bytes of b in Base64 into s, with "=" padding if pad *)
PROCEDURE Base64*(VAR b: TLSBytes.Buffer; pad: BOOLEAN; VAR s: ARRAY OF CHAR);
VAR i, j, v, n: LONGINT;
BEGIN
  i := 0; j := 0;
  WHILE (i < b.len) & (j + 4 < LEN(s)) DO
    n := b.len - i; IF n > 3 THEN n := 3 END;
    v := LONG(ORD(b.data[i])) * 10000H;
    IF n > 1 THEN INC(v, LONG(ORD(b.data[i + 1])) * 100H) END;
    IF n > 2 THEN INC(v, LONG(ORD(b.data[i + 2]))) END;
    s[j] := b64[v DIV 40000H]; s[j + 1] := b64[v DIV 1000H MOD 64]; INC(j, 2);
    IF n > 1 THEN s[j] := b64[v DIV 40H MOD 64]; INC(j) ELSIF pad THEN s[j] := "="; INC(j) END;
    IF n > 2 THEN s[j] := b64[v MOD 64]; INC(j) ELSIF pad THEN s[j] := "="; INC(j) END;
    INC(i, 3)
  END;
  s[j] := 0X
END Base64;

BEGIN
  b64 := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
END SSHWire.
