MODULE SSHKeys;  (** keys of SSH: the signatures of servers checked (ssh-ed25519, ecdsa-sha2-nistp256,
  rsa-sha2-256 and rsa-sha2-512), fingerprints, the known_hosts file of OpenSSH, and Ed25519 keys of
  users in the file format of OpenSSH, which sign *)

IMPORT Files, Kernel, TLSBytes, TLSBase64, TLSSHA256, TLSSHA512, TLSEd25519, TLSECDSA, TLSRSA, W := SSHWire;

CONST
  Unknown* = 0; Known* = 1; Changed* = 2;  (** what known_hosts says of a host key *)
  LineLen = 4096;

TYPE
  Key* = POINTER TO KeyDesc;  (** a key of the user *)
  KeyDesc* = RECORD
    type*: ARRAY 32 OF CHAR;  (** "ssh-ed25519" *)
    comment*: ARRAY 256 OF CHAR;
    seed, pub: ARRAY 32 OF CHAR
  END;

  Line = ARRAY LineLen OF CHAR;

VAR
  lastError*: ARRAY 256 OF CHAR;

PROCEDURE SetError(s: ARRAY OF CHAR);
BEGIN COPY(s, lastError)
END SetError;

(** the type of the key blob (its first string) into type *)
PROCEDURE Type*(VAR blob: TLSBytes.Buffer; VAR type: ARRAY OF CHAR);
VAR r: W.Reader;
BEGIN W.Open(r, 0); W.Text(blob, r, type)
END Type;

PROCEDURE Append(VAR s: ARRAY OF CHAR; t: ARRAY OF CHAR);
VAR i, j: LONGINT;
BEGIN
  i := 0; WHILE s[i] # 0X DO INC(i) END;
  j := 0; WHILE (t[j] # 0X) & (i < LEN(s) - 1) DO s[i] := t[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

(** the fingerprint of a key blob as OpenSSH shows it: "SHA256:" and the Base64 of its SHA-256 *)
PROCEDURE Fingerprint*(VAR blob: TLSBytes.Buffer; VAR fp: ARRAY OF CHAR);
VAR d: TLSSHA256.Digest; b: TLSBytes.Buffer; s: ARRAY 64 OF CHAR;
BEGIN
  TLSSHA256.DigestBuffer(blob, d); TLSSHA256.DigestToBuffer(d, b); W.Base64(b, FALSE, s);
  COPY("SHA256:", fp); Append(fp, s)
END Fingerprint;

(* the bytes of b into a, which must have exactly b.len elements *)
PROCEDURE ToArray(VAR b: TLSBytes.Buffer; VAR a: ARRAY OF CHAR): BOOLEAN;
VAR i: LONGINT;
BEGIN
  IF b.len # LEN(a) THEN RETURN FALSE END;
  i := 0; WHILE i < b.len DO a[i] := b.data[i]; INC(i) END;
  RETURN TRUE
END ToArray;

(** the signature sig (a signature blob of SSH) of data by the key blob, for the host key algorithm
  alg; FALSE (lastError says why) if it does not hold *)
PROCEDURE Verify*(alg: ARRAY OF CHAR; VAR blob, sig, data: TLSBytes.Buffer): BOOLEAN;
VAR kr, sr, ir: W.Reader; ktype, stype, curve: ARRAY 64 OF CHAR; a, b, inner, hash, rr, ss: TLSBytes.Buffer;
  pub: ARRAY 32 OF CHAR; s64: ARRAY 64 OF CHAR; d: TLSSHA256.Digest; ok: BOOLEAN; h: LONGINT;
BEGIN
  W.Open(kr, 0); W.Text(blob, kr, ktype); W.Open(sr, 0); W.Text(sig, sr, stype);
  IF ~kr.ok OR ~sr.ok THEN SetError("a malformed key or signature"); RETURN FALSE END;
  IF stype # alg THEN SetError("a signature of another algorithm than agreed"); RETURN FALSE END;
  IF alg = "ssh-ed25519" THEN
    IF ktype # alg THEN SetError("not an Ed25519 key"); RETURN FALSE END;
    W.String(blob, kr, a); W.String(sig, sr, b);
    ok := kr.ok & sr.ok & ToArray(a, pub) & ToArray(b, s64) & TLSEd25519.Verify(pub, data.data, 0, data.len, s64)
  ELSIF alg = "ecdsa-sha2-nistp256" THEN
    IF ktype # alg THEN SetError("not an ECDSA P-256 key"); RETURN FALSE END;
    W.Text(blob, kr, curve); W.String(blob, kr, a); W.String(sig, sr, inner);
    W.Open(ir, 0);
    ok := kr.ok & sr.ok & (curve = "nistp256") & W.Mpint(inner, ir, rr) & W.Mpint(inner, ir, ss);
    IF ok THEN
      TLSSHA256.DigestBuffer(data, d); TLSSHA256.DigestToBuffer(d, hash);
      ok := ir.ok & TLSECDSA.Verify(TLSECDSA.P256, a, hash, rr, ss)
    END
  ELSIF (alg = "rsa-sha2-256") OR (alg = "rsa-sha2-512") THEN
    IF ktype # "ssh-rsa" THEN SetError("not an RSA key"); RETURN FALSE END;
    ok := W.Mpint(blob, kr, b) & W.Mpint(blob, kr, a);  (* e, n *)
    W.String(sig, sr, inner);
    IF alg = "rsa-sha2-256" THEN h := TLSRSA.SHA256 ELSE h := TLSRSA.SHA512 END;
    ok := ok & kr.ok & sr.ok & (a.len >= 256) & TLSRSA.Hash(h, data, hash) & TLSRSA.VerifyPKCS1(a, b, h, hash, inner)
  ELSE SetError("an unknown host key algorithm"); RETURN FALSE
  END;
  IF ~ok THEN SetError("the signature of the server does not hold") END;
  RETURN ok
END Verify;

(* ----- known_hosts ----- *)

(** the file known_hosts of the user: $HOME/.ssh/known_hosts *)
PROCEDURE KnownHostsFile*(VAR name: ARRAY OF CHAR);
BEGIN
  Kernel.GetConfig("HOME", name);
  IF name[0] = 0X THEN COPY(".", name) END;
  Append(name, "/.ssh/known_hosts")
END KnownHostsFile;

(* the name of host as known_hosts writes it: host, or [host]:port for a port other than 22 *)
PROCEDURE EntryName(host: ARRAY OF CHAR; port: LONGINT; VAR name: ARRAY OF CHAR);
VAR d, s: ARRAY 12 OF CHAR; i, k: LONGINT;
BEGIN
  IF port = 22 THEN COPY(host, name)
  ELSE
    COPY("[", name); Append(name, host); Append(name, "]:");
    i := 0; REPEAT d[i] := CHR(port MOD 10 + ORD("0")); port := port DIV 10; INC(i) UNTIL port = 0;
    k := 0; WHILE k < i DO s[k] := d[i - 1 - k]; INC(k) END;
    s[i] := 0X; Append(name, s)
  END
END EntryName;

(* the next line of R into line; FALSE at the end of the file *)
PROCEDURE ReadLine(VAR R: Files.Rider; VAR line: Line): BOOLEAN;
VAR ch: CHAR; i: LONGINT;
BEGIN
  i := 0; Files.Read(R, ch);
  IF R.eof THEN RETURN FALSE END;
  WHILE ~R.eof & (ch # 0AX) DO
    IF (i < LEN(line) - 1) & (ch # 0DX) THEN line[i] := ch; INC(i) END;
    Files.Read(R, ch)
  END;
  line[i] := 0X;
  RETURN TRUE
END ReadLine;

(* the field number k (0 the first, separated by blanks) of line into f *)
PROCEDURE Field(VAR line: Line; k: LONGINT; VAR f: ARRAY OF CHAR);
VAR i, j: LONGINT;
BEGIN
  i := 0;
  LOOP
    WHILE (line[i] = " ") OR (line[i] = 9X) DO INC(i) END;
    IF (k = 0) OR (line[i] = 0X) THEN EXIT END;
    WHILE (line[i] # 0X) & (line[i] # " ") & (line[i] # 9X) DO INC(i) END;
    DEC(k)
  END;
  j := 0;
  WHILE (line[i] # 0X) & (line[i] # " ") & (line[i] # 9X) & (j < LEN(f) - 1) DO f[j] := line[i]; INC(i); INC(j) END;
  f[j] := 0X
END Field;

(* the names of the comma-separated list names include name *)
PROCEDURE NameIn(VAR names: ARRAY OF CHAR; VAR name: ARRAY OF CHAR): BOOLEAN;
VAR i, j: LONGINT;
BEGIN
  i := 0;
  WHILE names[i] # 0X DO
    j := 0; WHILE (name[j] # 0X) & (names[i + j] = name[j]) DO INC(j) END;
    IF (name[j] = 0X) & ((names[i + j] = ",") OR (names[i + j] = 0X)) THEN RETURN TRUE END;
    WHILE (names[i] # 0X) & (names[i] # ",") DO INC(i) END;
    IF names[i] = "," THEN INC(i) END
  END;
  RETURN FALSE
END NameIn;

(** what the file known_hosts says of the key blob of host and port: Known (listed with this key),
  Changed (listed with another key of the same type) or Unknown. Hashed host names are not read. *)
PROCEDURE Check*(file, host: ARRAY OF CHAR; port: LONGINT; VAR blob: TLSBytes.Buffer): LONGINT;
VAR f: Files.File; R: Files.Rider; line: Line; name: ARRAY 300 OF CHAR; names: Line;
  type, ktype: ARRAY 64 OF CHAR; data: Line; key: TLSBytes.Buffer; res, i: LONGINT; same: BOOLEAN;
BEGIN
  res := Unknown; f := Files.Old(file);
  IF f = NIL THEN RETURN Unknown END;
  EntryName(host, port, name); Type(blob, type);
  Files.Set(R, f, 0);
  WHILE ReadLine(R, line) DO
    Field(line, 0, names);
    IF (names[0] # "#") & (names[0] # "@") & (names[0] # "|") & NameIn(names, name) THEN
      Field(line, 1, ktype); Field(line, 2, data);
      IF (ktype = type) & TLSBase64.DecodeToBuffer(data, key) THEN
        same := key.len = blob.len; i := 0;
        WHILE same & (i < key.len) DO same := key.data[i] = blob.data[i]; INC(i) END;
        IF same THEN Files.Close(f); RETURN Known ELSE res := Changed END
      END
    END
  END;
  Files.Close(f);
  RETURN res
END Check;

(** appends a line for host, port and the key blob to the file known_hosts, its directory made if
  needed *)
PROCEDURE Add*(file, host: ARRAY OF CHAR; port: LONGINT; VAR blob: TLSBytes.Buffer): BOOLEAN;
VAR f: Files.File; R: Files.Rider; line, key: Line; type: ARRAY 64 OF CHAR; dir: ARRAY 300 OF CHAR;
  i, k: LONGINT; res: INTEGER; new: BOOLEAN;
BEGIN
  f := Files.Old(file); new := f = NIL;
  IF new THEN
    COPY(file, dir); k := -1; i := 0; WHILE dir[i] # 0X DO IF dir[i] = "/" THEN k := i END; INC(i) END;
    IF k > 0 THEN dir[k] := 0X; Files.CreateDirectory(dir, res) END;
    f := Files.New(file)
  END;
  IF f = NIL THEN SetError("cannot write the known_hosts file"); RETURN FALSE END;
  EntryName(host, port, line); Type(blob, type);
  Append(line, " "); Append(line, type); Append(line, " ");
  i := 0; WHILE line[i] # 0X DO INC(i) END;
  W.Base64(blob, TRUE, key); Append(line, key); Append(line, " ");
  i := 0; WHILE line[i] # 0X DO INC(i) END; line[i - 1] := 0AX;
  IF new THEN Files.Set(R, f, 0) ELSE Files.Set(R, f, Files.Length(f)) END;
  i := 0; WHILE line[i] # 0X DO Files.Write(R, line[i]); INC(i) END;
  IF new THEN Files.Register(f) ELSE Files.Close(f) END;
  RETURN TRUE
END Add;

(* ----- keys of the user ----- *)

(** the Ed25519 key of the file name, as ssh-keygen writes it (OpenSSH format, not encrypted);
  FALSE (lastError says why) if it cannot be used *)
PROCEDURE Load*(name: ARRAY OF CHAR; VAR k: Key): BOOLEAN;
VAR f: Files.File; R: Files.Rider; line: Line; text: ARRAY 8192 OF CHAR; b, s, priv, sec: TLSBytes.Buffer;
  r, pr: W.Reader; cipher, kdf, type: ARRAY 64 OF CHAR; i, j, n, c1, c2: LONGINT; inside: BOOLEAN;
BEGIN
  k := NIL; f := Files.Old(name);
  IF f = NIL THEN SetError("no such key file"); RETURN FALSE END;
  Files.Set(R, f, 0); j := 0; inside := FALSE;
  WHILE ReadLine(R, line) DO
    IF line = "-----BEGIN OPENSSH PRIVATE KEY-----" THEN inside := TRUE
    ELSIF line = "-----END OPENSSH PRIVATE KEY-----" THEN inside := FALSE
    ELSIF inside THEN
      i := 0; WHILE (line[i] # 0X) & (j < LEN(text) - 1) DO text[j] := line[i]; INC(i); INC(j) END
    END
  END;
  text[j] := 0X; Files.Close(f);
  IF (j = 0) OR ~TLSBase64.DecodeToBuffer(text, b) THEN SetError("not a private key of OpenSSH"); RETURN FALSE END;
  text := "openssh-key-v1"; i := 0;
  WHILE (i < 14) & (i < b.len) & (b.data[i] = text[i]) DO INC(i) END;
  IF (i < 14) OR (b.len < 15) OR (b.data[14] # 0X) THEN SetError("not a private key of OpenSSH"); RETURN FALSE END;
  W.Open(r, 15); W.Text(b, r, cipher); W.Text(b, r, kdf); W.String(b, r, s);
  n := W.Uint32(b, r); W.String(b, r, s); W.String(b, r, priv);
  IF ~r.ok OR (n # 1) THEN SetError("a malformed key file"); RETURN FALSE END;
  IF cipher # "none" THEN SetError("the key is encrypted (with a passphrase): not supported"); RETURN FALSE END;
  W.Open(pr, 0); c1 := W.Uint32(priv, pr); c2 := W.Uint32(priv, pr); W.Text(priv, pr, type);
  IF ~pr.ok OR (c1 # c2) THEN SetError("a malformed key file"); RETURN FALSE END;
  IF type # "ssh-ed25519" THEN SetError("only Ed25519 keys are supported"); RETURN FALSE END;
  NEW(k); COPY(type, k.type);
  W.String(priv, pr, s); W.String(priv, pr, sec); W.Text(priv, pr, k.comment);
  IF ~pr.ok OR ~ToArray(s, k.pub) OR (sec.len # 64) THEN SetError("a malformed key file"); k := NIL; RETURN FALSE END;
  i := 0; WHILE i < 32 DO k.seed[i] := sec.data[i]; INC(i) END;
  RETURN TRUE
END Load;

(** the public key of k as a key blob *)
PROCEDURE PublicBlob*(k: Key; VAR blob: TLSBytes.Buffer);
BEGIN
  TLSBytes.Init(blob); W.PutText(blob, k.type);
  W.PutUint32(blob, 32); TLSBytes.AppendOpen(blob, k.pub, 32)
END PublicBlob;

(** the signature blob of data by k *)
PROCEDURE Sign*(k: Key; VAR data, sig: TLSBytes.Buffer): BOOLEAN;
VAR s: ARRAY 64 OF CHAR;
BEGIN
  TLSBytes.Init(sig);
  IF ~TLSEd25519.Sign(k.seed, data.data, 0, data.len, s) THEN SetError("cannot sign"); RETURN FALSE END;
  W.PutText(sig, k.type); W.PutUint32(sig, 64); TLSBytes.AppendOpen(sig, s, 64);
  RETURN TRUE
END Sign;

BEGIN
  lastError := ""
END SSHKeys.
