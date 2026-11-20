MODULE SSHTransport;  (** the transport layer of SSH (RFC 4253): the version lines, the binary packets,
  the key exchange curve25519-sha256 (RFC 8731) with the strict key exchange of OpenSSH, the host key of
  the server, and aes128-gcm@openssh.com; a key exchange the server starts later is answered *)

IMPORT SYSTEM, unixNet, Internet, TLSBytes, TLSSHA256, TLSX25519, TLSAESGCM, TLS13Random,
  W := SSHWire, Keys := SSHKeys;

CONST
  Disconnect* = 1; Ignore* = 2; Unimplemented* = 3; Debug* = 4; ServiceRequest* = 5;
  ServiceAccept* = 6; ExtInfo* = 7; KexInit* = 20; NewKeys* = 21; KexEcdhInit* = 30; KexEcdhReply* = 31;
  (** message numbers of the transport layer *)

  Version* = "SSH-2.0-polpo_0.1";
  KexAlgs = "curve25519-sha256,curve25519-sha256@libssh.org,ext-info-c,kex-strict-c-v00@openssh.com";
  HostKeyAlgs = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256";
  Ciphers = "aes128-gcm@openssh.com";
  Macs = "hmac-sha2-256";
  MaxPacket = 32000;  (** the largest packet read *)

TYPE
  Connection* = POINTER TO ConnectionDesc;

  Checker* = PROCEDURE (c: Connection): BOOLEAN;  (** accepts the host key of the server (c.hostKey) *)

  Dir = RECORD  (* the keys of one direction *)
    key, iv: TLSBytes.Buffer;
    seq: LONGINT;
    on: BOOLEAN  (* encrypted *)
  END;

  ConnectionDesc* = RECORD
    fd*: LONGINT;
    host*: ARRAY 256 OF CHAR;
    port*: LONGINT;
    serverVersion*: ARRAY 256 OF CHAR;
    hostKeyAlg*: ARRAY 64 OF CHAR;
    hostKey*: TLSBytes.Buffer;    (** the key blob of the server *)
    sessionId*: TLSBytes.Buffer;
    serverSigAlgs*: ARRAY 256 OF CHAR;  (** what the server accepts for signatures of users (EXT_INFO) *)
    open*: BOOLEAN;
    strict, kexDone: BOOLEAN;
    out, in: Dir;
    ic, is: TLSBytes.Buffer;  (* the KEXINIT payloads of the key exchange *)
    check: Checker
  END;

VAR
  lastError*: ARRAY 256 OF CHAR;

PROCEDURE SetError(s: ARRAY OF CHAR);
BEGIN COPY(s, lastError)
END SetError;

PROCEDURE AppendError(s: ARRAY OF CHAR);
VAR i, j: LONGINT;
BEGIN
  i := 0; WHILE lastError[i] # 0X DO INC(i) END;
  j := 0; WHILE (s[j] # 0X) & (i < LEN(lastError) - 1) DO lastError[i] := s[j]; INC(i); INC(j) END;
  lastError[i] := 0X
END AppendError;

(* ----- reading and writing on the socket ----- *)

(* n bytes into b.data[pos..] *)
PROCEDURE ReadExact(c: Connection; VAR b: TLSBytes.Buffer; pos, n: LONGINT): BOOLEAN;
VAR got, r: LONGINT;
BEGIN
  got := 0;
  WHILE got < n DO
    r := unixNet.Read0(c.fd, SYSTEM.ADR(b.data[pos + got]), n - got);
    IF r <= 0 THEN
      IF (r < 0) & unixNet.Interrupted0(r) THEN r := 0
      ELSE SetError("the connection ended"); c.open := FALSE; RETURN FALSE
      END
    END;
    INC(got, r)
  END;
  RETURN TRUE
END ReadExact;

PROCEDURE WriteAll(c: Connection; VAR b: TLSBytes.Buffer): BOOLEAN;
BEGIN
  IF ~Internet.WriteBytes(c.fd, b.data, b.len) THEN SetError("cannot write to the server"); c.open := FALSE; RETURN FALSE END;
  RETURN TRUE
END WriteAll;

(* ----- packets ----- *)

(* the last 8 bytes of the nonce iv as a counter, plus 1 *)
PROCEDURE NextIV(VAR iv: TLSBytes.Buffer);
VAR i, x: LONGINT;
BEGIN
  i := 11;
  REPEAT x := (ORD(iv.data[i]) + 1) MOD 256; iv.data[i] := CHR(x); DEC(i) UNTIL (x # 0) OR (i < 4)
END NextIV;

(** sends the payload p as a packet *)
PROCEDURE Send*(c: Connection; VAR p: TLSBytes.Buffer): BOOLEAN;
VAR plain, aad, pkt: TLSBytes.Buffer; pad: LONGINT; rnd: ARRAY 32 OF CHAR;
BEGIN
  IF ~c.open THEN SetError("the connection is closed"); RETURN FALSE END;
  IF c.out.on THEN
    pad := 16 - (1 + p.len) MOD 16; IF pad < 4 THEN INC(pad, 16) END
  ELSE
    pad := 8 - (5 + p.len) MOD 8; IF pad < 4 THEN INC(pad, 8) END
  END;
  IF ~TLS13Random.Fill(rnd, pad) THEN SetError("no random bytes"); RETURN FALSE END;
  TLSBytes.Init(plain); W.PutByte(plain, pad); TLSBytes.Append(plain, p); TLSBytes.AppendOpen(plain, rnd, pad);
  TLSBytes.Init(aad); W.PutUint32(aad, plain.len);
  IF c.out.on THEN
    TLSAESGCM.AES128GCMEncrypt(c.out.key, plain, c.out.iv, aad, pkt); NextIV(c.out.iv);
    TLSBytes.Append(aad, pkt)
  ELSE TLSBytes.Append(aad, plain)
  END;
  c.out.seq := TLSBytes.Add32(c.out.seq, 1);
  RETURN WriteAll(c, aad)
END Send;

(* the next packet, its payload into p *)
PROCEDURE ReadPacket(c: Connection; VAR p: TLSBytes.Buffer): BOOLEAN;
VAR head, body, aad, plain: TLSBytes.Buffer; n, pad: LONGINT;
BEGIN
  TLSBytes.Init(p);
  IF ~c.open THEN SetError("the connection is closed"); RETURN FALSE END;
  TLSBytes.SetLen(head, 4);
  IF ~ReadExact(c, head, 0, 4) THEN RETURN FALSE END;
  n := TLSBytes.GetBE32(head, 0);
  IF (n < 5) OR (n > MaxPacket) OR c.in.on & (n MOD 16 # 0) THEN SetError("a packet of a wrong length"); c.open := FALSE; RETURN FALSE END;
  IF c.in.on THEN
    TLSBytes.SetLen(body, n + 16);
    IF ~ReadExact(c, body, 0, n + 16) THEN RETURN FALSE END;
    IF ~TLSAESGCM.AES128GCMDecrypt(c.in.key, body, c.in.iv, head, plain) THEN
      SetError("a packet that does not decrypt"); c.open := FALSE; RETURN FALSE
    END;
    NextIV(c.in.iv)
  ELSE
    TLSBytes.SetLen(plain, n);
    IF ~ReadExact(c, plain, 0, n) THEN RETURN FALSE END
  END;
  c.in.seq := TLSBytes.Add32(c.in.seq, 1);
  pad := ORD(plain.data[0]);
  IF (pad < 4) OR (pad > n - 1) THEN SetError("a packet with wrong padding"); c.open := FALSE; RETURN FALSE END;
  TLSBytes.Slice(plain, 1, n - 1 - pad, p);
  IF p.len = 0 THEN SetError("an empty packet"); c.open := FALSE; RETURN FALSE END;
  RETURN TRUE
END ReadPacket;

(* ----- key exchange ----- *)

PROCEDURE PutKexInit(VAR b: TLSBytes.Buffer): BOOLEAN;
VAR cookie: ARRAY 16 OF CHAR;
BEGIN
  IF ~TLS13Random.Fill(cookie, 16) THEN RETURN FALSE END;
  TLSBytes.Init(b); W.PutByte(b, KexInit); TLSBytes.AppendOpen(b, cookie, 16);
  W.PutText(b, KexAlgs); W.PutText(b, HostKeyAlgs);
  W.PutText(b, Ciphers); W.PutText(b, Ciphers); W.PutText(b, Macs); W.PutText(b, Macs);
  W.PutText(b, "none"); W.PutText(b, "none"); W.PutText(b, ""); W.PutText(b, "");
  W.PutBool(b, FALSE); W.PutUint32(b, 0);
  RETURN TRUE
END PutKexInit;

(* key material for letter x: SHA-256(K || H || x || session id), 32 bytes, the first n of them into out *)
PROCEDURE Derive(VAR k, h: TLSBytes.Buffer; x: CHAR; VAR id: TLSBytes.Buffer; n: LONGINT; VAR out: TLSBytes.Buffer);
VAR b, d: TLSBytes.Buffer; dig: TLSSHA256.Digest;
BEGIN
  TLSBytes.Init(b); W.PutMpint(b, k); TLSBytes.Append(b, h); TLSBytes.AppendChar(b, x); TLSBytes.Append(b, id);
  TLSSHA256.DigestBuffer(b, dig); TLSSHA256.DigestToBuffer(dig, d);
  TLSBytes.Slice(d, 0, n, out)
END Derive;

(* the next packet of a key exchange: in a strict exchange nothing else may come *)
PROCEDURE KexPacket(c: Connection; VAR p: TLSBytes.Buffer): BOOLEAN;
VAR t: LONGINT;
BEGIN
  LOOP
    IF ~ReadPacket(c, p) THEN RETURN FALSE END;
    t := ORD(p.data[0]);
    IF t = Disconnect THEN SetError("the server ended the connection"); c.open := FALSE; RETURN FALSE
    ELSIF (t = Ignore) OR (t = Debug) THEN
      IF c.strict & ~c.kexDone THEN SetError("a message during a strict key exchange"); c.open := FALSE; RETURN FALSE END
    ELSE RETURN TRUE
    END
  END
END KexPacket;

(* a key exchange; serverInit: the KEXINIT of the server is already in c.is *)
PROCEDURE Kex(c: Connection; serverInit: BOOLEAN): BOOLEAN;
VAR p, h, k, ks, qs, sig, iv, key: TLSBytes.Buffer; r: W.Reader; i: LONGINT;
  kex, hka, enc, encS, mac, macS, comp: ARRAY W.NameLen OF CHAR; chosen: ARRAY 64 OF CHAR;
  priv, pub, peer, shared: ARRAY 32 OF CHAR; dig: TLSSHA256.Digest; first, zero: BOOLEAN;
BEGIN
  first := c.sessionId.len = 0;
  IF ~PutKexInit(c.ic) OR ~Send(c, c.ic) THEN RETURN FALSE END;
  IF ~serverInit THEN
    IF ~KexPacket(c, c.is) THEN RETURN FALSE END;
    IF ORD(c.is.data[0]) # KexInit THEN SetError("no KEXINIT from the server"); c.open := FALSE; RETURN FALSE END
  END;
  W.Open(r, 17);
  W.Text(c.is, r, kex); W.Text(c.is, r, hka); W.Text(c.is, r, enc); W.Text(c.is, r, encS);
  W.Text(c.is, r, mac); W.Text(c.is, r, macS); W.Text(c.is, r, comp);
  IF ~r.ok THEN SetError("a malformed KEXINIT"); c.open := FALSE; RETURN FALSE END;
  IF first THEN c.strict := W.Has(kex, "kex-strict-s-v00@openssh.com") END;
  IF ~W.Choose(KexAlgs, kex, chosen) OR (chosen = "ext-info-c") OR (chosen = "kex-strict-c-v00@openssh.com") THEN
    SetError("no common key exchange (curve25519-sha256)"); c.open := FALSE; RETURN FALSE
  END;
  IF ~W.Choose(HostKeyAlgs, hka, c.hostKeyAlg) THEN SetError("no common host key algorithm"); c.open := FALSE; RETURN FALSE END;
  IF ~W.Choose(Ciphers, enc, chosen) OR ~W.Choose(Ciphers, encS, chosen) THEN
    SetError("no common cipher (aes128-gcm@openssh.com)"); c.open := FALSE; RETURN FALSE
  END;
  IF ~W.Has(comp, "none") THEN SetError("the server wants compression"); c.open := FALSE; RETURN FALSE END;
  (* ECDH *)
  IF ~TLS13Random.Fill(priv, 32) THEN SetError("no random bytes"); RETURN FALSE END;
  TLSX25519.ScalarMultBase(pub, priv);
  TLSBytes.Init(p); W.PutByte(p, KexEcdhInit); W.PutUint32(p, 32); TLSBytes.AppendOpen(p, pub, 32);
  IF ~Send(c, p) OR ~KexPacket(c, p) THEN RETURN FALSE END;
  IF ORD(p.data[0]) # KexEcdhReply THEN SetError("no KEX_ECDH_REPLY from the server"); c.open := FALSE; RETURN FALSE END;
  W.Open(r, 1); W.String(p, r, ks); W.String(p, r, qs); W.String(p, r, sig);
  IF ~r.ok OR (qs.len # 32) THEN SetError("a malformed KEX_ECDH_REPLY"); c.open := FALSE; RETURN FALSE END;
  i := 0; WHILE i < 32 DO peer[i] := qs.data[i]; INC(i) END;
  TLSX25519.ScalarMult(shared, priv, peer);
  zero := TRUE; i := 0; WHILE i < 32 DO zero := zero & (shared[i] = 0X); INC(i) END;
  IF zero THEN SetError("a weak key of the server"); c.open := FALSE; RETURN FALSE END;
  TLSBytes.Init(k); TLSBytes.AppendOpen(k, shared, 32);
  (* the exchange hash *)
  TLSBytes.Init(h); W.PutText(h, Version); W.PutText(h, c.serverVersion);
  W.PutString(h, c.ic); W.PutString(h, c.is); W.PutString(h, ks);
  W.PutUint32(h, 32); TLSBytes.AppendOpen(h, pub, 32); W.PutString(h, qs); W.PutMpint(h, k);
  TLSSHA256.DigestBuffer(h, dig); TLSSHA256.DigestToBuffer(dig, h);
  IF ~Keys.Verify(c.hostKeyAlg, ks, sig, h) THEN COPY(Keys.lastError, lastError); c.open := FALSE; RETURN FALSE END;
  IF first THEN
    TLSBytes.Copy(ks, c.hostKey);
    IF (c.check # NIL) & ~c.check(c) THEN
      IF lastError = "" THEN SetError("the host key of the server is not accepted") END;
      c.open := FALSE; RETURN FALSE
    END;
    TLSBytes.Copy(h, c.sessionId)
  ELSE
    zero := ks.len = c.hostKey.len; i := 0;
    WHILE zero & (i < ks.len) DO zero := ks.data[i] = c.hostKey.data[i]; INC(i) END;
    IF ~zero THEN SetError("the host key changed during the connection"); c.open := FALSE; RETURN FALSE END
  END;
  (* new keys: ours first, then the server's *)
  TLSBytes.Init(p); W.PutByte(p, NewKeys);
  IF ~Send(c, p) THEN RETURN FALSE END;
  Derive(k, h, "A", c.sessionId, 12, iv); Derive(k, h, "C", c.sessionId, 16, key);
  TLSBytes.Copy(iv, c.out.iv); TLSBytes.Copy(key, c.out.key); c.out.on := TRUE;
  IF c.strict THEN c.out.seq := 0 END;
  IF ~KexPacket(c, p) THEN RETURN FALSE END;
  IF ORD(p.data[0]) # NewKeys THEN SetError("no NEWKEYS from the server"); c.open := FALSE; RETURN FALSE END;
  Derive(k, h, "B", c.sessionId, 12, iv); Derive(k, h, "D", c.sessionId, 16, key);
  TLSBytes.Copy(iv, c.in.iv); TLSBytes.Copy(key, c.in.key); c.in.on := TRUE;
  IF c.strict THEN c.in.seq := 0 END;
  c.kexDone := TRUE;
  i := 0; WHILE i < 32 DO priv[i] := 0X; shared[i] := 0X; INC(i) END;
  RETURN TRUE
END Kex;

(* the extensions of EXT_INFO: server-sig-algs is kept *)
PROCEDURE Extensions(c: Connection; VAR p: TLSBytes.Buffer);
VAR r: W.Reader; n: LONGINT; name: ARRAY 64 OF CHAR; value: ARRAY 256 OF CHAR;
BEGIN
  W.Open(r, 1); n := W.Uint32(p, r);
  WHILE r.ok & (n > 0) DO
    W.Text(p, r, name); W.Text(p, r, value);
    IF r.ok & (name = "server-sig-algs") THEN COPY(value, c.serverSigAlgs) END;
    DEC(n)
  END
END Extensions;

(** the next message for the layers above, its payload into p: IGNORE, DEBUG and EXT_INFO are taken
  here, a KEXINIT starts a key exchange; FALSE when the connection ends (lastError says why) *)
PROCEDURE Receive*(c: Connection; VAR p: TLSBytes.Buffer): BOOLEAN;
VAR t: LONGINT; r: W.Reader; reason: ARRAY 200 OF CHAR;
BEGIN
  LOOP
    IF ~ReadPacket(c, p) THEN RETURN FALSE END;
    t := ORD(p.data[0]);
    IF t = Disconnect THEN
      W.Open(r, 5); W.Text(p, r, reason);
      SetError("the server ended the connection: "); AppendError(reason); c.open := FALSE; RETURN FALSE
    ELSIF (t = Ignore) OR (t = Debug) OR (t = Unimplemented) THEN
    ELSIF t = ExtInfo THEN Extensions(c, p)
    ELSIF t = KexInit THEN
      TLSBytes.Copy(p, c.is);
      IF ~Kex(c, TRUE) THEN RETURN FALSE END
    ELSE RETURN TRUE
    END
  END
END Receive;

(** the server has data waiting (a packet may be on its way) *)
PROCEDURE Ready*(c: Connection): BOOLEAN;
BEGIN RETURN c.open & (unixNet.Poll0(c.fd, FALSE, 0) > 0)
END Ready;

(* the version line of the server; lines before it are skipped *)
PROCEDURE ServerVersion(c: Connection): BOOLEAN;
VAR b: TLSBytes.Buffer; line: ARRAY 256 OF CHAR; i, lines: LONGINT; ch: CHAR;
BEGIN
  TLSBytes.SetLen(b, 1); lines := 0;
  LOOP
    i := 0;
    LOOP
      IF ~ReadExact(c, b, 0, 1) THEN RETURN FALSE END;
      ch := b.data[0];
      IF ch = 0AX THEN EXIT END;
      IF (ch # 0DX) & (i < LEN(line) - 1) THEN line[i] := ch; INC(i) END
    END;
    line[i] := 0X;
    IF (line[0] = "S") & (line[1] = "S") & (line[2] = "H") & (line[3] = "-") THEN EXIT END;
    INC(lines); IF lines > 50 THEN SetError("no SSH version line from the server"); RETURN FALSE END
  END;
  IF (line[4] # "2") & ((line[4] # "1") OR (line[5] # ".") OR (line[6] # "9") OR (line[7] # "9")) THEN
    SetError("the server does not speak SSH 2"); RETURN FALSE
  END;
  COPY(line, c.serverVersion);
  RETURN TRUE
END ServerVersion;

(** closes the connection, telling the server why if it is still open *)
PROCEDURE Close*(c: Connection);
VAR p: TLSBytes.Buffer; r: LONGINT;
BEGIN
  IF c = NIL THEN RETURN END;
  IF c.open & c.kexDone THEN
    TLSBytes.Init(p); W.PutByte(p, Disconnect); W.PutUint32(p, 11); W.PutText(p, "closed by the user");
    W.PutText(p, ""); IF Send(c, p) THEN END
  END;
  IF c.fd >= 0 THEN r := unixNet.Close0(c.fd); c.fd := -1 END;
  c.open := FALSE
END Close;

(** a connection to host and port, after the key exchange; check decides about the host key of the
  server (NIL: any is accepted). FALSE (lastError says why) if none came about. *)
PROCEDURE Connect*(host, port: ARRAY OF CHAR; check: Checker; VAR c: Connection): BOOLEAN;
VAR b: TLSBytes.Buffer; fd, i: LONGINT;
BEGIN
  c := NIL; lastError := "";
  IF ~Internet.Connect(host, port, fd) THEN SetError("no connection to the server"); RETURN FALSE END;
  NEW(c); c.fd := fd; COPY(host, c.host); c.port := 0; i := 0;
  WHILE (port[i] >= "0") & (port[i] <= "9") DO c.port := c.port * 10 + ORD(port[i]) - ORD("0"); INC(i) END;
  IF c.port = 0 THEN c.port := 22 END;
  c.open := TRUE; c.check := check; c.strict := FALSE; c.kexDone := FALSE; c.serverSigAlgs := "";
  TLSBytes.Init(c.sessionId); TLSBytes.Init(c.hostKey);
  c.out.on := FALSE; c.in.on := FALSE; c.out.seq := 0; c.in.seq := 0;
  TLSBytes.Init(b); TLSBytes.AppendString(b, Version); TLSBytes.AppendChar(b, 0DX); TLSBytes.AppendChar(b, 0AX);
  IF ~WriteAll(c, b) OR ~ServerVersion(c) OR ~Kex(c, FALSE) THEN Close(c); RETURN FALSE END;
  RETURN TRUE
END Connect;

(** asks for the service name ("ssh-userauth") *)
PROCEDURE Service*(c: Connection; name: ARRAY OF CHAR): BOOLEAN;
VAR p: TLSBytes.Buffer;
BEGIN
  TLSBytes.Init(p); W.PutByte(p, ServiceRequest); W.PutText(p, name);
  IF ~Send(c, p) OR ~Receive(c, p) THEN RETURN FALSE END;
  IF ORD(p.data[0]) # ServiceAccept THEN SetError("the server refused the service"); RETURN FALSE END;
  RETURN TRUE
END Service;

BEGIN
  lastError := ""
END SSHTransport.
