MODULE SSHTest;  (* SSHTest.Run, in the directory of msg.txt and its signatures: the data types of
  SSH, an Ed25519 key of OpenSSH loaded and its fingerprint, signatures checked (Ed25519, ECDSA P-256,
  RSA; made by ssh-keygen -Y sign, files msg-*.sig), the file known_hosts; no server is needed *)

IMPORT Files, TLSBytes, TLSBase64, TLSSHA512, W := SSHWire, K := SSHKeys, Out;

VAR checks, fails: LONGINT;

PROCEDURE Check(what: ARRAY OF CHAR; ok: BOOLEAN);
BEGIN
  INC(checks);
  IF ~ok THEN INC(fails); Out.String("FAIL "); Out.String(what); Out.String(" (case "); Out.Int(checks, 0); Out.String(")"); Out.Ln END
END Check;

(* b holds the bytes of the hex string h *)
PROCEDURE Is(VAR b: TLSBytes.Buffer; h: ARRAY OF CHAR): BOOLEAN;
VAR i, v: LONGINT; d: ARRAY 3 OF CHAR;
BEGIN
  i := 0; WHILE h[i] # 0X DO INC(i) END;
  IF b.len # i DIV 2 THEN RETURN FALSE END;
  i := 0;
  WHILE i < b.len DO
    d[0] := h[2 * i]; d[1] := h[2 * i + 1];
    v := 0;
    IF d[0] <= "9" THEN v := ORD(d[0]) - ORD("0") ELSE v := ORD(d[0]) - ORD("a") + 10 END;
    IF d[1] <= "9" THEN v := v * 16 + ORD(d[1]) - ORD("0") ELSE v := v * 16 + ORD(d[1]) - ORD("a") + 10 END;
    IF ORD(b.data[i]) # v THEN RETURN FALSE END;
    INC(i)
  END;
  RETURN TRUE
END Is;

PROCEDURE Wire;
VAR b, s: TLSBytes.Buffer; r: W.Reader; t: ARRAY 64 OF CHAR; name: ARRAY 64 OF CHAR;
BEGIN
  TLSBytes.Init(b); W.PutUint32(b, 1234567); W.PutText(b, "ssh"); W.PutBool(b, TRUE);
  W.Open(r, 0); Check("uint32", W.Uint32(b, r) = 1234567); W.Text(b, r, t); Check("text", t = "ssh");
  Check("bool", W.Bool(b, r)); Check("all read", r.ok & (r.pos = b.len));
  Check("past the end", (W.Byte(b, r) = 0) & ~r.ok);
  TLSBytes.Init(s); TLSBytes.AppendByte(s, 80H); TLSBytes.Init(b); W.PutMpint(b, s);
  Check("mpint with a high bit", Is(b, "000000020080"));
  TLSBytes.Init(s); TLSBytes.AppendByte(s, 0); TLSBytes.AppendByte(s, 0); TLSBytes.AppendByte(s, 7FH);
  TLSBytes.Init(b); W.PutMpint(b, s); Check("mpint without leading zeros", Is(b, "000000017f"));
  TLSBytes.Init(s); TLSBytes.Init(b); W.PutMpint(b, s); Check("mpint 0", Is(b, "00000000"));
  TLSBytes.Init(b); TLSBytes.PutBE32(b, 1); TLSBytes.AppendByte(b, 0FFH); W.Open(r, 0);
  Check("negative mpint refused", ~W.Mpint(b, r, s));
  Check("choose", W.Choose("a,b,c", "x,c,b", name) & (name = "b"));
  Check("nothing to choose", ~W.Choose("a,b", "c,d", name) & (name = ""));
  Check("has", W.Has("curve25519-sha256,ext-info-c", "ext-info-c") & ~W.Has("curve25519-sha256", "curve25519"));
  TLSBytes.Init(b); TLSBytes.AppendString(b, "foob"); W.Base64(b, TRUE, t); Check("Base64", t = "Zm9vYg==");
  W.Base64(b, FALSE, t); Check("Base64 without padding", t = "Zm9vYg");
  TLSBytes.Init(b); TLSBytes.AppendByte(b, 0FFH); TLSBytes.AppendByte(b, 0FEH); TLSBytes.AppendByte(b, 0FDH);
  W.Base64(b, TRUE, t); Check("Base64 of high bytes", t = "//79")
END Wire;

PROCEDURE Cat(VAR s: ARRAY OF CHAR; t: ARRAY OF CHAR);
VAR i, j: LONGINT;
BEGIN
  i := 0; WHILE s[i] # 0X DO INC(i) END;
  j := 0; WHILE (t[j] # 0X) & (i < LEN(s) - 1) DO s[i] := t[j]; INC(i); INC(j) END;
  s[i] := 0X
END Cat;

(* the key file zq_ssh_key: a key made for this test by ssh-keygen -t ed25519 -C "polpo test key" *)
PROCEDURE WriteKey;
VAR f: Files.File; R: Files.Rider; line: ARRAY 80 OF CHAR;

  PROCEDURE Line(s: ARRAY OF CHAR);
  VAR i: LONGINT;
  BEGIN i := 0; WHILE s[i] # 0X DO Files.Write(R, s[i]); INC(i) END; Files.Write(R, 0AX)
  END Line;

BEGIN
  f := Files.New("zq_ssh_key"); Files.Set(R, f, 0);
  COPY("-----BEGIN ", line); Cat(line, "OPENSSH PRIVATE KEY-----"); Line(line);
  Line("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW");
  Line("QyNTUxOQAAACBwhvu8TL30goNIyOBrE0hrEo7ryV/1YDLcuEYsgntYrAAAAJiDQqHkg0Kh");
  Line("5AAAAAtzc2gtZWQyNTUxOQAAACBwhvu8TL30goNIyOBrE0hrEo7ryV/1YDLcuEYsgntYrA");
  Line("AAAEBlWTX3075pPjuOl9l4mDDOBqm7PDvJ//c5x3WQ9v3QY3CG+7xMvfSCg0jI4GsTSGsS");
  Line("juvJX/VgMty4RiyCe1isAAAADnBvbHBvIHRlc3Qga2V5AQIDBAUGBw==");
  COPY("-----END ", line); Cat(line, "OPENSSH PRIVATE KEY-----"); Line(line);
  Files.Register(f)
END WriteKey;

PROCEDURE Keys;
VAR k: K.Key; blob, data, sig: TLSBytes.Buffer; fp: ARRAY 80 OF CHAR; type: ARRAY 32 OF CHAR; res: INTEGER;
BEGIN
  WriteKey;
  Check("key loaded", K.Load("zq_ssh_key", k));
  IF k = NIL THEN Out.String("  "); Out.String(K.lastError); Out.Ln; RETURN END;
  Check("comment", k.comment = "polpo test key");
  K.PublicBlob(k, blob); K.Type(blob, type); Check("type", type = "ssh-ed25519");
  K.Fingerprint(blob, fp); Check("fingerprint as ssh-keygen -l", fp = "SHA256:eAoYTMCybIj731kRquqNHgDwx23KIdrtLjYI4VZQLVg");
  TLSBytes.Init(data); TLSBytes.AppendString(data, "data to sign");
  Check("signed", K.Sign(k, data, sig));
  Check("own signature holds", K.Verify("ssh-ed25519", blob, sig, data));
  data.data[0] := "D"; Check("changed data refused", ~K.Verify("ssh-ed25519", blob, sig, data));
  Check("other algorithm refused", ~K.Verify("ecdsa-sha2-nistp256", blob, sig, data));
  Check("missing file", ~K.Load("zq_no_such_key", k));
  Files.Delete("zq_ssh_key", res)
END Keys;

(* the signature of msg.txt in the SSHSIG file name (ssh-keygen -Y sign -n polpo-test) checked as
  a signature of the algorithm alg; tamper changes the signed data first *)
PROCEDURE SigFile(name, alg: ARRAY OF CHAR; tamper: BOOLEAN): BOOLEAN;
VAR f: Files.File; R: Files.Rider; ch: CHAR; text: ARRAY 4096 OF CHAR; line: ARRAY 128 OF CHAR;
  b, pub, ns, res, hash, sig, msg, h, data: TLSBytes.Buffer; r: W.Reader; i, j: LONGINT;
BEGIN
  f := Files.Old(name); IF f = NIL THEN RETURN FALSE END;
  Files.Set(R, f, 0); j := 0; i := 0; Files.Read(R, ch);
  WHILE ~R.eof DO
    IF ch = 0AX THEN
      line[i] := 0X;
      IF line[0] # "-" THEN i := 0; WHILE line[i] # 0X DO text[j] := line[i]; INC(i); INC(j) END END;
      i := 0
    ELSIF i < LEN(line) - 1 THEN line[i] := ch; INC(i)
    END;
    Files.Read(R, ch)
  END;
  text[j] := 0X; Files.Close(f);
  IF ~TLSBase64.DecodeToBuffer(text, b) THEN RETURN FALSE END;
  W.Open(r, 6); IF W.Uint32(b, r) # 1 THEN RETURN FALSE END;
  W.String(b, r, pub); W.String(b, r, ns); W.String(b, r, res); W.String(b, r, hash); W.String(b, r, sig);
  IF ~r.ok THEN RETURN FALSE END;
  f := Files.Old("msg.txt"); IF f = NIL THEN RETURN FALSE END;
  TLSBytes.SetLen(msg, Files.Length(f)); Files.Set(R, f, 0); Files.ReadBytes(R, msg.data, msg.len); Files.Close(f);
  TLSSHA512.Digest512(msg, h);
  TLSBytes.Init(data); TLSBytes.AppendString(data, "SSHSIG");
  W.PutString(data, ns); W.PutString(data, res); W.PutString(data, hash); W.PutString(data, h);
  IF tamper THEN data.data[data.len - 1] := CHR((ORD(data.data[data.len - 1]) + 1) MOD 256) END;
  RETURN K.Verify(alg, pub, sig, data)
END SigFile;

PROCEDURE Signatures;
BEGIN
  Check("Ed25519 signature of ssh-keygen", SigFile("msg-ed25519.sig", "ssh-ed25519", FALSE));
  Check("ECDSA P-256 signature of ssh-keygen", SigFile("msg-ecdsa.sig", "ecdsa-sha2-nistp256", FALSE));
  Check("RSA signature of ssh-keygen", SigFile("msg-rsa.sig", "rsa-sha2-512", FALSE));
  Check("changed Ed25519 refused", ~SigFile("msg-ed25519.sig", "ssh-ed25519", TRUE));
  Check("changed ECDSA refused", ~SigFile("msg-ecdsa.sig", "ecdsa-sha2-nistp256", TRUE));
  Check("changed RSA refused", ~SigFile("msg-rsa.sig", "rsa-sha2-512", TRUE));
  Check("RSA as SHA-256 refused", ~SigFile("msg-rsa.sig", "rsa-sha2-256", FALSE))
END Signatures;

PROCEDURE KnownHosts;
VAR a, b: TLSBytes.Buffer; res: INTEGER; f: Files.File; R: Files.Rider; line: ARRAY 200 OF CHAR; ch: CHAR; i: LONGINT;
BEGIN
  Files.Delete("zq_known_hosts", res);
  Check("ECDSA key", TLSBase64.DecodeToBuffer("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBSXI7PtwwvuqMQFNh5soLeSBfqG6Q+5NTXe4mwPyj8LlfKKFOygSmCtyIeN5VuIlEmahSMZWBotp75Z2q0vyQI=", a));
  TLSBytes.Copy(a, b); b.data[b.len - 1] := CHR((ORD(b.data[b.len - 1]) + 1) MOD 256);
  Check("unknown before", K.Check("zq_known_hosts", "h.example", 22, a) = K.Unknown);
  Check("added", K.Add("zq_known_hosts", "h.example", 22, a) & K.Add("zq_known_hosts", "h.example", 2222, b));
  Check("known", K.Check("zq_known_hosts", "h.example", 22, a) = K.Known);
  Check("changed", K.Check("zq_known_hosts", "h.example", 22, b) = K.Changed);
  Check("known on its port", K.Check("zq_known_hosts", "h.example", 2222, b) = K.Known);
  Check("other host unknown", K.Check("zq_known_hosts", "g.example", 22, a) = K.Unknown);
  f := Files.Old("zq_known_hosts"); Files.Set(R, f, 0); i := 0; Files.Read(R, ch);
  WHILE ~R.eof & (ch # 0AX) & (i < LEN(line) - 1) DO line[i] := ch; INC(i); Files.Read(R, ch) END;
  line[i] := 0X; Files.Close(f);
  COPY("h.example ecdsa-sha2-nistp256 ", a.data); Cat(a.data, "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBSXI7PtwwvuqMQFNh5soLeSBfqG6Q+5NTXe4mwPyj8LlfKKFOygSmCtyIeN5VuIlEmahSMZWBotp75Z2q0vyQI=");
  Check("the line as OpenSSH writes it", line = a.data);
  Files.Delete("zq_known_hosts", res)
END KnownHosts;

PROCEDURE Run*;
BEGIN
  checks := 0; fails := 0;
  Wire; Keys; Signatures; KnownHosts;
  Out.String("SSHTest: "); Out.Int(checks, 0); Out.String(" checks, "); Out.Int(fails, 0); Out.String(" failed"); Out.Ln
END Run;

END SSHTest.
