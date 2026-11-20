MODULE SSHDesktopTest;  (** SSHDesktopTest.Run: SSH.Open without a server; needs the desktop's display *)

IMPORT Modules, Texts, Oberon, Out;

VAR fails, checks: LONGINT;

PROCEDURE Check(what: ARRAY OF CHAR; ok: BOOLEAN);
BEGIN
  INC(checks);
  IF ~ok THEN INC(fails); Out.String("FAIL "); Out.String(what); Out.Ln END
END Check;

(* TRUE if the text t from pos on holds s *)
PROCEDURE Holds(t: Texts.Text; pos: LONGINT; s: ARRAY OF CHAR): BOOLEAN;
VAR R: Texts.Reader; line: ARRAY 512 OF CHAR; ch: CHAR; i, j: LONGINT;
BEGIN
  Texts.OpenReader(R, t, pos); Texts.Read(R, ch);
  WHILE ~R.eot DO
    i := 0;
    WHILE ~R.eot & (ch # 0DX) & (ch # 0AX) & (i < LEN(line) - 1) DO line[i] := ch; INC(i); Texts.Read(R, ch) END;
    line[i] := 0X;
    i := 0;
    WHILE line[i] # 0X DO
      j := 0; WHILE (s[j] # 0X) & (line[i + j] = s[j]) DO INC(j) END;
      IF s[j] = 0X THEN RETURN TRUE END;
      INC(i)
    END;
    IF ~R.eot THEN Texts.Read(R, ch) END
  END;
  RETURN FALSE
END Holds;

(* SSH.Open with args; TRUE if what it wrote into the log holds s *)
PROCEDURE Open(args, s: ARRAY OF CHAR): BOOLEAN;
VAR par: Oberon.ParList; t: Texts.Text; W: Texts.Writer; pos: LONGINT; res: INTEGER;
BEGIN
  NEW(t); Texts.Open(t, ""); NEW(par); par.text := t; par.pos := 0; par.vwr := NIL; par.frame := NIL; par.obj := NIL;
  Texts.OpenWriter(W); Texts.WriteString(W, args); Texts.WriteLn(W); Texts.Append(par.text, W.buf);
  pos := Oberon.Log.len;
  Oberon.Call("SSH.Open", par, FALSE, res);
  RETURN (res = 0) & Holds(Oberon.Log, pos, s)
END Open;

PROCEDURE Run*;
BEGIN
  fails := 0; checks := 0;
  Check("SSH loaded", Modules.ThisMod("SSH") # NIL);
  Check("usage", Open("", "usage: SSH.Open"));
  Check("no server", Open("/p 1 /l zq 127.0.0.1", "SSH: no connection to the server"));
  Out.String("SSHDesktopTest: "); Out.Int(checks, 0); Out.String(" checks, "); Out.Int(fails, 0); Out.String(" failed"); Out.Ln
END Run;

END SSHDesktopTest.
