unit uHexUtils;

interface

uses
  Winapi.Windows,
  System.SysUtils;

  function ByteToHexStr(Base: NativeUInt; Data: Pointer; Len: Integer): string;

implementation

uses
  uUtils;

function ByteToHexStr(Base: NativeUInt; Data: Pointer; Len: Integer): string;
var
  I, PartOctets: Integer;
  Octets: NativeUInt;
  DumpData: string;
begin
  if Len = 0 then Exit;
  I := 0;
  Octets := Base;
  PartOctets := 0;
  Result := '';
  while I < Len do
  begin
    case PartOctets of
      0: Result := Result + UInt64ToStr(Octets) + ' ';
      9: Result := Result + '|';
      18:
      begin
        Inc(Octets, 16);
        PartOctets := -1;
        Result := Result + '    ' + DumpData + sLineBreak;
        DumpData := '';
      end;
    else
      begin
        Result := Result + Format('%s ', [IntToHex(TByteArray(Data^)[I], 2)]);
        if TByteArray(Data^)[I] in [$19..$FF] then
          DumpData := DumpData + Char(AnsiChar(TByteArray(Data^)[I]))
        else
          DumpData := DumpData + '.';
        Inc(I);
      end;
    end;
    Inc(PartOctets);
  end;
  if PartOctets <> 0 then
  begin
    PartOctets := (16 - Length(DumpData)) * 3;
    if PartOctets >= 24 then Inc(PartOctets, 2);
    Inc(PartOctets, 4);
    Result := Result + StringOfChar(' ', PartOctets) + DumpData;
  end;
end;

end.
