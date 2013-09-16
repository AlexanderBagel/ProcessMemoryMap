unit MemoryMap.Workset;

interface

uses
  Winapi.Windows,
  Winapi.PsAPI,
  System.SysUtils,
  Generics.Collections;

type
  TShareInfo = record
    Shared: Boolean;
    SharedCount: Byte;
  end;

  TWorkset = class
  private
    FData: TDictionary<Pointer, TShareInfo>;
  protected
    procedure InitWorksetData(hProcess: THandle);
  public
    constructor Create(hProcess: THandle);
    destructor Destroy; override;
    function GetPageSharedInfo(pPage: Pointer; var Shared: Boolean;
      var SharedCount: Byte): Boolean;
  end;

implementation

{ TWorkset }

constructor TWorkset.Create(hProcess: THandle);
begin
  FData := TDictionary<Pointer, TShareInfo>.Create;
  InitWorksetData(hProcess);
end;

destructor TWorkset.Destroy;
begin
  FData.Free;
  inherited;
end;

function TWorkset.GetPageSharedInfo(pPage: Pointer; var Shared: Boolean;
  var SharedCount: Byte): Boolean;
var
  ShareInfo: TShareInfo;
begin
  Result := FData.TryGetValue(pPage, ShareInfo);
  if Result then
  begin
    Shared := ShareInfo.Shared;
    SharedCount := ShareInfo.SharedCount;
  end;
end;

procedure TWorkset.InitWorksetData(hProcess: THandle);
const
  {$IFDEF WIN64}
  AddrMask = $FFFFFFFFFFFFF000;
  {$ELSE}
  AddrMask = $FFFFF000;
  {$ENDIF}
  SharedBitMask = $100;
  SharedCountMask = $E0;

  function GetSharedCount(Value: ULONG_PTR): Byte; inline;
  begin
    Result := (Value and SharedCountMask) shr 5;
  end;

var
  WorksetBuff: array of ULONG_PTR;
  I: Integer;
  ShareInfo: TShareInfo;
begin
  SetLength(WorksetBuff, $400000);
  while not QueryWorkingSet(hProcess, @WorksetBuff[0],
    Length(WorksetBuff) * SizeOf(ULONG_PTR)) do
    SetLength(WorksetBuff, WorksetBuff[0] * 2);
  for I := 0 to WorksetBuff[0] - 1 do
  begin
    ShareInfo.Shared := WorksetBuff[I]  and SharedBitMask <> 0;
    ShareInfo.SharedCount := GetSharedCount(WorksetBuff[I]);
    try
      FData.Add(Pointer(WorksetBuff[I] and AddrMask), ShareInfo);
    except
      on E: EListError do ;
    else
      raise;
    end;
  end;
end;

end.
