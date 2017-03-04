////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uSelectProcess.pas
//  * Purpose   : Диалог выбора процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2017.
//  * Version   : 1.0.2
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit uSelectProcess;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ImgList, Winapi.CommCtrl,
  Winapi.TlHelp32, Winapi.ShellAPI, Vcl.Themes,

  MemoryMap.Utils, System.ImageList;

type
  PSortData = ^TSortData;
  TSortData = record
    SortColumn: Integer;
    PreviosSelected: Integer;
    SortDirectionUp: Boolean;
  end;

  TdlgSelectProcess = class(TForm)
    lvProcess: TListView;
    btnRefresh: TButton;
    btnShowAll: TButton;
    btnCancel: TButton;
    btnDefault: TButton;
    il16: TImageList;
    procedure FormCreate(Sender: TObject);
    procedure btnRefreshClick(Sender: TObject);
    procedure lvProcessSelectItem(Sender: TObject; Item: TListItem;
      Selected: Boolean);
    procedure btnShowAllClick(Sender: TObject);
    procedure lvProcessColumnClick(Sender: TObject; Column: TListColumn);
    procedure lvProcessDblClick(Sender: TObject);
    procedure lvProcessMouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure btnDefaultClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    SortData: TSortData;
    DblClicked: Boolean;
    ProcessList: TStringList;
    procedure Refresh;
    procedure UpdateSort;
  public
    Pid: Cardinal;
    ProcessName: string;
  end;

implementation

uses
  uUtils,
  uProcessReconnect;

{$R *.dfm}

procedure TdlgSelectProcess.btnDefaultClick(Sender: TObject);
begin
  ProcessReconnect.SetKnownProcessList(ProcessList);
  ModalResult := mrOk;
end;

procedure TdlgSelectProcess.btnRefreshClick(Sender: TObject);
begin
  Refresh;
  Pid := 0;
  if lvProcess.Items.Count > 0 then
    lvProcess.Items[0].Selected := True;
end;

procedure TdlgSelectProcess.btnShowAllClick(Sender: TObject);
begin
  if RestartAsAdmin then
    ModalResult := mrClose
  else
    RaiseLastOSError;
end;

procedure TdlgSelectProcess.FormCreate(Sender: TObject);
begin
  btnShowAll.Visible := not CheckIsAdmin;
  SortData.SortDirectionUp := True;
  ProcessList := TStringList.Create;
  btnRefreshClick(nil);
end;

procedure TdlgSelectProcess.FormDestroy(Sender: TObject);
begin
  ProcessList.Free;
end;

procedure TdlgSelectProcess.lvProcessColumnClick(Sender: TObject;
  Column: TListColumn);
begin
  SortData.PreviosSelected := SortData.SortColumn;
  if Column.Index = SortData.SortColumn then
    SortData.SortDirectionUp := not SortData.SortDirectionUp
  else
  begin
    SortData.SortColumn := Column.Index;
    SortData.SortDirectionUp := True;
  end;
  UpdateSort;
end;

procedure TdlgSelectProcess.lvProcessDblClick(Sender: TObject);
begin
  DblClicked := True;
end;

procedure TdlgSelectProcess.lvProcessMouseUp(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  // Обход небольшого глюка.
  // Данный диалог обычно отображается над lvSummary, который отвечает
  // за фильтрацию данных.
  // А в lvSummary метод OnNodeClick вызывается по MouseUp,
  // и при двойном клике на текущем диалоге сразу вызывается фильтрация,
  // а это нам не надо.
  if DblClicked then
  begin
    ProcessReconnect.SetKnownProcessList(ProcessList);
    ModalResult := mrOk;
  end;
end;

procedure TdlgSelectProcess.lvProcessSelectItem(Sender: TObject;
  Item: TListItem; Selected: Boolean);
begin
  if (Item <> nil) and Selected then
  begin
    Pid := Cardinal(Item.Data);
    ProcessName := Item.Caption;
  end;
end;

procedure TdlgSelectProcess.Refresh;

  function GetUserNameDomainAndWow64(APid: Cardinal;
    var UserName, Domain: string; var IsWow: Boolean): Boolean;
  var
    hProcess: THandle;
    hToken: THandle;
    pTokenUserBuff: PTokenUser;
    TokenUserLength, NameLength, DomainLength: Cardinal;
    peUse: SID_NAME_USE;
  begin
    Result := False;
    IsWow := False;
    hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
      False, APid);
    if hProcess = 0 then Exit;
    try
      IsWow := IsWow64(hProcess);
      if not OpenProcessToken(hProcess, TOKEN_QUERY, hToken) then Exit;
      try
        GetTokenInformation(hToken, TokenUser, nil, 0, TokenUserLength);
        if GetLastError <> ERROR_INSUFFICIENT_BUFFER then Exit;
        GetMem(pTokenUserBuff, TokenUserLength);
        try
          if not GetTokenInformation(hToken, TokenUser, pTokenUserBuff,
            TokenUserLength, TokenUserLength) then Exit;
          NameLength := MAX_PATH;
          SetLength(UserName, NameLength);
          DomainLength := MAX_PATH;
          SetLength(Domain, DomainLength);
          if not LookupAccountSid(nil, pTokenUserBuff^.User.Sid,
            PChar(UserName), NameLength,
            PChar(Domain), DomainLength, peUse) then Exit;
          UserName := PChar(UserName);
          Domain := PChar(Domain);
          Result := True;
        finally
          FreeMem(pTokenUserBuff);
        end;
      finally
        CloseHandle(hToken);
      end;
    finally
      CloseHandle(hProcess);
    end;
  end;

  function GetProcessImageIndex(APid: Cardinal): Integer;
  var
    IconHandle: HICON;
  begin
    Result := 0;
    IconHandle := GetProcessIco(APid);
    if IconHandle <> 0 then
    try
      Result := ImageList_AddIcon(il16.Handle, IconHandle);
    finally
      DestroyIcon(IconHandle);
    end;
  end;

var
  hProcessSnap: THandle;
  ProcessEntry: TProcessEntry32;
  Item: TListItem;
  UserName, Domain: string;
  IsWow: Boolean;
begin
  ProcessList.Clear;
  hProcessSnap := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap = INVALID_HANDLE_VALUE) then Exit;
  try
    FillChar(ProcessEntry, SizeOf(TProcessEntry32), #0);
    ProcessEntry.dwSize := SizeOf(TProcessEntry32);
    if not Process32First(hProcessSnap, ProcessEntry) then Exit;
    lvProcess.Items.BeginUpdate;
    try
      lvProcess.Items.Clear;
      repeat
          if not GetUserNameDomainAndWow64(ProcessEntry.th32ProcessID,
            UserName, Domain, IsWow) then Continue;
          Item := lvProcess.Items.Add;
          Item.Caption := ProcessEntry.szExeFile;
          {$IFDEF WIN64}
          if IsWow then
            Item.Caption := Item.Caption + ' *32';
          {$ENDIF}
          Item.SubItems.Add(IntToStr(ProcessEntry.th32ProcessID));
          Item.SubItems.Add(Domain + '/' + UserName);
          Item.Data := Pointer(ProcessEntry.th32ProcessID);
          Item.ImageIndex := GetProcessImageIndex(ProcessEntry.th32ProcessID);
          ProcessList.AddObject(
            GetProcessFullPath(ProcessEntry.th32ProcessID),
            Pointer(ProcessEntry.th32ProcessID));
      until not Process32Next(hProcessSnap, ProcessEntry);
      UpdateSort;
    finally
      lvProcess.Items.EndUpdate;
    end;
  finally
    CloseHandle(hProcessSnap);
  end;
end;

function ListViewSort(Item1, Item2: TListItem; lParamSort: LPARAM): Integer stdcall;
begin
  Result := 0;
  case PSortData(lParamSort)^.SortColumn of
    0: Result := AnsiCompareStr(Item1.Caption, Item2.Caption);
    1:
      if Cardinal(Item1.Data) > Cardinal(Item2.Data) then
        Result := 1
      else
        if Cardinal(Item1.Data) < Cardinal(Item2.Data) then
          Result := -1
        else
          Result := 0;
    2: Result := AnsiCompareStr(Item1.SubItems[1], Item2.SubItems[1]);
  end;
  if not PSortData(lParamSort)^.SortDirectionUp then
    Result := Result * -1;
end;

procedure TdlgSelectProcess.UpdateSort;
var
  Item: THDItem;
  Direction: Integer;
  HeaderHandle: THandle;
begin
  lvProcess.CustomSort(@ListViewSort, NativeInt(@SortData));
  if SortData.SortDirectionUp then
    Direction := HDF_SORTUP
  else
    Direction := HDF_SORTDOWN;
  if StyleServices.Enabled then
  begin
    Item.Mask := HDI_FORMAT;
    // Убираем предыдущую стрелку
    HeaderHandle := ListView_GetHeader(lvProcess.Handle);
    if Header_GetItem(HeaderHandle, SortData.PreviosSelected, Item) then
    begin
      Item.fmt := Item.fmt and not (HDF_SORTUP or HDF_SORTDOWN);
      Header_SetItem(HeaderHandle, SortData.PreviosSelected, Item);
    end;
    // Рисуем новую
    Item.Mask := HDI_FORMAT;
    Header_GetItem(HeaderHandle, SortData.SortColumn, Item);
    Item.fmt := Item.fmt or Direction;
    Header_SetItem(HeaderHandle, SortData.SortColumn, Item);
  end;
  ListView_SetSelectedColumn(lvProcess.Handle, SortData.SortColumn);
end;

end.
