////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : uWindows.pas
//  * Purpose   : Форма для отображения окон процесса
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.7.53
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

// Частично основано на базе кода:
//  https://github.com/strobejb/winspy/
//  Copyright (c) 2002 by J Brown
//	Freeware

unit uWindows;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ComCtrls, Vcl.ExtCtrls, Math, StrUtils,
  Generics.Collections, Vcl.StdCtrls, Vcl.Mask, System.ImageList, Vcl.ImgList,
  Vcl.Buttons, Clipbrd, uBaseForm,

  MemoryMap.Core,
  MemoryMap.RegionData,
  MemoryMap.Utils,

  RawScanner.AbstractImage,
  RawScanner.SymbolStorage,
  RawScanner.Image.Pe,
  RawScanner.Core,

  uDisplayStyleInfo, Vcl.Menus;

type
  TRemoteWndData = record
    WndProc, DlgProc, RealDlgProc, Instance: UInt64;
  end;

  TRemoteStyle = record
    Name: string;
    Value: DWORD;
  end;

  TdlgWindows = class(TBaseAppForm)
    tvWindows: TTreeView;
    vSplitter: TSplitter;
    pcWindows: TPageControl;
    tsGeneral: TTabSheet;
    tsStyles: TTabSheet;
    tsProperties: TTabSheet;
    tsClass: TTabSheet;
    il16: TImageList;
    Label1: TLabel;
    edHandle: TEdit;
    Label2: TLabel;
    edCaption: TEdit;
    Label3: TLabel;
    edClass: TEdit;
    Label4: TLabel;
    edStyle: TEdit;
    edRect: TEdit;
    edCRect: TEdit;
    edWndProc: TEdit;
    edInstHandle: TEdit;
    edCtlID: TEdit;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    edUserData: TEdit;
    Label10: TLabel;
    Label11: TLabel;
    edDlgProc: TEdit;
    Label12: TLabel;
    edLanguage: TEdit;
    Label13: TLabel;
    tsFont: TTabSheet;
    tsUserData: TTabSheet;
    edClassName: TEdit;
    Label14: TLabel;
    btnOpenInst: TSpeedButton;
    btnOpenDlgProc: TSpeedButton;
    btnOpenWndProc: TSpeedButton;
    edRole: TEdit;
    Label15: TLabel;
    cbClassStyle: TComboBox;
    edClassStyle: TEdit;
    Label16: TLabel;
    edClassAtom: TEdit;
    Label17: TLabel;
    edClassProc: TEdit;
    Label18: TLabel;
    btnOpenClassProc: TSpeedButton;
    edClassModule: TEdit;
    Label19: TLabel;
    btOpenClassInst: TSpeedButton;
    lbStyles: TListBox;
    edExStyle: TEdit;
    Label20: TLabel;
    lbExStyle: TListBox;
    pmCopy: TPopupMenu;
    CopySelected1: TMenuItem;
    SelectAll1: TMenuItem;
    N1: TMenuItem;
    lvProps: TListView;
    lvScroll: TListView;
    Label21: TLabel;
    memFont: TMemo;
    btnOpenUserData: TSpeedButton;
    memWndBytes: TMemo;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormKeyPress(Sender: TObject; var Key: Char);
    procedure tvWindowsChange(Sender: TObject; Node: TTreeNode);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnOpenWndProcClick(Sender: TObject);
    procedure lbStylesDrawItem(Control: TWinControl; Index: Integer;
      Rect: TRect; State: TOwnerDrawState);
    procedure tsStylesResize(Sender: TObject);
    procedure CopySelected1Click(Sender: TObject);
    procedure SelectAll1Click(Sender: TObject);
  private
    FBuff: array [0..MAX_PATH] of Char; // + 1 для терминирующего
    FBuffLen: DWORD;
    FWndIndex: Integer;
    FWndList: TList<UInt64>;
    FWndData: TList<TRemoteWndData>;
    FWndStyles, FWndExStyles: TList<TRemoteStyle>;
    function AddrVAToStr(Value: UInt64; AButton: TSpeedButton = nil): string;
    function BuffToString: string;
    procedure Callback(pStyleLookup: PStyleLookupEx);
    procedure CallbackEx(pStyleLookup: PStyleLookupEx);
    procedure CheckAndAddComboValue(ACtl: TComboBox; AValue, AMask: UInt64; const MaskStr: string);
    function ClassifyByMSAA(hWnd: HWND; out RoleName: string): string;
    function EmptyRemoteWndData: TRemoteWndData;
    function IconIndexFromWindow(AHandle: HWND; dwStyle: DWORD; const AClassName: string): Integer;
    function GetExecutableDlgProc(hProc: THandle; AddrVA: UInt64): UInt64;
    function GetModule(ModuleInst: UInt64): string;
    function GetWndClassName(AHandle: HWND): string;
    function GetWndText(AHandle: HWND): string;
    procedure Fill(Node: TTreeNode; AHandle: HWND);
    procedure FillClassInfo(AHandle: HWND);
    procedure FillFontInfo(AHandle: HWND);
    procedure FillGeneralInfo(AHandle: HWND; const Info: TWindowInfo);
    procedure FillPropsInfo(AHandle: HWND; const Info: TWindowInfo);
    procedure FillStylesInfo(AHandle: HWND; const Info: TWindowInfo);
    procedure FillWindow(AHandle: HWND);
    procedure FillUserData(AHandle: HWND);
    procedure InternalUpdate;
    function LookUpClassIndex(const AClassName: string; dwStyle: DWORD): Integer;
    procedure QueryWndProcInRemoteApp;
  public
    procedure ShowProcessWindows;
  end;

  {
    Windows запрещает напрямую получать у окна значение его WndProc, DlgProc
    и Instance, поэтому реализованы две функции:
    1. ExecuteX64GetWndProcList
    Она инжектит в удаленный процесс небольшой ShellCode (задача которого
    получить эти данные) и запускает нить с этим шеллкодом.
    Парамерты окон, по которым необходимо получить информацию хранятся в
    именованом MemoryMapFile в который также пишутся резульаты работы шеллкода.
    2. ExecuteX86GetWndProcList
    Делает тоже самое что и первая функция, но она выполняется в 32 битном
    экземпляре ProcessMemoryMap которому параметры настройки шеллкода передаются
    через второй именованный MemoryMapFile. Сам вызов осуществляется через
    общий механизм IPC
  }
  function ExecuteX86GetWndProcList(PID: DWORD): LRESULT;

var
  dlgWindows: TdlgWindows;

implementation

uses
  Variants, ActiveX, AccCtrl,

  uIPC,
  uRegionProperties,
  uUtils;

const
  PMM_GetRemoteWndInfo = 'PMM_GetRemoteWndInfo'#0;

  X86_CalculatedFuncAddrVA = 'PMM_X86_CalculatedFuncAddrVA';
  X86_PMM_MMF_Off = 13;
  X86_OpenFileMapping_Off = 22;
  x86_GetLastError_Off1 = 33;
  X86_MapViewOfFile_Off = 52;
  x86_GetLastError_Off2 = 63;
  X86_GetWindowLongPtr1_Off = 82;
  X86_GetWindowLongPtr2_Off = 101;
  X86_GetWindowLongPtr3_Off = 120;
  X86_UnmapViewOfFile_Off = 146;
  X86_CloseHandle_Off = 152;

  X86_ShellCode: array [0..166] of Byte = (
    $55,               // push ebp
    $8B,$EC,           // mov ebp,esp
    $51,               // push ecx
    $53,               // push ebx
    $56,               // push esi
    $57,               // push edi
    // Result := 0;
    $33,$C0,           // xor eax,eax
    $89,$45,$FC,       // mov [ebp-$04],eax
    // hMapFile := OpenFileMapping(FILE_MAP_READ or FILE_MAP_WRITE, False, PChar(PMM_GetRemoteWndInfo));
    $68, 0, 0, 0, 0,   // push PChar(PMM_GetRemoteWndInfo) - 13
    $6A, 0,            // push $00
    $6A, 6,            // push $06
    $E8, 0, 0, 0, 0,   // call OpenFileMapping - 22
    $8B,$F0,           // mov esi,eax
    // if hMapFile = 0 then Exit(GetLastError);
    $85,$F6,           // test esi,esi
    $75,$0A,           // jnz @checked1
    $E8, 0, 0, 0, 0,   // call $GetLastError - 33
    $89,$45,$FC,       // mov [ebp-$04],eax
    $EB,$72,           // jmp @end
    // pMapView := MapViewOfFile(hMapFile, FILE_MAP_READ or FILE_MAP_WRITE, 0, 0, 0);
    // === > @checked1: =========================================
    $6A, 0,            // push $00
    $6A, 0,            // push $00
    $6A, 0,            // push $00
    $6A, 6,            // push $06
    $56,               // push esi
    $E8, 0, 0, 0, 0,   // call MapViewOfFile - 52
    $8B,$F8,           // mov edi,eax
    // if pMapView = nil then Exit(GetLastError);
    $85,$FF,           // test edi,edi
    $75,$0A,           // jnz @checked2
    $E8, 0, 0, 0, 0,   // call $GetLastError - 63
    $89,$45,$FC,       // mov [ebp-$04],eax
    $EB,$54,           // jmp @end
    // pCurrent := PInt64(pMapView);
    // === > @checked2: =========================================
    $8B,$DF,           // mov ebx,edi
    $EB,$39,           // jmp @while
    // pCurrent^ := GetWindowLongPtr(pCurrent^, GWL_WNDPROC);
    // === >  @get_wnd_proc: ====================================
    $6A,$FC,           // push $fc
    $8B, 3,            // mov eax,[ebx]
    $50,               // push eax
    $E8, 0, 0, 0, 0,   // call GetWindowLongPtr - 82
    $99,               // cdq
    $89, 3,            // mov [ebx],eax
    $89,$53, 4,        // mov [ebx+$04],edx
    // Inc(pCurrent);
    $83,$C3, 8,        // add ebx,$08
    // pCurrent^ := GetWindowLongPtr(pCurrent^, DWL_DLGPROC);
    $6A, 4,            // push 4
    $8B, 3,            // mov eax,[ebx]
    $50,               // push eax
    $E8, 0, 0, 0, 0,   // call GetWindowLongPtr - 101
    $99,               // cdq
    $89, 3,            // mov [ebx],eax
    $89,$53, 4,        // mov [ebx+$04],edx
    // Inc(pCurrent);
    $83,$C3, 8,        // add ebx,$08
    // pCurrent^ := GetWindowLongPtr(pCurrent^, GWL_HINSTANCE);
    $6A,$FA,           // push $fa
    $8B, 3,            // mov eax,[ebx]
    $50,               // push eax
    $E8, 0, 0, 0, 0,   // call GetWindowLongPtr - 120
    $99,               // cdq
    $89, 3,            // mov [ebx],eax
    $89,$53, 4,        // mov [ebx+$04],edx
    // Inc(pCurrent);
    $83,$C3, 8,        // add ebx,$08
    // while pCurrent^ <> 0 do
    // === > @while: ============================================
    $83,$7B, 4, 0,     // cmp dword ptr [ebx+$04],$00
    $75,$C1,           // jnz @get_wnd_proc
    $83,$3B, 0,        // cmp dword ptr [ebx],$00
    $75,$BC,           // jnz @get_wnd_proc
    // UnmapViewOfFile(pMapView);
    $57,               // push edi
    $E8, 0, 0, 0, 0,   // call UnmapViewOfFile - 146
    // CloseHandle(hMapFile);
    $56,               // push esi
    $E8, 0, 0, 0, 0,   // call CloseHandle - 152
    // === > @end ===============================================
    $8B,$45,$FC,       // mov eax,[ebp-$04]
    $5F,               // pop edi
    $5E,               // pop esi
    $5B,               // pop ebx
    $59,               // pop ecx
    $5D,               // pop ebp
    $C2, 4, 0          // ret $0004
  );

  X64_OpenFileMapping_Off = 31;
  X64_GetLastError_Off1 = 45;
  X64_MapViewOfFile_Off = 74;
  X64_GetLastError_Off2 = 88;
  X64_GetWindowLongPtr1_Off = 111;
  X64_GetWindowLongPtr2_Off = 134;
  X64_GetWindowLongPtr3_Off = 157;
  X64_UnmapViewOfFile_Off = 183;
  X64_CloseHandle_Off = 192;
  X64_PMM_MMF_Off = 240;

  X64_ShellCode: array [0..208] of Byte = (
    $55,                    // push rbp
    $41,$55,                // push r13
    $57,                    // push rdi
    $56,                    // push rsi
    $53,                    // push rbx
    $48,$83,$EC,$30,        // sub rsp,$30
    $48,$8B,$EC,            // mov rbp,rsp
    // Result := 0;
    $33,$DB,                // xor ebx,ebx
    // hMapFile := OpenFileMapping(FILE_MAP_READ or FILE_MAP_WRITE, False, PChar('MyMappingName'));
    $B9,$06, 0, 0, 0,       // mov ecx, 0000006
    $33,$D2,                // xor edx,edx
    $4C,$8B,$05,$CB,0,0,0,  // lea r8,[rel $000000CB]
    $FF, $15, 0, 0, 0, 0,   // call OpenFileMapping - 31
    $48,$89,$C6,            // mov rsi,rax
    // if hMapFile = 0 then Exit(GetLastError);
    $48,$85,$F6,            // test rsi,rsi
    $75,$0A,                // jnz @checked1
    $FF, $15, 0, 0, 0, 0,   // call GetLastError - 45
    $89,$C3,                // mov ebx,eax
    $EB,$29,                // jmp @end
    // pMapView := MapViewOfFile(hMapFile, FILE_MAP_READ or FILE_MAP_WRITE, 0, 0, 0);
    // === > @checked1: =========================================
    $48,$89,$F1,            // mov rcx,rsi
    $BA,$06, 0, 0, 0,       // mov edx, 0000006
    $4D,$33,$C0,            // xor r8,r8
    $4D,$33,$C9,            // xor r9,r9
    $4C,$89,$4C,$24,$20,    // mov [rsp+$20],r9
    $FF, $15, 0, 0, 0, 0,   // call MapViewOfFile - 74
    $48,$89,$C7,            // mov rdi,rax
    // if pMapView = nil then Exit(GetLastError);
    $48,$85,$FF,            // test rdi,rdi
    $75,$0A,                // jnz @checked2
    $FF, $15, 0, 0, 0, 0,   // call GetLastError - 88
    $89,$C3,                // mov ebx,eax
    $EB,$64,                // jmp @end
    // pCurrent := PInt64(pMapView);
    // === > @checked2: =========================================
    $49,$89,$FD,            // mov r13,rdi
    $EB,$44,                // jmp @while
    // pCurrent^ := GetWindowLongPtr(pCurrent^, GWL_WNDPROC);
    // === >  @get_wnd_proc: ====================================
    $48,$89,$C1,            // mov rcx,rax
    $BA,$FC,$FF,$FF,$FF,    // mov edx,$fffffffc
    $FF, $15, 0, 0, 0, 0,   // call GetWindowLongPtr - 111
    $49,$89,$45, 0,         // mov [r13+$00],rax
    // Inc(pCurrent);
    $49,$83,$C5,$08,        // add r13,$08
    // pCurrent^ := GetWindowLongPtr(pCurrent^, DWL_DLGPROC);
    $49,$8B,$4D, 0,         // mov rcx,[r13+00]
    $BA, 8, 0, 0, 0,        // mov edx,8
    $FF, $15, 0, 0, 0, 0,   // call GetWindowLongPtr - 134
    $49,$89,$45, 0,         // mov [r13+$00],rax
    // Inc(pCurrent);
    $49,$83,$C5,$08,        // add r13,$08
    // pCurrent^ := GetWindowLongPtr(pCurrent^, GWL_HINSTANCE);
    $49,$8B,$4D, 0,         // mov rcx,[r13+00]
    $BA,$FA,$FF,$FF,$FF,    // mov edx,$fffffffa
    $FF, $15, 0, 0, 0, 0,   // call GetWindowLongPtr - 157
    $49,$89,$45, 0,         // mov [r13+$00],rax
    // Inc(pCurrent);
    $49,$83,$C5,$08,        // add r13,$08
    // while pCurrent^ <> 0 do
    // === > @while: ============================================
    $49,$8B,$45, 0,         // mov rax,[r13+$00]
    $48,$85,$C0,            // test rax,rax
    $75,$B3,                // jnz @get_wnd_proc
    // UnmapViewOfFile(pMapView);
    $48,$89,$F9,            // mov rcx,rdi
    $FF, $15, 0, 0, 0, 0,   // call UnmapViewOfFile - 183
    // CloseHandle(hMapFile);
    $48,$89,$F1,            // mov rcx,rsi
    $FF, $15, 0, 0, 0, 0,   // call CloseHandle - 192
    // === > @end ===============================================
    $89,$D8,                // mov eax,ebx
    $48,$8D,$65,$30,        // lea rsp,[rbp+$30]
    $5B,                    // pop rbx
    $5E,                    // pop rsi
    $5F,                    // pop rdi
    $41,$5D,                // pop r13
    $5D,                    // pop rbp
    $C3                     // ret
  );

  CHILDID_SELF = 0;
  OBJID_CLIENT = DWORD(-4);

  ROLE_SYSTEM_TITLEBAR           = $00000001;
  ROLE_SYSTEM_MENUBAR            = $00000002;
  ROLE_SYSTEM_SCROLLBAR          = $00000003;
  ROLE_SYSTEM_GRIP               = $00000004;
  ROLE_SYSTEM_SOUND              = $00000005;
  ROLE_SYSTEM_CURSOR             = $00000006;
  ROLE_SYSTEM_CARET              = $00000007;
  ROLE_SYSTEM_ALERT              = $00000008;
  ROLE_SYSTEM_WINDOW             = $00000009;
  ROLE_SYSTEM_CLIENT             = $0000000A;
  ROLE_SYSTEM_MENUPOPUP          = $0000000B;
  ROLE_SYSTEM_MENUITEM           = $0000000C;
  ROLE_SYSTEM_TOOLTIP            = $0000000D;
  ROLE_SYSTEM_APPLICATION        = $0000000E;
  ROLE_SYSTEM_DOCUMENT           = $0000000F;
  ROLE_SYSTEM_PANE               = $00000010;
  ROLE_SYSTEM_CHART              = $00000011;
  ROLE_SYSTEM_DIALOG             = $00000012;
  ROLE_SYSTEM_BORDER             = $00000013;
  ROLE_SYSTEM_GROUPING           = $00000014;
  ROLE_SYSTEM_SEPARATOR          = $00000015;
  ROLE_SYSTEM_TOOLBAR            = $00000016;
  ROLE_SYSTEM_STATUSBAR          = $00000017;
  ROLE_SYSTEM_TABLE              = $00000018;
  ROLE_SYSTEM_COLUMNHEADER       = $00000019;
  ROLE_SYSTEM_ROWHEADER          = $0000001A;
  ROLE_SYSTEM_COLUMN             = $0000001B;
  ROLE_SYSTEM_ROW                = $0000001C;
  ROLE_SYSTEM_CELL               = $0000001D;
  ROLE_SYSTEM_LINK               = $0000001E;
  ROLE_SYSTEM_HELPBALLOON        = $0000001F;
  ROLE_SYSTEM_CHARACTER          = $00000020;
  ROLE_SYSTEM_LIST               = $00000021;
  ROLE_SYSTEM_LISTITEM           = $00000022;
  ROLE_SYSTEM_OUTLINE            = $00000023;
  ROLE_SYSTEM_OUTLINEITEM        = $00000024;
  ROLE_SYSTEM_PAGETAB            = $00000025;
  ROLE_SYSTEM_PROPERTYPAGE       = $00000026;
  ROLE_SYSTEM_INDICATOR          = $00000027;
  ROLE_SYSTEM_GRAPHIC            = $00000028;
  ROLE_SYSTEM_STATICTEXT         = $00000029;
  ROLE_SYSTEM_TEXT               = $0000002A;
  ROLE_SYSTEM_PUSHBUTTON         = $0000002B;
  ROLE_SYSTEM_CHECKBUTTON        = $0000002C;
  ROLE_SYSTEM_RADIOBUTTON        = $0000002D;
  ROLE_SYSTEM_COMBOBOX           = $0000002E;
  ROLE_SYSTEM_DROPLIST           = $0000002F;
  ROLE_SYSTEM_PROGRESSBAR        = $00000030;
  ROLE_SYSTEM_DIAL               = $00000031;
  ROLE_SYSTEM_HOTKEYFIELD        = $00000032;
  ROLE_SYSTEM_SLIDER             = $00000033;
  ROLE_SYSTEM_SPINBUTTON         = $00000034;
  ROLE_SYSTEM_DIAGRAM            = $00000035;
  ROLE_SYSTEM_ANIMATION          = $00000036;
  ROLE_SYSTEM_EQUATION           = $00000037;
  ROLE_SYSTEM_BUTTONDROPDOWN     = $00000038;
  ROLE_SYSTEM_BUTTONMENU         = $00000039;
  ROLE_SYSTEM_BUTTONDROPDOWNGRID = $0000003A;
  ROLE_SYSTEM_WHITESPACE         = $0000003B;
  ROLE_SYSTEM_PAGETABLIST        = $0000003C;
  ROLE_SYSTEM_CLOCK              = $0000003D;
  ROLE_SYSTEM_SPLITBUTTON        = $0000003E;
  ROLE_SYSTEM_IPADDRESS          = $0000003F;
  ROLE_SYSTEM_OUTLINEBUTTON      = $00000040;

type
  IAccessible = interface(IDispatch)
    ['{618736E0-3C3D-11CF-810C-00AA00389B71}']
    function Get_accParent(out ppdispParent: IDispatch): HResult; stdcall;
    function Get_accChildCount(out pcountChildren: Integer): HResult; stdcall;
    function Get_accChild(varChild: OleVariant; out ppdispChild: IDispatch): HResult; stdcall;
    function Get_accName(varChild: OleVariant; out pszName: WideString): HResult; stdcall;
    function Get_accValue(varChild: OleVariant; out pszValue: WideString): HResult; stdcall;
    function Get_accDescription(varChild: OleVariant; out pszDescription: WideString): HResult; stdcall;
    function Get_accRole(varChild: OleVariant; out pvarRole: OleVariant): HResult; stdcall;
    function Get_accState(varChild: OleVariant; out pvarState: OleVariant): HResult; stdcall;
    function Get_accHelp(varChild: OleVariant; out pszHelp: WideString): HResult; stdcall;
    function Get_accHelpTopic(out pszHelpFile: WideString; varChild: OleVariant; out pidTopic: Integer): HResult; stdcall;
    function Get_accKeyboardShortcut(varChild: OleVariant; out pszKeyboardShortcut: WideString): HResult; stdcall;
    function Get_accFocus(out pvarChild: OleVariant): HResult; stdcall;
    function Get_accSelection(out pvarChildren: OleVariant): HResult; stdcall;
    function Get_accDefaultAction(varChild: OleVariant; out pszDefaultAction: WideString): HResult; stdcall;
    function AccSelect(flagsSelect: Integer; varChild: OleVariant): HResult; stdcall;
    function AccLocation(out pxLeft, pyTop, pcxWidth, pcyHeight: Integer; varChild: OleVariant): HResult; stdcall;
    function AccNavigate(navDir: Integer; varStart: OleVariant; out pvarEndUpAt: OleVariant): HResult; stdcall;
    function AccHitTest(xLeft, yTop: Integer; out pvarChild: OleVariant): HResult; stdcall;
    function AccDoDefaultAction(varChild: OleVariant): HResult; stdcall;
    function Set_accName(varChild: OleVariant; pszName: WideString): HResult; stdcall;
    function Set_accValue(varChild: OleVariant; pszValue: WideString): HResult; stdcall;
  end;

  function AccessibleObjectFromWindow(hwnd: HWND; dwId: DWORD;
    const riid: TGUID; var ppvObject): HRESULT; stdcall;
    external 'oleacc.dll' name 'AccessibleObjectFromWindow';

  function GetRoleTextW(lRole: DWORD; lpszRole: PWideChar; cchRoleMax: UINT): UINT; stdcall;
    external 'oleacc.dll' name 'GetRoleTextW';

type
  TClassImageLookup = record
    szName: string;
    index: Integer;
    dwAdjustStyles: DWORD;
    dwMask: DWORD;
  end;

const
  ClassImage: array[0..36] of TClassImageLookup = (
    (szName: TYPE_DIALOG;             index: 2;   dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_BUTTON;             index: 7;   dwAdjustStyles: BS_GROUPBOX;                 dwMask: $F),
    (szName: TYPE_BUTTON;             index: 5;   dwAdjustStyles: BS_CHECKBOX;                 dwMask: $F),
    (szName: TYPE_BUTTON;             index: 5;   dwAdjustStyles: BS_AUTOCHECKBOX;             dwMask: $F),
    (szName: TYPE_BUTTON;             index: 5;   dwAdjustStyles: BS_AUTO3STATE;               dwMask: $F),
    (szName: TYPE_BUTTON;             index: 5;   dwAdjustStyles: BS_3STATE;                   dwMask: $F),
    (szName: TYPE_BUTTON;             index: 6;   dwAdjustStyles: BS_RADIOBUTTON;              dwMask: $F),
    (szName: TYPE_BUTTON;             index: 6;   dwAdjustStyles: BS_AUTORADIOBUTTON;          dwMask: $F),
    (szName: TYPE_BUTTON;             index: 4;   dwAdjustStyles: 0;                           dwMask: 0), // (default push-button)
    (szName: TYPE_COMBOBOX;           index: 8;   dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_EDIT;               index: 9;   dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_LISTBOX;            index: 10;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_ComboLBox;          index: 10;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_RICHEDIT;           index: 11;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_RichEdit20A;        index: 11;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_RichEdit20W;        index: 11;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SCROLLBAR;          index: 12;  dwAdjustStyles: SBS_VERT;                    dwMask: 0),
    (szName: TYPE_SCROLLBAR;          index: 14;  dwAdjustStyles: SBS_SIZEBOX or SBS_SIZEGRIP; dwMask: 0),
    (szName: TYPE_SCROLLBAR;          index: 13;  dwAdjustStyles: 0;                           dwMask: 0), // (default horizontal)
    (szName: TYPE_STATIC;             index: 15;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysAnimate32;       index: 16;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysDateTimePick32;  index: 17;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysHeader32;        index: 18;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_IPAddress;          index: 19;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysListView32;      index: 20;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysMonthCal32;      index: 21;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysPager;           index: 22;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_msctls_progress32;  index: 23;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_ReBarWindow32;      index: 24;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_msctls_statusbar32; index: 25;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysLink;            index: 26;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysTabControl32;    index: 27;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_ToolbarWindow32;    index: 28;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_tooltips_class32;   index: 29;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_msctls_trackbar32;  index: 30;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_SysTreeView32;      index: 31;  dwAdjustStyles: 0;                           dwMask: 0),
    (szName: TYPE_msctls_updown32;    index: 32;  dwAdjustStyles: 0;                           dwMask: 0)
  );

{$R *.dfm}

function ExecuteX86GetWndProcList(PID: DWORD): LRESULT;
var
  hMapFile, hProc, hThread: THandle;
  pMapFile: Pointer;
  pCurrent: PUInt64;
  OpenFileMappingAddrVA, MapViewOfFileAddrVA,
  UnmapViewOfFileAddrVA, CloseHandleAddrVA, GetLastErrorAddrVA,
  GetWindowLongPtrAddrVA: UInt64;
  ShellCode: array [0..166] of Byte;
  pShellCode, pMMFNameBuff: PByte;
  BytesWriten: SIZE_T;
  dwThreadId, dwExitCode: DWORD;
begin
  hMapFile := OpenFileMapping(FILE_MAP_READ, False, PChar(X86_CalculatedFuncAddrVA));
  if hMapFile = 0 then Exit(GetLastError);
  try
    pMapFile := MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
    if pMapFile = nil then Exit(GetLastError);
    try
      pCurrent := PUInt64(pMapFile);
      OpenFileMappingAddrVA := pCurrent^;
      Inc(pCurrent);
      MapViewOfFileAddrVA := pCurrent^;
      Inc(pCurrent);
      UnmapViewOfFileAddrVA := pCurrent^;
      Inc(pCurrent);
      CloseHandleAddrVA := pCurrent^;
      Inc(pCurrent);
      GetLastErrorAddrVA := pCurrent^;
      Inc(pCurrent);
      GetWindowLongPtrAddrVA := pCurrent^;
    finally
      UnmapViewOfFile(pMapFile);
    end;
  finally
    CloseHandle(hMapFile);
  end;
  hProc := OpenProcess(PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or
    PROCESS_VM_WRITE, False, PID);
  if hProc = 0 then Exit(GetLastError);
  try
    pShellCode := VirtualAllocEx(hProc, nil, Length(X86_ShellCode),
      MEM_COMMIT or MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
    if pShellCode = nil then Exit(GetLastError);
    try
      pMMFNameBuff := VirtualAllocEx(hProc, nil, Length(PMM_GetRemoteWndInfo) shl 1,
        MEM_COMMIT or MEM_TOP_DOWN, PAGE_READWRITE);
      if pMMFNameBuff = nil then Exit(GetLastError);
      try
        if not WriteProcessMemory(hProc, pMMFNameBuff, @PMM_GetRemoteWndInfo[1],
          Length(PMM_GetRemoteWndInfo) shl 1, BytesWriten) then Exit(GetLastError);
        Move(X86_ShellCode[0], ShellCode[0], Length(X86_ShellCode));
        {$PUSHOPT} {$R-} {$Q-}
        PDWORD(@ShellCode[X86_PMM_MMF_Off])^ := DWORD(pMMFNameBuff);
        PDWORD(@ShellCode[X86_OpenFileMapping_Off])^ := DWORD(OpenFileMappingAddrVA) -
          (DWORD(pShellCode) + X86_OpenFileMapping_Off + SizeOf(DWORD));
        PDWORD(@ShellCode[x86_GetLastError_Off1])^ := DWORD(GetLastErrorAddrVA) -
          (DWORD(pShellCode) + x86_GetLastError_Off1 + SizeOf(DWORD));
        PDWORD(@ShellCode[X86_MapViewOfFile_Off])^ := DWORD(MapViewOfFileAddrVA) -
          (DWORD(pShellCode) + X86_MapViewOfFile_Off + SizeOf(DWORD));
        PDWORD(@ShellCode[x86_GetLastError_Off2])^ := DWORD(GetLastErrorAddrVA) -
          (DWORD(pShellCode) + x86_GetLastError_Off2 + SizeOf(DWORD));
        PDWORD(@ShellCode[X86_GetWindowLongPtr1_Off])^ := DWORD(GetWindowLongPtrAddrVA) -
          (DWORD(pShellCode) + X86_GetWindowLongPtr1_Off + SizeOf(DWORD));
        PDWORD(@ShellCode[X86_GetWindowLongPtr2_Off])^ := DWORD(GetWindowLongPtrAddrVA) -
          (DWORD(pShellCode) + X86_GetWindowLongPtr2_Off + SizeOf(DWORD));
        PDWORD(@ShellCode[X86_GetWindowLongPtr3_Off])^ := DWORD(GetWindowLongPtrAddrVA) -
          (DWORD(pShellCode) + X86_GetWindowLongPtr3_Off + SizeOf(DWORD));
        PDWORD(@ShellCode[X86_UnmapViewOfFile_Off])^ := DWORD(UnmapViewOfFileAddrVA) -
          (DWORD(pShellCode) + X86_UnmapViewOfFile_Off + SizeOf(DWORD));
        PDWORD(@ShellCode[X86_CloseHandle_Off])^ := DWORD(CloseHandleAddrVA) -
          (DWORD(pShellCode) + X86_CloseHandle_Off + SizeOf(DWORD));
        {$POPOPT}
        if not WriteProcessMemory(hProc, pShellCode, @ShellCode[0],
          Length(X86_ShellCode), BytesWriten) then Exit(GetLastError);
        hThread := CreateRemoteThread(hProc, nil, 0, pShellCode, nil, 0, dwThreadId);
        if hThread = 0 then Exit(GetLastError);
        Result := ERROR_ACCESS_DENIED;
        if WaitForSingleObject(hThread, 1000) = WAIT_OBJECT_0 then
          if GetExitCodeThread(hThread, dwExitCode) then
            Result := LRESULT(dwExitCode);
      finally
        VirtualFreeEx(hProc, pMMFNameBuff, Length(PMM_GetRemoteWndInfo) shl 1, MEM_RELEASE);
      end;
    finally
      VirtualFreeEx(hProc, pShellCode, Length(X86_ShellCode), MEM_RELEASE);
    end;
  finally
    CloseHandle(hProc);
  end;
end;

function ExecuteX64GetWndProcList(hProc: THandle; OpenFileMappingAddrVA,
  MapViewOfFileAddrVA, UnmapViewOfFileAddrVA, CloseHandleAddrVA,
  GetLastErrorAddrVA, GetWindowLongPtrAddrVA: UInt64): Boolean;
var
  hThread: THandle;
  pCurrent: PUInt64;
  ShellCode: array of Byte;
  pShellCode: PByte;
  BytesWriten: SIZE_T;
  dwThreadId, dwExitCode: DWORD;
begin
  Result := False;
  SetLength(ShellCode, X64_PMM_MMF_Off + 48 + Length(PMM_GetRemoteWndInfo) shl 1);
  pShellCode := VirtualAllocEx(hProc, nil, Length(ShellCode),
    MEM_COMMIT or MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
  if pShellCode = nil then Exit;
  try
    Move(X64_ShellCode[0], ShellCode[0], Length(X64_ShellCode));
    PUInt64(@ShellCode[X64_PMM_MMF_Off - 8])^ := UInt64(pShellCode + X64_PMM_MMF_Off);
    Move(PMM_GetRemoteWndInfo[1], ShellCode[X64_PMM_MMF_Off], Length(PMM_GetRemoteWndInfo) shl 1);
    pCurrent := @ShellCode[X64_PMM_MMF_Off + Length(PMM_GetRemoteWndInfo) shl 1];
    pCurrent^ := OpenFileMappingAddrVA;
    {$PUSHOPT} {$R-} {$Q-}
    PDWORD(@ShellCode[X64_OpenFileMapping_Off])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_OpenFileMapping_Off + SizeOf(DWORD));
    Inc(pCurrent);
    pCurrent^ := GetLastErrorAddrVA;
    PDWORD(@ShellCode[X64_GetLastError_Off1])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_GetLastError_Off1 + SizeOf(DWORD));
    PDWORD(@ShellCode[X64_GetLastError_Off2])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_GetLastError_Off2 + SizeOf(DWORD));
    Inc(pCurrent);
    pCurrent^ := MapViewOfFileAddrVA;
    PDWORD(@ShellCode[X64_MapViewOfFile_Off])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_MapViewOfFile_Off + SizeOf(DWORD));
    Inc(pCurrent);
    pCurrent^ := GetWindowLongPtrAddrVA;
    PDWORD(@ShellCode[X64_GetWindowLongPtr1_Off])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_GetWindowLongPtr1_Off + SizeOf(DWORD));
    PDWORD(@ShellCode[X64_GetWindowLongPtr2_Off])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_GetWindowLongPtr2_Off + SizeOf(DWORD));
    PDWORD(@ShellCode[X64_GetWindowLongPtr3_Off])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_GetWindowLongPtr3_Off + SizeOf(DWORD));
    Inc(pCurrent);
    pCurrent^ := UnmapViewOfFileAddrVA;
    PDWORD(@ShellCode[X64_UnmapViewOfFile_Off])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_UnmapViewOfFile_Off + SizeOf(DWORD));
    Inc(pCurrent);
    pCurrent^ := CloseHandleAddrVA;
    PDWORD(@ShellCode[X64_CloseHandle_Off])^ := UInt64(pCurrent) -
      (UInt64(@ShellCode[0]) + X64_CloseHandle_Off + SizeOf(DWORD));
    {$POPOPT}
    if not WriteProcessMemory(hProc, pShellCode, @ShellCode[0],
      Length(ShellCode), BytesWriten) then Exit;
    hThread := CreateRemoteThread(hProc, nil, 0, pShellCode, nil, 0, dwThreadId);
    if hThread = 0 then Exit;
    if WaitForSingleObject(hThread, 1000) = WAIT_OBJECT_0 then
      if GetExitCodeThread(hThread, dwExitCode) then
        Result := dwExitCode = NO_ERROR;
  finally
    VirtualFreeEx(hProc, pShellCode, Length(ShellCode), MEM_RELEASE);
  end;
end;

{ TdlgWindows }

function TdlgWindows.AddrVAToStr(Value: UInt64; AButton: TSpeedButton): string;
begin
  if Assigned(AButton) then
  begin
    AButton.Enabled := Value <> 0;
    AButton.ShowHint := Value <> 0;
  end;
  if Value = 0 then
    Result := 'N/A'
  else
    Result := IntToHex(Value, 8);
end;

procedure TdlgWindows.btnOpenWndProcClick(Sender: TObject);
var
  AddrVA: UInt64;
begin
  case TSpeedButton(Sender).Tag of
    0: AddrVA := FWndData.List[FWndIndex].WndProc;
    1:
      if FWndData.List[FWndIndex].RealDlgProc = 0 then
        AddrVA := FWndData.List[FWndIndex].DlgProc
      else
        AddrVA := FWndData.List[FWndIndex].RealDlgProc;
    2: AddrVA := FWndData.List[FWndIndex].Instance;
    3: TryStrToUInt64('$' + edClassProc.Text, AddrVA);
    4: TryStrToUInt64('$' + edClassModule.Text, AddrVA);
    5: TryStrToUInt64('$' + edUserData.Text, AddrVA);
  end;
  if not CheckAddr(AddrVA) then Exit;  
  dlgRegionProps := TdlgRegionProps.Create(Application);
  dlgRegionProps.ShowPropertyAtAddr(Pointer(AddrVA));
end;

function TdlgWindows.BuffToString: string;
begin
  if FBuffLen = 0 then
    Result := ''
  else
  begin
    SetLength(Result, FBuffLen);
    Move(FBuff[0], Result[1], FBuffLen shl 1);
  end;
end;

procedure TdlgWindows.Callback(pStyleLookup: PStyleLookupEx);
var
  S: TRemoteStyle;
begin
  S.Name := pStyleLookup^.name;
  S.Value := pStyleLookup^.style;
  if S.Value = 0 then
    FWndStyles.Insert(0, S)
  else
    FWndStyles.Add(S);
end;

procedure TdlgWindows.CallbackEx(pStyleLookup: PStyleLookupEx);
var
  S: TRemoteStyle;
begin
  S.Name := pStyleLookup^.name;
  S.Value := pStyleLookup^.style;
  if S.Value = 0 then
    FWndExStyles.Insert(0, S)
  else
    FWndExStyles.Add(S);
end;

procedure TdlgWindows.CheckAndAddComboValue(ACtl: TComboBox; AValue,
  AMask: UInt64; const MaskStr: string);
begin
  if AValue and AMask = AMask then
    ACtl.Items.Add(MaskStr);
end;

function TdlgWindows.ClassifyByMSAA(hWnd: HWND; out RoleName: string): string;
var
  Acc: IAccessible;
  VarRole: OleVariant;
  Buf: array[0..127] of WideChar;
  Role: DWORD;
begin
  Result := '';
  RoleName := '';
  if Failed(AccessibleObjectFromWindow(hWnd, OBJID_CLIENT, IAccessible, Acc)) or not Assigned(Acc) then
    Exit;
  try
    if Failed(Acc.Get_accRole(CHILDID_SELF, VarRole)) then Exit;
    if VarType(VarRole) <> varInteger then Exit;
    Role := DWORD(Integer(VarRole));
    if GetRoleTextW(Role, Buf, Length(Buf)) > 0 then
      RoleName := Buf;
    case Role of
      ROLE_SYSTEM_DIALOG:          Result := TYPE_DIALOG;
      ROLE_SYSTEM_PUSHBUTTON,
      ROLE_SYSTEM_CHECKBUTTON,
      ROLE_SYSTEM_RADIOBUTTON,
      ROLE_SYSTEM_GROUPING,
      ROLE_SYSTEM_BUTTONDROPDOWN,
      ROLE_SYSTEM_BUTTONMENU,
      ROLE_SYSTEM_BUTTONDROPDOWNGRID,
      ROLE_SYSTEM_SPLITBUTTON:     Result := TYPE_BUTTON;
      ROLE_SYSTEM_COMBOBOX,
      ROLE_SYSTEM_DROPLIST:        Result := TYPE_COMBOBOX;
      ROLE_SYSTEM_TEXT:            Result := TYPE_EDIT;
      ROLE_SYSTEM_LIST:            Result := TYPE_LISTBOX;
      ROLE_SYSTEM_SCROLLBAR:       Result := TYPE_SCROLLBAR;
      ROLE_SYSTEM_STATICTEXT,
      ROLE_SYSTEM_GRAPHIC:         Result := TYPE_STATIC;
      ROLE_SYSTEM_ANIMATION:       Result := TYPE_SysAnimate32;
      ROLE_SYSTEM_CLOCK:           Result := TYPE_SysDateTimePick32;
      ROLE_SYSTEM_COLUMNHEADER,
      ROLE_SYSTEM_ROWHEADER:       Result := TYPE_SysHeader32;
      ROLE_SYSTEM_IPADDRESS:       Result := TYPE_IPAddress;
      ROLE_SYSTEM_LISTITEM,
      ROLE_SYSTEM_TABLE,
      ROLE_SYSTEM_COLUMN,
      ROLE_SYSTEM_ROW,
      ROLE_SYSTEM_CELL:            Result := TYPE_SysListView32;
      ROLE_SYSTEM_PANE:            Result := TYPE_SysPager;
      ROLE_SYSTEM_PROGRESSBAR:     Result := TYPE_msctls_progress32;
      ROLE_SYSTEM_STATUSBAR:       Result := TYPE_msctls_statusbar32;
      ROLE_SYSTEM_LINK:            Result := TYPE_SysLink;
      ROLE_SYSTEM_PAGETABLIST,
      ROLE_SYSTEM_PAGETAB:         Result := TYPE_SysTabControl32;
      ROLE_SYSTEM_TOOLBAR:         Result := TYPE_ToolbarWindow32;
      ROLE_SYSTEM_TOOLTIP,
      ROLE_SYSTEM_HELPBALLOON:     Result := TYPE_tooltips_class32;
      ROLE_SYSTEM_SLIDER,
      ROLE_SYSTEM_DIAL:            Result := TYPE_msctls_trackbar32;
      ROLE_SYSTEM_OUTLINE,
      ROLE_SYSTEM_OUTLINEITEM,
      ROLE_SYSTEM_OUTLINEBUTTON:   Result := TYPE_SysTreeView32;
      ROLE_SYSTEM_SPINBUTTON:      Result := TYPE_msctls_updown32;

      ROLE_SYSTEM_CLIENT: ;
    end;
  finally
    Acc := nil;
  end;
end;

procedure TdlgWindows.CopySelected1Click(Sender: TObject);
var
  I, A: Integer;
  ACtl: TWinControl;
  AStyleList: TList<TRemoteStyle>;
  S: string;
begin
  ACtl := ActiveControl;
  S := '';
  if ACtl is TListBox then
  begin
    AStyleList := nil;
    if ACtl = lbStyles then AStyleList := FWndStyles;
    if ACtl = lbExStyle then AStyleList := FWndExStyles;
    if AStyleList = nil then Exit;
    for I := 0 to TListBox(ACtl).Count - 1 do
      if TListBox(ACtl).Selected[I] then
        S := S + IntToHex(AStyleList[I].Value, 8) + #9 + AStyleList[I].Name + sLineBreak;
  end;
  if ACtl is TListView then
  begin
    for I := 0 to TListView(ACtl).Items.Count - 1 do
      if TListView(ACtl).Items[I].Selected then
      begin
        S := S + TListView(ACtl).Items[I].Caption;
        for A := 0 to TListView(ACtl).Items[I].SubItems.Count - 1 do
          S := S + #9 + TListView(ACtl).Items[I].SubItems[0];
        S := S + sLineBreak;
      end;
  end;
  Clipboard.AsText := S;
end;

function TdlgWindows.EmptyRemoteWndData: TRemoteWndData;
begin
  Result.WndProc := 0;
  Result.DlgProc := 0;
  Result.RealDlgProc := 0;
  Result.Instance := 0;
end;

procedure TdlgWindows.Fill(Node: TTreeNode; AHandle: HWND);
var
  ProcessID: DWORD;
  AClassName: string;
  AChild: TTreeNode;
begin
  while AHandle <> 0 do
  begin
    GetWindowThreadProcessId(AHandle, ProcessID);
    if ProcessID = MemoryMapCore.PID then
    begin
      FWndList.Add(AHandle);
      FWndData.Add(EmptyRemoteWndData);
      AClassName := GetWndClassName(AHandle);
      AChild := tvWindows.Items.AddChild(Node,
        Format('%.8X %s "%s"', [AHandle, AClassName, GetWndText(AHandle)]));
      AChild.Data := Pointer(AHandle);
      AChild.ImageIndex := IconIndexFromWindow(AHandle, DWORD(GetWindowLongPtr(AHandle, GWL_STYLE)), AClassName);
      AChild.SelectedIndex := AChild.ImageIndex;
      Fill(AChild, GetWindow(AHandle, GW_CHILD));
    end
    else
      Fill(Node, GetWindow(AHandle, GW_CHILD));
    AHandle := GetNextWindow(AHandle, GW_HWNDNEXT);
  end;
end;

procedure TdlgWindows.FillClassInfo(AHandle: HWND);
var
  Data: UInt64;
begin
  edClassName.Text := edClass.Text;
  Data := GetClassLong(AHandle, GCL_STYLE);
  edClassStyle.Text := IntToHex(Data, 8);
  cbClassStyle.Items.Clear;
  CheckAndAddComboValue(cbClassStyle, Data, CS_VREDRAW, 'CS_VREDRAW');
  CheckAndAddComboValue(cbClassStyle, Data, CS_HREDRAW, 'CS_HREDRAW');
  CheckAndAddComboValue(cbClassStyle, Data, CS_KEYCVTWINDOW, 'CS_KEYCVTWINDOW');
  CheckAndAddComboValue(cbClassStyle, Data, CS_DBLCLKS, 'CS_DBLCLKS');
  CheckAndAddComboValue(cbClassStyle, Data, CS_OWNDC, 'CS_OWNDC');
  CheckAndAddComboValue(cbClassStyle, Data, CS_CLASSDC, 'CS_CLASSDC');
  CheckAndAddComboValue(cbClassStyle, Data, CS_PARENTDC, 'CS_PARENTDC');
  CheckAndAddComboValue(cbClassStyle, Data, CS_NOKEYCVT, 'CS_NOKEYCVT');
  CheckAndAddComboValue(cbClassStyle, Data, CS_NOCLOSE, 'CS_NOCLOSE');
  CheckAndAddComboValue(cbClassStyle, Data, CS_SAVEBITS, 'CS_SAVEBITS');
  CheckAndAddComboValue(cbClassStyle, Data, CS_BYTEALIGNCLIENT, 'CS_BYTEALIGNCLIENT');
  CheckAndAddComboValue(cbClassStyle, Data, CS_BYTEALIGNWINDOW, 'CS_BYTEALIGNWINDOW');
  CheckAndAddComboValue(cbClassStyle, Data, CS_GLOBALCLASS, 'CS_GLOBALCLASS');
  CheckAndAddComboValue(cbClassStyle, Data, CS_IME, 'CS_IME');
  CheckAndAddComboValue(cbClassStyle, Data, CS_DROPSHADOW, 'CS_DROPSHADOW');
  cbClassStyle.ItemIndex := 0;
  Data := GetClassLong(AHandle, GCW_ATOM);
  edClassAtom.Text := IntToHex(Data, 4);
  Data := GetClassLong(AHandle, GCL_WNDPROC);
  edClassProc.Text := AddrVAToStr(Data, btnOpenClassProc);
  Data := GetClassLong(AHandle, GCL_HMODULE);
  edClassModule.Text := Format('%s%s', [AddrVAToStr(Data, btOpenClassInst), GetModule(Data)]);
end;

procedure TdlgWindows.FillFontInfo(AHandle: HWND);

  procedure Add(const Param, Value: string);
  begin
    memFont.Lines.Add(Param + Value);
  end;

  function CharSetToStr(CharSet: Byte): string;
  begin
    case CharSet of
      ANSI_CHARSET:        Result := 'ANSI_CHARSET';
      DEFAULT_CHARSET:     Result := 'DEFAULT_CHARSET';
      SYMBOL_CHARSET:      Result := 'SYMBOL_CHARSET';
      SHIFTJIS_CHARSET:    Result := 'SHIFTJIS_CHARSET';
      HANGEUL_CHARSET:     Result := 'HANGEUL_CHARSET';
      GB2312_CHARSET:      Result := 'GB2312_CHARSET';
      CHINESEBIG5_CHARSET: Result := 'CHINESEBIG5_CHARSET';
      OEM_CHARSET:         Result := 'OEM_CHARSET';
      JOHAB_CHARSET:       Result := 'JOHAB_CHARSET';
      HEBREW_CHARSET:      Result := 'HEBREW_CHARSET';
      ARABIC_CHARSET:      Result := 'ARABIC_CHARSET';
      GREEK_CHARSET:       Result := 'GREEK_CHARSET';
      TURKISH_CHARSET:     Result := 'TURKISH_CHARSET';
      VIETNAMESE_CHARSET:  Result := 'VIETNAMESE_CHARSET';
      THAI_CHARSET:        Result := 'THAI_CHARSET';
      EASTEUROPE_CHARSET:  Result := 'EASTEUROPE_CHARSET';
      RUSSIAN_CHARSET:     Result := 'RUSSIAN_CHARSET';
      BALTIC_CHARSET:      Result := 'BALTIC_CHARSET';
      MAC_CHARSET:         Result := 'MAC_CHARSET';
    else
      Result := Format('unknown (%d)', [CharSet]);
    end;
  end;

  procedure FillGroupID(const LogFont: TLogFont);
  begin
    if memFont.Lines.Count > 0 then
    begin
      Add('', '');
      Add('DC Font:', '');
    end;
    Add('FaceName: ', string(PChar(@LogFont.lfFaceName[0])));
    Add('Height:   ', IntToStr(LogFont.lfHeight));
    Add('Width:    ', IntToStr(LogFont.lfWidth));
    Add('Weight:   ', IntToStr(LogFont.lfWeight));
    Add('CharSet:  ', CharSetToStr(LogFont.lfCharSet));
  end;

var
  AFont, OldFnt: HFONT;
  LogFont, DefFont: TLogFont;
  DC: HDC;
begin
  memFont.Lines.BeginUpdate;
  try
    memFont.Lines.Clear;

    SystemParametersInfo(SPI_GETICONTITLELOGFONT, SizeOf(TLogFont), @DefFont, 0);
    AFont := HFONT(SendMessage(AHandle, WM_GETFONT, 0, 0));
    if AFont = 0 then
      LogFont := DefFont
    else
      GetObject(AFont, SizeOf(TLogFont), @LogFont);

    FillGroupID(LogFont);

    DC := GetWindowDC(AHandle);
    try
      OldFnt := SelectObject(DC, AFont);
      try
        if OldFnt <> 0 then
        begin
          GetObject(OldFnt, SizeOf(TLogFont), @LogFont);
          FillGroupID(LogFont);
        end;
      finally
        SelectObject(DC, OldFnt);
      end;
    finally
      ReleaseDC(AHandle, DC);
    end;

  finally
    memFont.Lines.EndUpdate;
  end;
end;

procedure TdlgWindows.FillGeneralInfo(AHandle: HWND; const Info: TWindowInfo);
var
  ProcessID: DWORD;
  RoleName: string;
  dwThreadID: TThreadID;
begin
  edHandle.Text := Format('%s (%s)', [AddrVAToStr(AHandle), IfThen(IsWindowUnicode(AHandle), 'Unicode', 'Ansi')]);
  edCaption.Text := GetWndText(AHandle);
  edClass.Text := GetWndClassName(AHandle);
  ClassifyByMSAA(AHandle, RoleName);
  edRole.Text := RoleName;
  edRect.Text := Format('(%d,%d)-(%d,%d) - %dx%d', [
    Info.rcWindow.Left, Info.rcWindow.Top,
    Info.rcWindow.Right, Info.rcWindow.Bottom,
    Info.rcWindow.Width, Info.rcWindow.Height
  ]);
  edCRect.Text := Format('(%d,%d)-(%d,%d) - %dx%d', [
    Info.rcClient.Left, Info.rcClient.Top,
    Info.rcClient.Right, Info.rcClient.Bottom,
    Info.rcClient.Width, Info.rcClient.Height
  ]);

  FWndIndex := FWndList.IndexOf(AHandle);
  if FWndIndex < 0 then
  begin
    edWndProc.Text := AddrVAToStr(0, btnOpenWndProc);
    edDlgProc.Text := AddrVAToStr(0, btnOpenDlgProc);
    edInstHandle.Text := AddrVAToStr(0, btnOpenInst);
  end
  else
  begin
    edWndProc.Text := AddrVAToStr(FWndData[FWndIndex].WndProc, btnOpenWndProc);
    if FWndData[FWndIndex].DlgProc = FWndData[FWndIndex].RealDlgProc then
      edDlgProc.Text := AddrVAToStr(FWndData[FWndIndex].DlgProc, btnOpenDlgProc)
    else
      edDlgProc.Text :=
        AddrVAToStr(FWndData[FWndIndex].DlgProc, btnOpenDlgProc) +
        ' -> ' +
        AddrVAToStr(FWndData[FWndIndex].RealDlgProc);
    edInstHandle.Text := Format('%s%s', [
      AddrVAToStr(FWndData[FWndIndex].Instance, btnOpenInst), GetModule(FWndData[FWndIndex].Instance)]);
  end;

  edCtlID.Text := AddrVAToStr(GetWindowLongPtr(AHandle, GWL_ID));

  dwThreadID := GetWindowThreadProcessId(AHandle, ProcessID);
  AttachThreadInput(GetCurrentThreadId, dwThreadID, True);
  FBuffLen := VerLanguageName(GetKeyboardLayout(dwThreadID) and $FFFF, @FBuff[0], MAX_PATH);
  AttachThreadInput(GetCurrentThreadId, dwThreadID, False);
  edLanguage.Text := BuffToString;
end;

function PropEnumProcEx(AHandle: HWND; lpszString: PChar; hData: THandle; dwUser: ULONG_PTR): BOOL; stdcall;
var
  lvProps: TListView;
  Itm: TListItem;
begin
  lvProps := dlgWindows.lvProps;
  Itm := lvProps.Items.Add;
  Itm.Caption := IntToHex(hData, 8);
  if ULONG_PTR(lpszString) <= $FFFF then
    Itm.SubItems.Add(Format('%.8X (Atom)', [Word(ULONG_PTR(lpszString))]))
  else
    Itm.SubItems.Add(string(lpszString));
  Result := True;
end;

procedure TdlgWindows.FillPropsInfo(AHandle: HWND; const Info: TWindowInfo);

  procedure AddLvRow(const ACaption: string);
  begin
    with lvScroll.Items.Add do
    begin
      Caption := ACaption;
      SubItems.Add('');
      SubItems.Add('');
    end;
  end;

  function GetInfo(Flag: Integer; var Info: TScrollInfo): Boolean;
  begin
    FillChar(Info, SizeOf(Info), 0);
    Info.cbSize := SizeOf(Info);
    Info.fMask := SIF_ALL;
    Result := GetScrollInfo(AHandle, Flag, Info);
  end;

const
  BarVisible = 'Visible';
  BarHidden = 'Hidden';
  BarDisabled = 'Disabled';
var
  RoleName: string;
  siHorz, siVert: TScrollInfo;
  Idx: Integer;
begin
  lvProps.Items.BeginUpdate;
  try
    lvProps.Items.Clear;
    EnumPropsEx(AHandle, @PropEnumProcEx, 0);
  finally
    lvProps.Items.EndUpdate;
  end;
  lvScroll.Items.BeginUpdate;
  try
    lvScroll.Items.Clear;
    AddLvRow('State');
    AddLvRow('Minimum');
    AddLvRow('Maximum');
    AddLvRow('Position');
    AddLvRow('PageSize');
    if ClassifyByMSAA(AHandle, RoleName) = TYPE_SCROLLBAR then
    begin
      Idx := 0;
      if Info.dwStyle and SBS_HORZ = SBS_HORZ then
      begin
        GetInfo(SB_HORZ, siHorz);
        FillChar(siVert, SizeOf(siVert), 0);
      end;
      if Info.dwStyle and SBS_VERT = SBS_VERT then
      begin
        FillChar(siHorz, SizeOf(siHorz), 0);
        GetInfo(SB_HORZ, siVert);
        Idx := 1;
      end;
      lvScroll.Items[0].SubItems[Idx] := BarVisible;
      if GetInfo(SB_CTL, siHorz) then
      begin
        lvScroll.Items[1].SubItems[Idx] := IntToStr(siHorz.nMin);
        lvScroll.Items[2].SubItems[Idx] := IntToStr(siHorz.nMax);
        lvScroll.Items[3].SubItems[Idx] := IntToStr(siHorz.nPos);
        lvScroll.Items[4].SubItems[Idx] := IntToStr(siHorz.nPage);
      end;
    end
    else
    begin
      lvScroll.Items[0].SubItems[0] := IfThen(
        Info.dwStyle and WS_HSCROLL = WS_HSCROLL, BarVisible, BarHidden);
      lvScroll.Items[0].SubItems[1] := IfThen(
        Info.dwStyle and WS_VSCROLL = WS_VSCROLL, BarVisible, BarHidden);
      if GetInfo(SB_HORZ, siHorz) then
      begin
        lvScroll.Items[1].SubItems[0] := IntToStr(siHorz.nMin);
        lvScroll.Items[2].SubItems[0] := IntToStr(siHorz.nMax);
        lvScroll.Items[3].SubItems[0] := IntToStr(siHorz.nPos);
        lvScroll.Items[4].SubItems[0] := IntToStr(siHorz.nPage);
      end;
      if GetInfo(SB_VERT, siVert) then
      begin
        lvScroll.Items[1].SubItems[1] := IntToStr(siVert.nMin);
        lvScroll.Items[2].SubItems[1] := IntToStr(siVert.nMax);
        lvScroll.Items[3].SubItems[1] := IntToStr(siVert.nPos);
        lvScroll.Items[4].SubItems[1] := IntToStr(siVert.nPage);
      end;
    end;

  finally
    lvScroll.Items.EndUpdate;
  end;
end;

procedure TdlgWindows.FillStylesInfo(AHandle: HWND; const Info: TWindowInfo);
var
  AClassName, AStyleName, RoleName: string;
  dwStyle: DWORD;
  StyleList: PStyleLookupEx;
  Idx: Integer;
  UnknownStyle: TRemoteStyle;
begin
  AStyleName := '';
  if not IsWindowVisible(AHandle) then
    AStyleName := 'hidden';
  if not IsWindowEnabled(AHandle) then
  begin
    if AStyleName <> '' then
      AStyleName := AStyleName + ', ';
      AStyleName := AStyleName + 'disabled'
  end;
  if AStyleName <> '' then
    AStyleName := Format(' (%s)', [AStyleName]);
  edStyle.Text := Format('%.8X%s', [Info.dwStyle, AStyleName]);

  AClassName := edClass.Text;
  if (AClassName <> '') and (LookUpClassIndex(AClassName, Info.dwStyle) < 0) then
    AClassName := ClassifyByMSAA(AHandle, RoleName);
  Idx := LookUpClassIndex(AClassName, Info.dwStyle);
  if Idx >= 0 then
    AClassName := ClassImage[Idx].szName;

  FWndStyles.Clear;
  dwStyle := EnumStyleCallback(@WindowStyles[0], Info.dwStyle, Callback);
  StyleList := FindStyleList(@StandardControls[0], AClassName);
  if Assigned(StyleList) then
    dwStyle := EnumStyleCallback(StyleList, dwStyle, Callback);
  StyleList := FindStyleList(@CustomControls[0], AClassName);
  if Assigned(StyleList) then
    dwStyle := EnumStyleCallback(StyleList, dwStyle, Callback);
  if dwStyle <> 0 then
  begin
    UnknownStyle.Name := Format('0x%.8X', [dwStyle]);
    UnknownStyle.Value := dwStyle;
    FWndStyles.Add(UnknownStyle);
  end;

  lbStyles.Items.Clear;
  for UnknownStyle in FWndStyles do
    lbStyles.Items.Add(UnknownStyle.Name);

  edExStyle.Text := Format('%.8X', [Info.dwExStyle]);

  FWndExStyles.Clear;
  dwStyle := EnumStyleCallback(@StyleExList[0], Info.dwExStyle, CallbackEx);
  StyleList := FindStyleList(@ExtendedControls[0], AClassName);
  if Assigned(StyleList) then
    dwStyle := EnumStyleCallback(StyleList, dwStyle, CallbackEx);
  if dwStyle <> 0 then
  begin
    UnknownStyle.Name := Format('0x%.8X', [dwStyle]);
    UnknownStyle.Value := dwStyle;
    FWndExStyles.Add(UnknownStyle);
  end;

  lbExStyle.Items.Clear;
  for UnknownStyle in FWndExStyles do
    lbExStyle.Items.Add(UnknownStyle.Name);
end;

procedure TdlgWindows.FillUserData(AHandle: HWND);
var
  ExtraBytesCount, Idx, Bitness: Integer;
  DataAddrVA: LONG_PTR;
  OffsetStr, DataSizeStr, ExtraName: string;
begin
  edUserData.Text := AddrVAToStr(GetWindowLongPtr(AHandle, GWL_USERDATA), btnOpenUserData);

  ExtraBytesCount := GetClassLong(AHandle, GCL_CBWNDEXTRA);
  Idx := 0;
  memWndBytes.Lines.BeginUpdate;
  try
    Bitness := IfThen(MemoryMapCore.Process64, 8, 4);
    memWndBytes.Lines.Clear;
    while Idx < ExtraBytesCount do
    begin
      DataAddrVA := GetWindowLongPtr(AHandle, Idx);
      case Idx of
        DWLP_MSGRESULT: ExtraName := 'DWLP_MSGRESULT';
        DWLP_DLGPROC: ExtraName := 'DWLP_DLGPROC';
        DWLP_USER: ExtraName := 'DWLP_USER';
      else
        ExtraName := '';
      end;
      if ExtraName <> '' then
        ExtraName := Format(' - (%s)', [ExtraName]);
      OffsetStr := IntToStr(Length(IntToStr(ExtraBytesCount)));
      DataSizeStr := IntToStr(Min(Bitness, ExtraBytesCount - Idx) shl 1);
      memWndBytes.Lines.Add(Format('+%.' + OffsetStr + 'd %.' + DataSizeStr + 'X%s', [Idx, DataAddrVA, ExtraName]));
      Inc(Idx, Bitness);
    end;
  finally
    memWndBytes.Lines.EndUpdate;
  end;
end;

procedure TdlgWindows.FillWindow(AHandle: HWND);
var
  Info: TWindowInfo;
begin
  Info := Default(TWindowInfo);
  Info.cbSize := SizeOf(TWindowInfo);
  GetWindowInfo(AHandle, Info);
  OffsetRect(Info.rcClient, -Info.rcWindow.Left, -Info.rcWindow.Top);
  FillGeneralInfo(AHandle, Info);
  FillStylesInfo(AHandle, Info);
  FillPropsInfo(AHandle, Info);
  FillClassInfo(AHandle);
  FillFontInfo(AHandle);
  FillUserData(AHandle);
end;

procedure TdlgWindows.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  Action := caFree;
  dlgWindows := nil;
end;

procedure TdlgWindows.FormCreate(Sender: TObject);

  procedure SetComboBoxReadOnly(ComboBox: TComboBox);
  var
    Info: TComboBoxInfo;
  begin
    FillChar(Info, SizeOf(Info), 0);
    Info.cbSize := SizeOf(TComboBoxInfo);
    if GetComboBoxInfo(ComboBox.Handle, Info) then
    begin
      if Info.hwndItem <> 0 then
        SendMessage(Info.hwndItem, EM_SETREADONLY, WPARAM(True), 0);
    end;
  end;

begin
  inherited;
  FWndList := TList<UInt64>.Create;
  FWndData := TList<TRemoteWndData>.Create;
  FWndStyles := TList<TRemoteStyle>.Create;
  FWndExStyles := TList<TRemoteStyle>.Create;
  SetComboBoxReadOnly(cbClassStyle);
end;

procedure TdlgWindows.FormDestroy(Sender: TObject);
begin
  inherited;
  FWndList.Free;
  FWndData.Free;
  FWndStyles.Free;
  FWndExStyles.Free;
end;

procedure TdlgWindows.FormKeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #27 then
    Close;
end;

function TdlgWindows.GetExecutableDlgProc(hProc: THandle; AddrVA: UInt64): UInt64;

  function IsExecutable(PtrVA: Pointer): Boolean;
  var
    MBI: TMemoryBasicInformation;
    dwLength: Cardinal;
  begin
    dwLength := SizeOf(TMemoryBasicInformation);
    if VirtualQueryEx(hProc, PtrVA, MBI, dwLength) <> dwLength then Exit(False);
    Result := MBI.Protect and (
      PAGE_EXECUTE or
      PAGE_EXECUTE_READ or
      PAGE_EXECUTE_READWRITE or
      PAGE_EXECUTE_WRITECOPY) <> 0;
  end;

var
  CheckCount: Integer;
  dwSize, dwRegSize, dwNewAddrVA: NativeUInt;
begin
  Result := AddrVA;
  if Result = 0 then Exit;
  dwSize := IfThen(MemoryMapCore.Process64, 8, 4);
  CheckCount := 0;
  // проверка на COM+ окно
  // если DlgProc вернул значение в неисполняемую область,
  // то скорее всего это связка: this -> vptr -> vtable[0] -> code
  // и её нужно раскрутить
  while CheckAddr(Result) and (CheckCount < 3) do
  begin
    if IsExecutable(Pointer(Result)) then
    begin
      if CheckCount in [0, 2] then
        Exit;
    end;
    Inc(CheckCount);
    if not ReadProcessData(hProc, Pointer(Result), @dwNewAddrVA,
      dwSize, dwRegSize, rcReadAllwais) then
    begin
      if not IsExecutable(Pointer(Result)) then
        Result := AddrVA;
      Exit;
    end;
    Result := dwNewAddrVA;
  end;
end;

function TdlgWindows.GetModule(ModuleInst: UInt64): string;
var
  Idx: Integer;
  RegionData: TRegionData;
begin
  if not MemoryMapCore.GetRegionIndex(Pointer(ModuleInst), Idx) then Exit('');
  RegionData := MemoryMapCore.GetRegionAtUnfilteredIndex(Idx);
  if RegionData.Details <> '' then
    Result := ' - ' + ExtractFileName(RegionData.Details)
  else
    Result := '';
end;

function TdlgWindows.GetWndClassName(AHandle: HWND): string;
begin
  FBuffLen := DWORD(GetClassName(AHandle, @FBuff[0], MAX_PATH));
  Result := BuffToString;
end;

function TdlgWindows.GetWndText(AHandle: HWND): string;
begin
  FBuffLen := DWORD(GetWindowText(AHandle, @FBuff[0], MAX_PATH));
  Result := BuffToString;
end;

function TdlgWindows.IconIndexFromWindow(AHandle: HWND; dwStyle: DWORD;
  const AClassName: string): Integer;
const
  WINDOW_IMAGE = 0;
  CHILD_IMAGE = 1;
  DIALOG_IMAGE = 2;
  POPUP_IMAGE = 3;

  function Lookup(const AWndClassName: string; out ImageIndex: Integer): Boolean;
  var
    Idx: Integer;
  begin
    Idx := LookUpClassIndex(AWndClassName, dwStyle);
    Result := Idx >= 0;
    if Result then
      ImageIndex := ClassImage[Idx].index;
  end;

var
  MSAAClassName, RoleName: string;
begin
  Result := WINDOW_IMAGE;
  if dwStyle and WS_CHILD <> 0  then
    Result := CHILD_IMAGE
  else if dwStyle and WS_POPUPWINDOW = WS_POPUPWINDOW then
    Result := DIALOG_IMAGE
  else if dwStyle and WS_POPUP <> 0 then
    Result := POPUP_IMAGE;

  if (AClassName <> '') and Lookup(AClassName, Result) then
    Exit;

  MSAAClassName := ClassifyByMSAA(AHandle, RoleName);
  if (MSAAClassName <> '') and Lookup(MSAAClassName, Result) then
    Exit;
end;

procedure TdlgWindows.InternalUpdate;
begin
  tvWindows.Items.BeginUpdate;
  try
    tvWindows.Items.Clear;
    FWndList.Clear;
    FWndData.Clear;
    Fill(nil, GetDesktopWindow);
    try
      QueryWndProcInRemoteApp;
    except
      on E: Exception do
        MessageBox(0, PChar(
          'Error determining the address of WndProc in a remote process.' + sLineBreak +
          E.ClassName + ': ' + E.Message), nil, MB_ICONWARNING);
    end;
  finally
    tvWindows.Items.EndUpdate;
  end;
end;

procedure TdlgWindows.lbStylesDrawItem(Control: TWinControl; Index: Integer;
  Rect: TRect; State: TOwnerDrawState);
var
  ACanvas: TCanvas;
  Item: TRemoteStyle;
begin
  ACanvas := TListBox(Control).Canvas;
  ACanvas.Brush.Color := clWindow;
  ACanvas.FillRect(Rect);
  if odSelected in State then
    ACanvas.Brush.Color := clHighlight
  else
    ACanvas.Brush.Color := clWindow;
  ACanvas.FillRect(Rect);
  if Control.Tag = 0 then
    Item := FWndStyles[Index]
  else
    Item := FWndExStyles[Index];
  if not (odSelected in State) then
  begin
    if Item.Value = 0 then
      ACanvas.Font.Color := cl3DDkShadow
    else
      ACanvas.Font.Color := clWindowText;
  end;
  InflateRect(Rect, MulDiv(-4, FCurrentPPI, USER_DEFAULT_SCREEN_DPI), 0);
  DrawText(ACanvas.Handle, PChar(Item.Name), Length(Item.Name), Rect, DT_VCENTER or DT_SINGLELINE);
  if not (odSelected in State) then
    ACanvas.Font.Color := cl3DDkShadow;
  DrawText(ACanvas.Handle, PChar(IntToHex(Item.Value, 8)), 8, Rect, DT_VCENTER or DT_SINGLELINE or DT_RIGHT);
end;

function TdlgWindows.LookUpClassIndex(const AClassName: string;
  dwStyle: DWORD): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to Length(ClassImage) - 1 do
    if AnsiSameText(AClassName, ClassImage[I].szName) then
    begin
      if ClassImage[I].dwAdjustStyles = 0 then
        Exit(I);
      if ClassImage[I].dwMask = 0 then
      begin
        if ClassImage[I].dwAdjustStyles and dwStyle <> 0 then
          Exit(I);
      end
      else
        if ClassImage[I].dwAdjustStyles = (dwStyle and ClassImage[I].dwMask) then
          Exit(I);
    end;
end;

const
  SDDL_REVISION_1 = 1;

function ConvertStringSecurityDescriptorToSecurityDescriptorW(
  StringSecurityDescriptor: PWideChar;
  StringSDRevision: DWORD;
  var SecurityDescriptor: PSECURITY_DESCRIPTOR;
  SecurityDescriptorSize: PULONG): BOOL; stdcall;
  external 'advapi32.dll' name 'ConvertStringSecurityDescriptorToSecurityDescriptorW';

function CreateSharedMapping(Size: DWORD; const Name: string): THandle;
var
  pSD: PSECURITY_DESCRIPTOR;
  sa: TSecurityAttributes;
  sddl: WideString;
begin
  if CheckWin32Version(6, 0) then
    sddl := 'D:(A;;GRGW;;;WD)S:(ML;;NW;;;LW)'
  else
    sddl := 'D:(A;;GRGW;;;WD)';
  pSD := nil;
  if not ConvertStringSecurityDescriptorToSecurityDescriptorW(
    PWideChar(sddl), SDDL_REVISION_1, pSD, nil) then
    RaiseLastOSError;
  try
    FillChar(sa, SizeOf(sa), 0);
    sa.nLength := SizeOf(sa);
    sa.lpSecurityDescriptor := pSD;
    sa.bInheritHandle := False;
    Result := CreateFileMapping(INVALID_HANDLE_VALUE, @sa, PAGE_READWRITE, 0, Size, PChar(Name));
    if Result = 0 then
      RaiseLastOSError;
  finally
    LocalFree(HLOCAL(pSD));
  end;
end;

procedure TdlgWindows.QueryWndProcInRemoteApp;
var
  Kernel32Path, User32Path, GetWindowLongFuncName: string;
  OpenFileMappingAddrVA, MapViewOfFileAddrVA,
  UnmapViewOfFileAddrVA, CloseHandleAddrVA, GetLastErrorAddrVA,
  GetWindowLongPtrAddrVA: UInt64;
  Module: TModule;
  Image: TRawPEImage;
  hMapFile, hSharedFuncMap: THandle;
  pMapView: Pointer;
  pCurrent: PUInt64;
  I: Integer;
  IsShellCodeExecute: Boolean;
  hProc: THandle;

  function GetExportAddr(const FuncName: string; out AddrVA: UInt64): Boolean;
  var
    Idx: Integer;
  begin
    Result := True;
    Idx := Image.ExportIndex(FuncName);
    if Idx < 0 then Exit(False);
    AddrVA := Image.ExportList[Idx].FuncAddrVA;
  end;

begin
  if FWndList.Count = 0 then Exit;
  for Module in MemoryMapCore.Modules do
  begin
    if (Module.Is64Image = MemoryMapCore.Process64) and Module.LoadAsImage and
      AnsiSameText(ExtractFileName(Module.Path), kernel32) then
      Kernel32Path := Module.Path;
    if (Module.Is64Image = MemoryMapCore.Process64) and Module.LoadAsImage and
      AnsiSameText(ExtractFileName(Module.Path), user32) then
      User32Path := Module.Path;
    if (Kernel32Path <> '') and (User32Path <> '') then
      Break;
  end;

  I := RawScannerCore.Modules.GetModule(Kernel32Path);
  if I < 0 then Exit;
  Image := RawScannerCore.Modules.Items[I];
  if not GetExportAddr('OpenFileMappingW', OpenFileMappingAddrVA) then Exit;
  if not GetExportAddr('MapViewOfFile', MapViewOfFileAddrVA) then Exit;
  if not GetExportAddr('UnmapViewOfFile', UnmapViewOfFileAddrVA) then Exit;
  if not GetExportAddr('CloseHandle', CloseHandleAddrVA) then Exit;
  if not GetExportAddr('GetLastError', GetLastErrorAddrVA) then Exit;
  I := RawScannerCore.Modules.GetModule(User32Path);
  if I < 0 then Exit;
  Image := RawScannerCore.Modules.Items[I];
  if MemoryMapCore.Process64 then
    GetWindowLongFuncName := 'GetWindowLongPtrW'
  else
    GetWindowLongFuncName := 'GetWindowLongW';
  if not GetExportAddr(GetWindowLongFuncName, GetWindowLongPtrAddrVA) then Exit;

  hMapFile := CreateSharedMapping((FWndList.Count + 1) * SizeOf(TRemoteWndData), PChar(PMM_GetRemoteWndInfo));
  try
    pMapView := MapViewOfFile(hMapFile, FILE_MAP_WRITE, 0, 0, 0);
    if pMapView <> nil then
    try
      pCurrent := PUInt64(pMapView);
      for I := 0 to FWndList.Count - 1 do
      begin
        // для оконной процедуры
        pCurrent^ := FWndList[I];
        Inc(pCurrent);
        // для диалоговой процедуры
        pCurrent^ := FWndList[I];
        Inc(pCurrent);
        // для инстанса модуля
        pCurrent^ := FWndList[I];
        Inc(pCurrent);
      end;
      pCurrent^ := 0;
    finally
      UnmapViewOfFile(pMapView);
    end;

    hProc := OpenProcess(PROCESS_CREATE_THREAD or PROCESS_VM_OPERATION or
      PROCESS_VM_READ or PROCESS_VM_WRITE, False, MemoryMapCore.PID);
    if hProc = 0 then Exit;
    try
      if MemoryMapCore.Process64 then
        IsShellCodeExecute := ExecuteX64GetWndProcList(hProc,
          OpenFileMappingAddrVA, MapViewOfFileAddrVA, UnmapViewOfFileAddrVA,
          CloseHandleAddrVA, GetLastErrorAddrVA, GetWindowLongPtrAddrVA)
      else
      begin
        hSharedFuncMap := CreateSharedMapping(
          Length(X86_ShellCode), PChar(X86_CalculatedFuncAddrVA));
        try
          pMapView := MapViewOfFile(hSharedFuncMap, FILE_MAP_WRITE, 0, 0, 0);
          if pMapView <> nil then
          try
            pCurrent := PUInt64(pMapView);
            pCurrent^ := OpenFileMappingAddrVA;
            Inc(pCurrent);
            pCurrent^ := MapViewOfFileAddrVA;
            Inc(pCurrent);
            pCurrent^ := UnmapViewOfFileAddrVA;
            Inc(pCurrent);
            pCurrent^ := CloseHandleAddrVA;
            Inc(pCurrent);
            pCurrent^ := GetLastErrorAddrVA;
            Inc(pCurrent);
            pCurrent^ := GetWindowLongPtrAddrVA;
          finally
            UnmapViewOfFile(pMapView);
          end;
          {$IFDEF WIN64}
          IsShellCodeExecute := GetWin32WndProcList(MemoryMapCore.PID);
          {$ELSE}
          IsShellCodeExecute := ExecuteX86GetWndProcList(MemoryMapCore.PID) = NO_ERROR;
          {$ENDIF}
        finally
          CloseHandle(hSharedFuncMap);
        end;
      end;

      if not IsShellCodeExecute then Exit;

      pMapView := MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
      if pMapView <> nil then
      try
        pCurrent := PUInt64(pMapView);
        for I := 0 to FWndList.Count - 1 do
        begin
          if pCurrent^ <> FWndList[I] then
            FWndData.List[I].WndProc := pCurrent^
          else
            FWndData.List[I].WndProc := 0;
          Inc(pCurrent);
          FWndData.List[I].DlgProc := pCurrent^;
          FWndData.List[I].RealDlgProc := GetExecutableDlgProc(hProc, pCurrent^);
          Inc(pCurrent);
          if pCurrent^ <> FWndList[I] then
            FWndData.List[I].Instance := pCurrent^
          else
            FWndData.List[I].Instance := 0;
          Inc(pCurrent);
        end;
      finally
        UnmapViewOfFile(pMapView);
      end;
    finally
      CloseHandle(hProc);
    end;
  finally
    CloseHandle(hMapFile);
  end;
end;

procedure TdlgWindows.SelectAll1Click(Sender: TObject);
var
  ACtl: TWinControl;
begin
  ACtl := ActiveControl;
  if Assigned(ACtl) then
  begin
    if ACtl is TListBox then
      TListBox(ACtl).SelectAll;
    if ACtl is TListView then
      TListView(ACtl).SelectAll;
  end;
end;

procedure TdlgWindows.ShowProcessWindows;
begin
  InternalUpdate;
  Show;
end;

procedure TdlgWindows.tsStylesResize(Sender: TObject);
begin
  lbStyles.Invalidate;
  lbExStyle.Invalidate;
end;

procedure TdlgWindows.tvWindowsChange(Sender: TObject; Node: TTreeNode);
begin
  if Assigned(Node) then
    FillWindow(HWND(Node.Data));
end;

end.
