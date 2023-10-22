////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Disassembler.pas
//  * Purpose   : Класс для дизасемблирования указаного буфера памяти
//  *           : на основе Distorm 3.5.3
//  *           : Не используется в составе фреймворка,
//  *           : и предназначен для внешнего кода.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.15
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Disassembler;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  Masks,
  Math,
  Generics.Collections,
  distorm,
  mnemonics,
  RawScanner.Types,
  {$IFNDEF DISABLE_LOGGER}
  RawScanner.Logger,
  {$ENDIF}
  RawScanner.Utils;

type
  TAddrType = (atUnknown, atAddress, atRipOffset, atPointer4, atPointer8, atSegment);
  TInstructionType =
    (itOther, itNop, itInt, itRet, itCall, itJmp, itMov, itPush, itPop, itPrivileged, itZero, itUndefined);

  TInstruction = record
    InstType: TInstructionType;
    AddrVa,
    RipAddrVA,
    JmpAddrVa,
    SegAddrVA: ULONG_PTR64;
    Opcodes: array [0..14] of Byte;
    OpcodesLen: Byte;
    RipFirst: Boolean;
    DecodedString: string;
    class operator NotEqual(const A, B: TInstruction): Boolean;
  end;
  TInstructionArray = array of TInstruction;

  TDecodeMode = (dmFull, dmUntilRet, dmUntilUndefined);

  TAddrData = record
    AddrVA: ULONG_PTR64;
    AType: TAddrType;
  end;

  TAddrTypesData = record
    Count: Integer;
    AddrData: array [0..3] of TAddrData;
  end;

  TDisassembler = class
  private
    FAddrVA: ULONG_PTR64;
    FBufferSize: Integer;
    FCode64: Boolean;
    FProcessHandle: THandle;
    function FixAddr(AddrVA: ULONG_PTR64): ULONG_PTR64;
    procedure GetAddrTypes(Inst: TDInst; out Data: TAddrTypesData);
    function GetInstructionType(Value: TDInst): TInstructionType;
    function GET_WString(w: _WString): string;
    function HexUpperCase(const Value: string): string;
    function InitCodeInfo(Code: PByte): TCodeInfo;
  public
    constructor Create(AProcessHandle: THandle; AAddrVA: ULONG_PTR64;
      ABufferSize: Integer;  ACode64: Boolean);
    function DecodeBuff(pBuff: PByte; DecodeMode: TDecodeMode;
      CollapceZero: Boolean): TInstructionArray;
  end;

implementation

procedure Warn(const Description: string); overload;
begin
  {$IFNDEF DISABLE_LOGGER}
  RawScannerLogger.Warn(llDisasm, Description);
  {$ENDIF}
end;

{ TInstruction }

class operator TInstruction.NotEqual(const A, B: TInstruction): Boolean;
begin
  Result :=
    (A.AddrVa <> B.AddrVa) or
    (A.OpcodesLen <> B.OpcodesLen) or
    (A.DecodedString <> B.DecodedString);
end;

{ TDisassembler }

constructor TDisassembler.Create(AProcessHandle: THandle; AAddrVA: ULONG_PTR64;
  ABufferSize: Integer; ACode64: Boolean);
begin
  FAddrVA := AAddrVA;
  FBufferSize := ABufferSize;
  FCode64 := ACode64;
  FProcessHandle := AProcessHandle;
end;

function TDisassembler.DecodeBuff(pBuff: PByte;
  DecodeMode: TDecodeMode; CollapceZero: Boolean): TInstructionArray;
var
  DecodeResult: TDecodeResult;
  InstList: array of TDInst;
  ci: TCodeInfo;
  I, A, Count, ZeroCount: Integer;
  Instruction: TDecodedInst;
  HintStr: string;
  OffsetAddr, AddrVA: ULONG_PTR64;
  NeedStop, ZeroDetected: Boolean;
  ATypes: TAddrTypesData;
begin
  SetLength(InstList, FBufferSize);

  ci := InitCodeInfo(pBuff);

  if CollapceZero then
  begin
    Count := 0;
    while Count < FBufferSize do
    begin
      DecodeResult := distorm_decompose(
        @ci, @InstList[Count], 1, @A);
      case DecodeResult of
        DECRES_SUCCESS: Break;
        DECRES_MEMORYERR: ;
      else
        Warn('Buffer disassembly error: ' + IntToStr(Byte(DecodeResult)));
        Exit;
      end;
      Inc(ci.codeOffset, InstList[Count].size);
      ci.code := ci.code + InstList[Count].size;
      Dec(ci.codeLen, InstList[Count].size);

      Inc(Count);
      if Count = FBufferSize then
        Break;

      if ci.codeLen <= 0 then
        Break;

      // детектирование нулей для выравнивания
      ZeroCount := 0;
      while ci.codeLen > 0 do
      begin
        if ci.code^ = 0 then
        begin
          Inc(ci.code);
          Dec(ci.codeLen);
          Inc(ZeroCount);
          // страховка, чтобы не упало если будем дизасмить
          // неисполняемую  страницу с нулями
          if ZeroCount = 32 then
            Break;
        end
        else
          Break;
      end;
      if ZeroCount > 0 then
      begin
        InstList[Count].addr := ci.nextOffset;
        InstList[Count].size := ZeroCount;
        Inc(ci.codeOffset, ZeroCount);
        ci.nextOffset := 0;
        Inc(Count);
      end;
    end;
    ci := InitCodeInfo(pBuff);
  end
  else
  begin
    DecodeResult := distorm_decompose(
      @ci, @InstList[0], FBufferSize, @Count);
    if DecodeResult <> DECRES_SUCCESS then
    begin
      Warn('Buffer disassembly error: ' + IntToStr(Byte(DecodeResult)));
      Exit;
    end;
  end;

  SetLength(Result, Count);
  for I := 0 to Count - 1 do
  begin
    Result[I].AddrVa := InstList[I].addr;
    Result[I].OpcodesLen := InstList[I].size;
    Result[I].InstType := GetInstructionType(InstList[I]);

    ZeroDetected := False;
    if CollapceZero then
    begin
      if Result[I].InstType = itZero then
      begin
        ZeroDetected := True;
        if DecodeMode = dmUntilUndefined then
        begin
          SetLength(Result, I);
          Break;
        end;
      end;
    end;

    if not ZeroDetected then
    begin
      distorm_format(@ci, @InstList[I], @Instruction);
      Result[I].DecodedString :=
        HexUpperCase(GET_WString(Instruction.mnemonic)) + Space +
        HexUpperCase(GET_WString(Instruction.operands)) + HintStr;
    end;

    if (DecodeMode = dmUntilUndefined) and not CollapceZero and
      (_InstructionType(InstList[I].opcode) = I_ADD) then
    begin
      case Result[I].OpcodesLen of
        1: NeedStop := PByte(pBuff)^ = 0;
        2: NeedStop := PWord(pBuff)^ = 0;
        4: NeedStop := PDWORD(pBuff)^ = 0;
      else
        NeedStop := False;
      end;
      if NeedStop then
      begin
        SetLength(Result, I);
        Break;
      end;
    end;

    Move(pBuff^, Result[I].Opcodes[0], Min(Result[I].OpcodesLen, 14));
    Inc(pBuff, Result[I].OpcodesLen);

    HintStr := EmptyStr;
    case Result[I].InstType of
      itRet, itInt:
      begin
        if DecodeMode <> dmFull then
        begin
          SetLength(Result, I + 1);
          Exit;
        end;
      end;
      itCall, itJmp, itMov, itPush, itPop, itOther:
      begin
        GetAddrTypes(InstList[I], ATypes);
        for A := 0 to ATypes.Count - 1 do
        begin
          case ATypes.AddrData[A].AType of
            atAddress: Result[I].JmpAddrVa := ATypes.AddrData[A].AddrVA;
            atSegment: Result[I].SegAddrVA := ATypes.AddrData[A].AddrVA;
            atRipOffset:
            begin
              {$IFDEF DEBUG} {$OVERFLOWCHECKS OFF} {$ENDIF}
              OffsetAddr := InstList[I].addr + InstList[I].size + ATypes.AddrData[A].AddrVA;
              {$IFDEF DEBUG} {$OVERFLOWCHECKS ON} {$ENDIF}
              Result[I].RipAddrVA := OffsetAddr;
              // какой по очереди встретился RIP, чтобы вывести в правильном порядке
              Result[I].RipFirst := Result[I].JmpAddrVa = 0;
            end;
            atPointer4:
            begin
              AddrVA := 0;
              if ReadRemoteMemory(FProcessHandle, AddrVA, @AddrVA, 4) then
                Result[I].JmpAddrVa := ATypes.AddrData[A].AddrVA;
            end;
            atPointer8:
              if ReadRemoteMemory(FProcessHandle, AddrVA, @AddrVA, 8) then
                Result[I].JmpAddrVa := ATypes.AddrData[A].AddrVA;
          end;
        end;
      end;
      itUndefined, itPrivileged:
        if DecodeMode = dmUntilUndefined then
        begin
          SetLength(Result, I);
          Exit;
        end;
    end;

  end;
end;

function TDisassembler.FixAddr(AddrVA: ULONG_PTR64): ULONG_PTR64;
begin
  if FCode64 then
    Result := AddrVA
  else
    Result := DWORD(AddrVA);
end;

procedure TDisassembler.GetAddrTypes(Inst: TDInst; out Data: TAddrTypesData);
var
  I: Integer;
begin
  I := 0;
  ZeroMemory(@Data, SizeOf(Data));
  while I < Inst.opsNo do
  begin
    case _OperandType(Inst.ops[I]._type) of
      O_IMM:
      begin
        if (Inst.flags and FLAG_IMM_SIGNED <> 0) and
          (Inst.ops[I].size = 8) and (Inst.imm.sbyte < 0) then
          Data.AddrData[Data.Count].AddrVA := FixAddr(-Inst.imm.sbyte)
        else
          if Inst.ops[I].size = 32 then
            Data.AddrData[Data.Count].AddrVA := FixAddr(Inst.imm.udword)
          else
            Data.AddrData[Data.Count].AddrVA := FixAddr(Inst.imm.uqword);
        Data.AddrData[Data.Count].AType := atAddress;
        Inc(Data.Count);
      end;
      O_PC:
      begin
        {$IFDEF DEBUG} {$OVERFLOWCHECKS OFF} {$ENDIF}
        Data.AddrData[Data.Count].AddrVA := FixAddr(ULONG_PTR64(Inst.addr +
          Inst.size + ULONG_PTR64(Inst.imm.sqword)));
        {$IFDEF DEBUG} {$OVERFLOWCHECKS ON} {$ENDIF}
        Data.AddrData[Data.Count].AType := atAddress;
        Inc(Data.Count);
      end;
      O_DISP, O_SMEM:
      begin
        Data.AddrData[Data.Count].AddrVA := FixAddr(Inst.disp);
        if Inst.flags and FLAG_RIP_RELATIVE <> 0 then
          Data.AddrData[Data.Count].AType := atRipOffset
        else
          // детект обрашения к TEB
          if not SEGMENT_IS_DEFAULT_OR_NONE(Inst.segment) then
          begin
            case _RegisterType(SEGMENT_GET(Inst.segment)) of
              R_FS: if not FCode64 then Data.AddrData[Data.Count].AType := atSegment;
              R_GS: if FCode64 then Data.AddrData[Data.Count].AType := atSegment;
            end;
          end
          else
            case Inst.dispSize of
              64: Data.AddrData[Data.Count].AType := atPointer8;
              32: Data.AddrData[Data.Count].AType := atPointer4;
            end;
        if Data.AddrData[Data.Count].AType <> atUnknown then
          Inc(Data.Count);
      end;
    end;
    Inc(I);
  end;
end;

function TDisassembler.GetInstructionType(Value: TDInst): TInstructionType;
begin
  Result := itOther;
  if Value.flags and FLAG_PRIVILEGED_INSTRUCTION <> 0 then
    Result := itPrivileged
  else
    case _InstructionType(Value.opcode) of
      I_NOP, I_FNOP: Result := itNop;
      I_INT, I_INT1, I_INT3, I_INTO:
        Result := itInt;
      I_RET, I_RETF, I_IRET: Result := itRet;
      I_CALL, I_CALL_FAR: Result := itCall;
      I_JA, I_JAE, I_JB, I_JBE, I_JCXZ, I_JECXZ, I_JG, I_JGE,
      I_JL, I_JLE, I_JMP, I_JMP_FAR, I_JNO, I_JNP, I_JNS, I_JNZ,
      I_JO, I_JP, I_JRCXZ, I_JS, I_JZ: Result := itJmp;
      I_MOV: Result := itMov;
      I_PUSH: Result := itPush;
      I_POP: Result := itPop;
      I_UNDEFINED:
        if (Value.size > 0) and (Value.undefinedFlagsMask = 0) then
          Result := itZero
        else
          Result := itUndefined;
    end;
end;

function TDisassembler.GET_WString(w: _WString): string;
begin
  Result := string(PAnsiChar(@w.p[0]));
end;

function TDisassembler.HexUpperCase(const Value: string): string;
begin
  Result := UpperCase(Value);
  Result := StringReplace(Result, '0X', '0x', [rfReplaceAll]);
end;

function TDisassembler.InitCodeInfo(Code: PByte): TCodeInfo;
begin
  ZeroMemory(@Result, SizeOf(TCodeInfo));
  Result.codeOffset := FAddrVA;
  if FCode64 then
    Result.dt := Decode64Bits
  else
  begin
    Result.dt := Decode32Bits;
    Result.features := DF_MAXIMUM_ADDR32;
  end;
  Result.code := Code;
  Result.codeLen := FBufferSize;
end;

end.
