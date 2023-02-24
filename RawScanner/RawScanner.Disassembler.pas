////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Disassembler.pas
//  * Purpose   : Класс для дизасемблирования указаного буфера памяти
//  *           : на основе Distorm 3.5.3
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2023.
//  * Version   : 1.0.10
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Disassembler;

interface

uses
  Windows,
  SysUtils,
  Masks,
  Generics.Collections,
  distorm,
  mnemonics,
  RawScanner.Types,
  RawScanner.Utils,
  RawScanner.Logger;

type
  TAddrType = (atUnknown, atAddress, atRipOffset, atPointer4, atPointer8, atSegment);
  TInstructionType =
    (itOther, itNop, itInt, itRet, itCall, itJmp, itMov, itPush, itPrivileged, itUndefined);

  TInstruction = record
    InstType: TInstructionType;
    AddrType: TAddrType;
    AddrVa,
    RipAddrVA,
    JmpAddrVa: ULONG_PTR64;
    Opcodes: array [0..14] of Byte;
    OpcodesLen: Byte;
    DecodedString: string;
    class operator NotEqual(const A, B: TInstruction): Boolean;
  end;
  TInstructionArray = array of TInstruction;

  TDecodeMode = (dmFull, dmUntilRet, dmUntilUndefined);

  TDisassembler = class
  private
    FAddrVA: ULONG_PTR64;
    FBufferSize: Integer;
    FCode64: Boolean;
    FProcessHandle: THandle;
    function FixAddr(AddrVA: ULONG_PTR64): ULONG_PTR64;
    function GetAddrType(Inst: TDInst; out Address: ULONG_PTR64): TAddrType;
    function GetInstructionType(Value: TDInst): TInstructionType;
    function GET_WString(w: _WString): string;
    function HexUpperCase(const Value: string): string;
    function InitCodeInfo(Code: PByte): TCodeInfo;
  public
    constructor Create(AProcessHandle: THandle; AAddrVA: ULONG_PTR64;
      ABufferSize: Integer;  ACode64: Boolean);
    function DecodeBuff(pBuff: PByte; DecodeMode: TDecodeMode): TInstructionArray;
  end;

implementation

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
  DecodeMode: TDecodeMode): TInstructionArray;
var
  DecodeResult: TDecodeResult;
  InstList: array of TDInst;
  ci: TCodeInfo;
  I, Count: Integer;
  Instruction: TDecodedInst;
  HintStr: string;
  OffsetAddr, AddrVA: ULONG_PTR64;
  NeedStop: Boolean;
begin
  SetLength(InstList, FBufferSize);

  ci := InitCodeInfo(pBuff);
  DecodeResult := distorm_decompose(
    @ci, @InstList[0], FBufferSize, @Count);
  if DecodeResult <> DECRES_SUCCESS then
  begin
    RawScannerLogger.Warn(llDisasm, 'Buffer disassembly error: ' +
      IntToStr(Byte(DecodeResult)));
    Exit;
  end;

  SetLength(Result, Count);
  for I := 0 to Count - 1 do
  begin
    Result[I].AddrVa := InstList[I].addr;
    Result[I].OpcodesLen := InstList[I].size;

    distorm_format(@ci, @InstList[I], @Instruction);
    Result[I].DecodedString :=
      HexUpperCase(GET_WString(Instruction.mnemonic)) + Space +
      HexUpperCase(GET_WString(Instruction.operands)) + HintStr;

    if (DecodeMode = dmUntilUndefined) and
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

    Move(pBuff^, Result[I].Opcodes[0], Result[I].OpcodesLen);
    Inc(pBuff, Result[I].OpcodesLen);

    HintStr := EmptyStr;
    Result[I].InstType := GetInstructionType(InstList[I]);
    case Result[I].InstType of
      itRet, itInt:
      begin
        if DecodeMode <> dmFull then
        begin
          SetLength(Result, I + 1);
          Exit;
        end;
      end;
      itCall, itJmp, itMov, itPush:
      begin
        Result[I].AddrType := GetAddrType(InstList[I], AddrVA);
        case Result[I].AddrType of
          atAddress, atSegment: Result[I].JmpAddrVa := AddrVA;
          atRipOffset:
          begin
            {$IFDEF DEBUG} {$OVERFLOWCHECKS OFF} {$ENDIF}
            OffsetAddr := InstList[I].addr + InstList[I].size + AddrVA;
            {$IFDEF DEBUG} {$OVERFLOWCHECKS ON} {$ENDIF}
            Result[I].RipAddrVA := OffsetAddr;
            if ReadRemoteMemory(FProcessHandle, OffsetAddr, @AddrVA, 8) then
              Result[I].JmpAddrVa := AddrVA;
          end;
          atPointer4:
            if ReadRemoteMemory(FProcessHandle, AddrVA, @AddrVA, 4) then
              Result[I].JmpAddrVa := AddrVA;
          atPointer8:
            if ReadRemoteMemory(FProcessHandle, AddrVA, @AddrVA, 8) then
              Result[I].JmpAddrVa := AddrVA;
        end;
        if (Result[I].AddrType <> atSegment) and (Result[I].JmpAddrVa = 0) then
          Result[I].AddrType := atUnknown;
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

function TDisassembler.GetAddrType(Inst: TDInst;
  out Address: ULONG_PTR64): TAddrType;
var
  I: Integer;
begin
  Result := atUnknown;
  Address := 0;
  I := Inst.opsNo - 1;
  while I >= 0  do
  begin
    case _OperandType(Inst.ops[I]._type) of
      O_IMM:
      begin
        if (Inst.flags and FLAG_IMM_SIGNED <> 0) and
          (Inst.ops[I].size = 8) and (Inst.imm.sbyte < 0) then
          Address := FixAddr(-Inst.imm.sbyte)
        else
          if Inst.ops[I].size = 32 then
            Address := FixAddr(Inst.imm.udword)
          else
            Address := FixAddr(Inst.imm.uqword);
        Exit(atAddress);
      end;
      O_PC:
      begin
        {$IFDEF DEBUG} {$OVERFLOWCHECKS OFF} {$ENDIF}
        Address := FixAddr(ULONG_PTR64(Inst.addr +
          Inst.size + ULONG_PTR64(Inst.imm.sqword)));
        {$IFDEF DEBUG} {$OVERFLOWCHECKS ON} {$ENDIF}
        Exit(atAddress);
      end;
      O_DISP, O_SMEM:
      begin
        Address := FixAddr(Inst.disp);
        if Inst.flags and FLAG_RIP_RELATIVE <> 0 then
          Exit(atRipOffset)
        else
          // детект обрашения к TEB
          if not SEGMENT_IS_DEFAULT_OR_NONE(Inst.segment) then
            case _RegisterType(SEGMENT_GET(Inst.segment)) of
              R_FS: if not FCode64 then Exit(atSegment);
              R_GS: if FCode64 then Exit(atSegment);
            end;

          case Inst.dispSize of
            64: Exit(atPointer8);
            32: Exit(atPointer4);
          end;
      end;
    end;
    Dec(I);
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
      I_UNDEFINED: Result := itUndefined;
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
