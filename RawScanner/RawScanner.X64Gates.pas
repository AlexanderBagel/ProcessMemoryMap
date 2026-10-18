////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : Process Memory Map
//  * Unit Name : RawScanner.X64Gates.pas
//  * Purpose   : 64-bit stdcall API call thunk generator
//  * Author    : Alexander (Rouse_) Bagel
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.30
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : https://github.com/AlexanderBagel/ProcessMemoryMap/releases
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//  *
//  * SPDX-License-Identifier: MPL-2.0
//  * This Source Code Form is subject to the terms of the Mozilla Public
//  * License, v. 2.0. If a copy of the MPL was not distributed with this
//  * file, You can obtain one at http://mozilla.org/MPL/2.0/.
//  *
//  ****************************************************************************
//  *
//  * Support the Project:
//  *
//  * If you found this project useful, you can support its development
//  * on the author's main-project page:
//  *
//  * https://boosty.to/processmemorymap
//  *
//  ****************************************************************************
//

unit RawScanner.X64Gates;

interface

  {$I rawscanner.inc}

uses
  Windows,
  SysUtils,
  Math,
  RawScanner.Types;

type
  TParamSize = (ps4Byte = 2, ps8Byte = 3{, psXMM - XMM пока не поддерживается});

  /// <summary>
  ///  MakeX64Gate - generates a call thunk for a 64-bit API function.
  /// </summary>
  /// <param name="FuncAddr">address of the 64-bit stdcall function in the current process</param>
  /// <param name="Params">array of parameter sizes on the 32-bit stack</param>
  /// <remarks>
  ///  [ru] MakeX64Gate - генерирует шлюз вызова 64 битной API функции.
  ///  FuncAddr - адрес 64 битной stdcall функции в текущем процессе
  ///  Params - массив размеров параметров на 32 битном стеке
  /// </remarks>
  function MakeX64Gate(FuncAddr: ULONG_PTR64; Params: array of TParamSize): Pointer;
  procedure ReleaseX64Gate(Value: Pointer);

implementation

function MakeX64Gate(FuncAddr: ULONG_PTR64; Params: array of TParamSize): Pointer;
{$IFDEF WIN64}
begin
  Result := Pointer(FuncAddr);
{$ELSE}

var
  InsPoint: PByte;

  procedure Push(Instructions: array of Byte);
  begin
    Move(Instructions[0], InsPoint^, Length(Instructions));
    Inc(InsPoint, Length(Instructions));
  end;

  procedure PushDWord(Value: DWORD);
  begin
    Move(Value, InsPoint^, 4);
    Inc(InsPoint, 4);
  end;

  procedure PushDWord64(Value: DWORD64);
  begin
    Move(Value, InsPoint^, 8);
    Inc(InsPoint, 8);
  end;

var
  I, ParamsCount, ShadowSpace, ParamSize, ParamsLeft: Integer;
  x32StackPtr, x64StackPtr: Byte;
begin
  Result := VirtualAlloc(nil, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  InsPoint := Result;

  if Result = nil then
    RaiseLastOSError;

  // calculation of the count and total size of the passed parameters
  // [ru] рассчет количества и общего размера переданых параметров

  ParamsCount := Length(Params);

  // auto-generation uses short instructions that operate on a byte
  // so we need to check that ParamsCount * 8 does not exceed its limit

  // [ru] в автогенерации используются короткие инструкции работающие с байтом
  // поэтому нужен контроль чтобы ParamsCount * 8 не вылез за его пределы

  if ParamsCount > 31 then
    raise Exception.Create('Too many params');

  ParamSize := 0;
  for I := 0 to ParamsCount - 1 do
    Inc(ParamSize, 1 shl Byte(Params[I]));

  // The shadow space requires a minimum of 32 bytes for the 4 default registers
  // [ru] Теневое пространство требует минимум 32 байта под 4 дефолтных регистра

  ShadowSpace := Max(32, ParamsCount * 8);

  // prologue
  // [ru] пролог

  Push([$55]);                              // push ebp
  Push([$8B, $EC]);                         // mov ebp, esp

  // stack alignment
  // [ru] выравнивание стека

  Push([$89, $E0]);                         // mov eax, esp
  Push([$83, $E0, $07]);                    // and eax, $07
  Push([$83, $F8, $00]);                    // cmp eax, $00
  Push([$74, $02]);                         // jz +2
  Push([$29, $C4]);                         // sub esp, eax

  // switching to 64-bit mode
  // [ru] переключение в 64-битный режим

  Push([$EA]);                              // jmp far 0x33:+SizeOf(jmp)
  PushDWord(DWORD(InsPoint) + 6);
  Push([$33, 0]);

  // building the 64-bit frame
  // [ru] формирование 64-битного фрейма

  Push([$55]);                              // push rbp
  Push([$48, $83, $EC, ShadowSpace]);       // sub rsp, 64 ShadowSpace
  Push([$48, $89, $E5]);                    // mov rbp, rsp

  // transferring parameters for the 64-bit call
  // [ru] перенос параметров для 64-битного вызова

  if ParamsCount > 0 then
  begin

    // setting the pointer to the last parameter on the 32-bit stack
    // [ru] выставление указателя на последний параметр с 32 битного стека

    Push([$48, $8D, $84, $04]);             // lea rax, [rsp + rax + ...]
    PushDWord(
      ShadowSpace +
      8 +                                   // SizeOf(push rbp)
      ParamSize +
      4 +                                   // SizeOf(push ebp)
      4                                     // SizeOf(32-bit ret addr)
      );
    ParamsLeft := ParamsCount - 1;
    x32StackPtr := 0;
    x64StackPtr := ShadowSpace;
    while ParamsLeft >= 0 do
    begin

      // shifting the pointer to the start of the next parameter on the 32-bit stack
      // [ru] сдвиг указателя на начало следующего параметра на 32 битном стеке

      Inc(x32StackPtr, 1 shl Byte(Params[ParamsLeft]));
      case ParamsLeft of
        0: // mov rcx(ecx), [rax - x32StackPtr]]
        begin
          if Params[ParamsLeft] = ps8Byte then
          begin

            // REX Pfx here and below. Used to modify ecx->rcx
            // [ru] REX Pfx здесь и далее. Используется для модификации ecx->rcx

            Push([$48]);
          end;
          Push([$8B, $48, Byte(-x32StackPtr)]);
        end;
        1: // mov rdx(edx), [rax - x32StackPtr]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$48]);
          Push([$8B, $50, Byte(-x32StackPtr)]);
        end;
        2: // mov r8(r8d), [rax - x32StackPtr]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$4C, $8B, $40, Byte(-x32StackPtr)])
          else
            Push([$44, $8B, $40, Byte(-x32StackPtr)]);
        end;
        3: // mov r9(r9d), [rax - x32StackPtr]
        begin
          if Params[ParamsLeft] = ps8Byte then
            Push([$4C, $8B, $48, Byte(-x32StackPtr)])
          else
            Push([$44, $8B, $48, Byte(-x32StackPtr)]);
        end;
      else
        // mov rcx(ecx), [rax - x32StackPtr]
        if Params[ParamsLeft] = ps8Byte then
          Push([$48]);
        Push([$8B, $48, Byte(-x32StackPtr)]);
        Dec(x64StackPtr, 8);
        // mov [rsp + "offset to the 64-bit parameter on the stack"], rcx
        Push([$48, $89, $4C, $24, x64StackPtr]);
      end;
      Dec(ParamsLeft);
    end;
  end;

  // function call
  // [ru] вызов функции

  Push([$48, $B8]);                         // mov rax, FuncAddr
  PushDWord64(FuncAddr);
  Push([$FF, $D0]);                         // call rax

  // moving the result from RAX into the EAX + EDX pair
  // [ru] перемещение результата из RAX в пару EAX + EDX

  Push([$48, $89, $C2]);                    // mov rdx, rax
  Push([$48, $C1, $EA, $20]);               // shr rdx, $20

  // closing the 64-bit frame
  // [ru] закрытие 64-битного фрейма

  Push([$48, $83, $C4, ShadowSpace]);       // add rsp, 64 ShadowSpace
  Push([$5D]);                              // pop rbp

  // switching to 32-bit mode
  // [ru] переключение в 32-битный режим

  Push([$FF, $2D, 0, 0, 0, 0]);             // jmp far word ptr ds:[0]
  PushDWord(DWORD(InsPoint) + 6);           // jmp addr
  Push([$23, 0]);                           // CS param

  // restoring the 32-bit stack
  // [ru] восстановление 32-битного стека

  Push([$89, $EC]);                         // mov esp, ebp

  // epilogue
  // [ru] эпилог

  Push([$5D]);                              // pop ebp
  Push([$C2, ParamSize, 0]);                // ret + 32 params size
{$ENDIF}
end;

procedure ReleaseX64Gate(Value: Pointer);
begin
  {$IFDEF WIN32}
  if Value <> nil then
    VirtualFree(Value, 0, MEM_RELEASE);
  {$ENDIF}
end;

end.
