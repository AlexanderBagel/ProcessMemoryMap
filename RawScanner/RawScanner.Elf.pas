////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Elf.pas
//  * Purpose   : Декларация типов используемых для чтения ELF файлов.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.1.20
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Elf;

interface

// Дока взята из man elf, она же в интеренетах этих ваших:
// https://manpages.ubuntu.com/manpages/lunar/ru/man5/elf.5.html

const

  // ElfN_Ehdr.e_ident

  EI_MAG0       = 0; // Первый байт отличительного (magic) числа. Должен быть заполнен ELFMAG0.  (0: 0x7f)
  EI_MAG1       = 1; // E
  EI_MAG2       = 2; // L
  EI_MAG3       = 3; // F
  EI_CLASS      = 4; // В пятом байте задаётся архитектура двоичного файла ELFCLASS*
  EI_DATA       = 5; // В  шестом  байте задаётся порядок кодирования данных в файле, используемый в процессоре ELFDATA*
  EI_VERSION    = 6; // В седьмом байте указывается номер версии спецификации ELF: EV_CURRENT
  EI_OSABI      = 7; // В восьмом байте указывается тип операционной системы и двоичного  интерфейса
                     // приложений  (ABI),  для которой предназначен объект ELFOSABI_*
  EI_ABIVERSION = 8; // В девятом байте указывается версия ABI, для которой предназначен объект
  EI_PAD        = 9; // Начало заполнителя
  EI_NIDENT     = 16; // Размер массива e_ident.
  ELF_MAGIC     = $464C457F; // $7F + ELF

  // EI_CLASS

  ELFCLASSNONE  = 0; // Неправильный класс.
  ELFCLASS32    = 1; // 32-битная  архитектура.
  ELFCLASS64    = 2; // 64-битная архитектура.
  // EI_DATA
  ELFDATANONE   = 0; // Неизвестный формат данных.
  ELFDATA2LSB   = 1; // Обратный порядок байт (little-endian) в дополнительном коде
  ELFDATA2MSB   = 2; // Прямой порядок байт (big-endian) в дополнительном коде.

  // EI_VERSION + ElfN_Ehdr.e_version
  // В этом поле содержится версия файла:

  EV_NONE     = 0; // Неправильный номер версии
  EV_CURRENT  = 1; // Текущая версия
  EV_NUM      = 2; // ???

  // EI_OSABI

  ELFOSABI_NONE		  = 00; // Тоже что и ELFOSABI_SYSV.
  ELFOSABI_SYSV		  = ELFOSABI_NONE; // UNIX System V ABI
  ELFOSABI_HPUX		  = 01; // Hewlett-Packard HP-UX
  ELFOSABI_NETBSD		= 02; // NetBSD
  ELFOSABI_LINUX		= 03; // Linux
  ELFOSABI_SOLARIS	= 06; // Sun Solaris
  ELFOSABI_AIX		  = 07; // AIX
  ELFOSABI_IRIX		  = 08; // IRIX
  ELFOSABI_FREEBSD	= 09; // FreeBSD
  ELFOSABI_TRU64		= 10;	// Compaq TRU64 UNIX
  ELFOSABI_MODESTO	= 11;	// Novell Modesto
  ELFOSABI_OPENBSD	= 12;	// Open BSD
  ELFOSABI_OPENVMS	= 13;	// Open VMS
  ELFOSABI_NSK		  = 14;	// Hewlett-Packard Non-Stop Kernel
  ELFOSABI_AROS		  = 15;	// Amiga Research OS
  ELFOSABI_ARM		  = 97; // ABI архитектуры ARM
  ELFOSABI_STANDALONE	= 255; //	Автономный (встраиваемый) ABI

  // ElfN_Ehdr.e_type
  // В этом поле структуры содержится тип объектного файла:

  ET_NONE       = 0;  // Неизвестный тип.
  ET_REL        = 1;  // Перемещаемый файл.
  ET_EXEC       = 2;  // Исполняемый файл.
  ET_DYN        = 3;  // Динамический объект.
  ET_CORE       = 4;  // Файл типа core.

  // ElfN_Ehdr.e_machine
  // В этом поле содержится значение требуемой для файла архитектуры. Пример:

  EM_NONE         = 00; // Неизвестная машинная архитектура
  EM_M32          = 01; // AT&T WE 32100
  EM_SPARC        = 02; // Sun Microsystems SPARC
  EM_386          = 03; // Intel 80386
  EM_68K          = 04; // Motorola 68000
  EM_88K          = 05; // Motorola 88000
  EM_486          = 06; // Intel 80486
  EM_860          = 07; // Intel i860
  EM_MIPS         = 08; // MIPS RS3000 (только с прямым порядком байт)
  EM_PARISC       = 15; // HP/PA
  EM_SPARC32PLUS  = 18; // SPARC с расширенным набором инструкций
  EM_PPC          = 20; // PowerPC
  EM_PPC64        = 21; // PowerPC, 64-битная
  EM_S390         = 22; // IBM S/390.
  EM_ARM          = 40; // Advanced RISC Machines.
  EM_SH           = 42; // Renesas SuperH.
  EM_SPARCV9      = 43; // SPARC v9, 64-битная
  EM_IA_64        = 50; // Intel Itanium.
  EM_X86_64       = 62; // AMD x86-64.
  EM_VAX          = 75; // DEC Vax

  // ElfN_Ehdr.e_phnum
  // В этом поле содержится количество элементов в таблице заголовков  программы.

  PN_XNUM = $FFFF;

  // ElfN_Phdr.p_type

  PT_NULL     = 0;
  PT_LOAD     = 1;
  PT_DYNAMIC  = 2;
  PT_INTERP   = 3;
  PT_NOTE     = 4;
  PT_SHLIB    = 5;
  PT_PHDR     = 6;
  PT_TLS		  = 7;
  PT_NUM		  = 8;
  PT_LOOS		  = $60000000;
  PT_LOPROC   = $70000000;
  PT_HIPROC   = $7FFFFFFF;

  // ElfN_Phdr.p_flags

  PF_X  = 1;
  PF_W  = 2;
  PF_R  = 4;

  // ElfN_Shdr.sh_type

  SHT_NULL      = 0;
  SHT_PROGBITS  = 1;
  SHT_SYMTAB    = 2;
  SHT_STRTAB    = 3;
  SHT_RELA      = 4;
  SHT_HASH      = 5;
  SHT_DYNAMIC   = 6;
  SHT_NOTE      = 7;
  SHT_NOBITS    = 8;
  SHT_REL       = 9;
  SHT_SHLIB     = 10;
  SHT_DYNSYM    = 11;
  SHT_NUM       = 12;
  SHT_LOPROC    = $70000000;
  SHT_HIPROC    = $7fffffff;
  SHT_LOUSER    = $80000000;
  SHT_HIUSER    = $ffffffff;

  // ElfN_Shdr.sh_flags

  SHF_WRITE     = $1;
  SHF_ALLOC     = $2;
  SHF_EXECINSTR = $4;
  SHF_MASKPROC  = $F0000000;

  SHN_UNDEF	      = 0;     // special section numbers
  SHN_LORESERVE	  = $FF00;
  SHN_LOPROC	    = $FF00; // processor speciFic range
  SHN_HIPROC	    = $FF1F;
  SHN_LOOS	      = $FF20; // OS speciFic range
  SHN_LOSUNW	    = $FF3F;
  SHN_SUNW_IGNORE = $FF3F;
  SHN_HISUNW	    = $FF3F;
  SHN_HIOS	      = $FF3F;
  SHN_ABS		      = $FFF1;
  SHN_COMMON	    = $FFF2;
  {$IFDEF __APPLE__}
  SHN_MACHO_64	  = $FFFD; // Mach-o_64 direct string access
  SHN_MACHO	      = $FFFE; // Mach-o direct string access
  {$ENDIF}
  SHN_XINDEX	    = $FFFF; // extended sect index
  SHN_HIRESERVE	  = $FFFF;

  STT_NOTYPE	    = 0;
  STT_OBJECT	    = 1;
  STT_FUNC	      = 2;
  STT_SECTION	    = 3;
  STT_FILE	      = 4;
  STT_COMMON	    = 5;
  STT_TLS		      = 6;
  STT_NUM		      = 7;
  STT_LOPROC	    = 13;	// processor specific range
  STT_HIPROC	    = 15;

type
  Elf_Byte = Byte;

  Elf32_Addr = UInt32;
  Elf32_Off = UInt32;
  Elf32_Section = UInt16;
  Elf32_Versym  = UInt16;
  Elf32_Half  = UInt16;
  Elf32_Sword  = Int32;
  Elf32_Word  = UInt32;
  Elf32_Sxword  = Int64;
  Elf32_Xword  = UInt64;

  Elf64_Addr = UInt64;
  Elf64_Off = UInt64;
  Elf64_Section = UInt16;
  Elf64_Versym  = UInt16;
  Elf64_Half  = UInt16;
  Elf64_Sword  = Int32;
  Elf64_Word  = UInt32;
  Elf64_Sxword  = Int64;
  Elf64_Xword  = UInt64;

  // Заголовок ELF

  EIdent = record
    e_magic: UInt32;
    e_class: Byte;
    e_data: Byte;
    e_version: Byte;
    e_osabi: Byte;
    e_abiversion: Byte;
    e_padding: array [10..16] of Byte;
  end;

  PElf32_Ehdr = ^Elf32_Ehdr;
  Elf32_Ehdr = record
    e_ident: EIdent;
    e_type: UInt16;
    e_machine: UInt16;
    e_version: UInt32;
    e_entry: Elf32_Addr;
    e_phoff: Elf32_Off;
    e_shoff: Elf32_Off;
    e_flags: UInt32;
    e_ehsize: UInt16;
    e_phentsize: UInt16;
    e_phnum: UInt16;
    e_shentsize: UInt16;
    e_shnum: UInt16;
    e_shstrndx: UInt16;
  end;

  PElf64_Ehdr = ^Elf64_Ehdr;
  Elf64_Ehdr = record
    e_ident: EIdent;
    e_type: UInt16;
    e_machine: UInt16;
    e_version: UInt32;
    e_entry: Elf64_Addr;
    e_phoff: Elf64_Off;
    e_shoff: Elf64_Off;
    e_flags: UInt32;
    e_ehsize: UInt16;
    e_phentsize: UInt16;
    e_phnum: UInt16;
    e_shentsize: UInt16;
    e_shnum: UInt16;
    e_shstrndx: UInt16;
  end;

  // Заголовок программы

  Elf32_Phdr = record
    p_type: UInt32;
    p_offset: Elf32_Off;
    p_vaddr: Elf32_Addr;
    p_paddr: Elf32_Addr;
    p_filesz: UInt32;
    p_memsz: UInt32;
    p_flags: UInt32;
    p_align: UInt32;
  end;

  Elf64_Phdr = record
    p_type: UInt32;
    p_flags: UInt32;
    p_offset: Elf64_Off;
    p_vaddr: Elf64_Addr;
    p_paddr: Elf64_Addr;
    p_filesz: UInt64;
    p_memsz: UInt64;
    p_align: UInt64;
  end;

  // Заголовок раздела

  Elf32_Shdr = record
    sh_name: UInt32;
    sh_type: UInt32;
    sh_flags: UInt32;
    sh_addr: Elf32_Addr;
    sh_offset: Elf32_Off;
    sh_size: UInt32;
    sh_link: UInt32;
    sh_info: UInt32;
    sh_addralign: UInt32;
    sh_entsize: UInt32;
  end;

  Elf64_Shdr = record
    sh_name: UInt32;
    sh_type: UInt32;
    sh_flags: UInt64;
    sh_addr: Elf64_Addr;
    sh_offset: Elf64_Off;
    sh_size: UInt64;
    sh_link: UInt32;
    sh_info: UInt32;
    sh_addralign: UInt64;
    sh_entsize: UInt64;
  end;

  // Зпголовок таблицы символов

  Elf32_Sym = record
    st_name: UInt32;
    st_value: Elf32_Addr;
    st_size: UInt32;
    st_info: Byte;
    st_other: Byte;
    st_shndx: UInt16;
  end;

  Elf64_Sym = record
    st_name: UInt32;
    st_info: Byte;
    st_other: Byte;
    st_shndx: UInt16;
    st_value: Elf64_Addr;
    st_size: UInt64;
  end;

  function ELF32_ST_BIND(Info: Byte): Byte;
  function ELF32_ST_TYPE(Info: Byte): Byte;

implementation

function ELF32_ST_BIND(Info: Byte): Byte;
begin
  Result := Info shr 4;
end;

function ELF32_ST_TYPE(Info: Byte): Byte;
begin
  Result := Info and $F;
end;

end.
