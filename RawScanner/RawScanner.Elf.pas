////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.Elf.pas
//  * Purpose   : Декларация типов используемых для чтения ELF файлов.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2026.
//  * Version   : 1.2.26
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

unit RawScanner.Elf;

interface

  {$I rawscanner.inc}

{$Q-} // Отключаем INTEGER OVERFLOW
{$R-} // Отключаем RANGE CHECK ERROR

// Дока взята из man elf, она же в интеренетах этих ваших:
// https://manpages.ubuntu.com/manpages/lunar/ru/man5/elf.5.html

// Дополнено из https://llvm.org/docs/doxygen/BinaryFormat_2ELF_8h_source.html

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
  ELFOSABI_ARM_AEABI= 64; // ARM EABI
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
  // В этом поле содержится значение требуемой для файла архитектуры.
  // https://docs.rs/elf/latest/src/elf/abi.rs.html

  EM_NONE         = 000;
  EM_M32          = 001; // AT&T WE 32100
  EM_SPARC        = 002; // Sun Microsystems SPARC
  EM_386          = 003; // Intel 80386
  EM_68K          = 004; // Motorola 68000
  EM_88K          = 005; // Motorola 88000
  EM_486          = 006; // Intel 80486
  EM_860          = 007; // Intel i860
  EM_MIPS         = 008; // MIPS RS3000 Big-endian
  EM_S370         = 009; // IBM System/370
  EM_MIPS_RS3_LE  = 010; // MIPS RS3000 Little-endian
  // 11-14 Reserved for future use
  EM_PARISC       = 015; // Hewlett-Packard PA-RISC
  // 16 Reserved for future use
  EM_VPP500       = 017; // Fujitsu VPP500
  EM_SPARC32PLUS  = 018; // Enhanced instruction set SPARC
  EM_960          = 019; // Intel 80960
  EM_PPC          = 020; // PowerPC
  EM_PPC64        = 021; // PowerPC64
  EM_S390         = 022; // IBM System/390.
	EM_SPU          = 023; // IBM SPU/SPC
  // 24-35 Reserved for future use
	EM_V800         = 036; // NEC V800
	EM_FR20         = 037; // Fujitsu FR20
	EM_RH32         = 038; // TRW RH-32
	EM_RCE          = 039; // Motorola RCE
  EM_ARM          = 040; // ARM 32-bit architecture (AARCH32)
	EM_ALPHA        = 041; // DEC Alpha
  EM_SH           = 042; // Renesas SuperH.
  EM_SPARCV9      = 043; // SPARC v9
	EM_TRICORE      = 044; // Siemens TriCore
	EM_ARC          = 045; // Argonaut RISC Core
	EM_H8_300       = 046; // Hitachi H8/300
	EM_H8_300H      = 047; // Hitachi H8/300H
	EM_H8S          = 048; // Hitachi H8S
	EM_H8_500       = 049; // Hitachi H8/500
  EM_IA_64        = 050; // Intel IA-64 processor architecture
	EM_MIPS_X       = 051; // Stanford MIPS-X
	EM_COLDFIRE     = 052; // Motorola ColdFire
	EM_68HC12       = 053; // Motorola M68HC12
	EM_MMA          = 054; // Fujitsu MMA Multimedia Accelerator
	EM_PCP          = 055; // Siemens PCP
	EM_NCPU         = 056; // Sony nCPU embedded RISC processor
	EM_NDR1         = 057; // Denso NDR1 microprocessor
	EM_STARCORE     = 058; // Motorola Star*Core processor
	EM_ME16         = 059; // Toyota ME16 processor
	EM_ST100        = 060; // STMicroelectronics ST100 processor
	EM_TINYJ        = 061; // Advanced Logic Corp. TinyJ embedded processor family
  EM_X86_64       = 062; // AMD x86-64 architecture.
	EM_PDSP         = 063; // Sony DSP Processor
	EM_PDP10        = 064; // Digital Equipment Corp. PDP-10
	EM_PDP11        = 065; // Digital Equipment Corp. PDP-11
	EM_FX66         = 066; // Siemens FX66 microcontroller
	EM_ST9PLUS      = 067; // STMicroelectronics ST9+ 8/16 bit microcontroller
	EM_ST7          = 068; // STMicroelectronics ST7 8-bit microcontroller
	EM_68HC16       = 069; // Motorola MC68HC16 Microcontroller
	EM_68HC11       = 070; // Motorola MC68HC11 Microcontroller
	EM_68HC08       = 071; // Motorola MC68HC08 Microcontroller
	EM_68HC05       = 072; // Motorola MC68HC05 Microcontroller
	EM_SVX          = 073; // Silicon Graphics SVx
	EM_ST19         = 074; // STMicroelectronics ST19 8-bit microcontroller
	EM_VAX          = 075; // Digital VAX
	EM_CRIS         = 076; // Axis Communications 32-bit embedded processor
	EM_JAVELIN      = 077; // Infineon Technologies 32-bit embedded processor
	EM_FIREPATH     = 078; // Element 14 64-bit DSP Processor
	EM_ZSP          = 079; // LSI Logic 16-bit DSP Processor
	EM_MMIX         = 080; // Donald Knuth's educational 64-bit processor
	EM_HUANY        = 081; // Harvard University machine-independent object files
	EM_PRISM        = 082; // SiTera Prism
	EM_AVR          = 083; // Atmel AVR 8-bit microcontroller
	EM_FR30         = 084; // Fujitsu FR30
	EM_D10V         = 085; // Mitsubishi D10V
	EM_D30V         = 086; // Mitsubishi D30V
	EM_V850         = 087; // NEC v850
	EM_M32R         = 088; // Mitsubishi M32R
	EM_MN10300      = 089; // Matsushita MN10300
	EM_MN10200      = 090; // Matsushita MN10200
	EM_PJ           = 091; // picoJava
	EM_OPENRISC     = 092; // OpenRISC 32-bit embedded processor
	EM_ARC_COMPACT  = 093; // ARC International ARCompact processor
	EM_XTENSA       = 094; // Tensilica Xtensa Architecture
	EM_VIDEOCORE    = 095; // Alphamosaic VideoCore processor
	EM_TMM_GPP      = 096; // Thompson Multimedia General Purpose Processor
	EM_NS32K        = 097; // National Semiconductor 32000 series
	EM_TPC          = 098; // Tenor Network TPC processor
	EM_SNP1K        = 099; // Trebia SNP 1000 processor
	EM_ST200        = 100; // STMicroelectronics ST200
	EM_IP2K         = 101; // Ubicom IP2xxx microcontroller family
	EM_MAX          = 102; // MAX Processor
	EM_CR           = 103; // National Semiconductor CompactRISC microprocessor
	EM_F2MC16       = 104; // Fujitsu F2MC16
	EM_MSP430       = 105; // Texas Instruments embedded microcontroller msp430
	EM_BLACKFIN     = 106; // Analog Devices Blackfin (DSP) processor
	EM_SE_C33       = 107; // S1C33 Family of Seiko Epson processors
	EM_SEP          = 108; // Sharp embedded microprocessor
	EM_ARCA         = 109; // Arca RISC Microprocessor
	EM_UNICORE      = 110; // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
	EM_EXCESS       = 111; // eXcess: 16/32/64-bit configurable embedded CPU
	EM_DXP          = 112; // Icera Semiconductor Inc. Deep Execution Processor
	EM_ALTERA_NIOS2 = 113; // Altera Nios II soft-core processor
	EM_CRX          = 114; // National Semiconductor CompactRISC CRX
	EM_XGATE        = 115; // Motorola XGATE embedded processor
	EM_C166         = 116; // Infineon C16x/XC16x processor
	EM_M16C         = 117; // Renesas M16C series microprocessors
	EM_DSPIC30F     = 118; // Microchip Technology dsPIC30F Digital Signal Controller
	EM_CE           = 119; // Freescale Communication Engine RISC core
	EM_M32C         = 120; // Renesas M32C series microprocessors
  // 121-130 Reserved for future use
	EM_TSK3000      = 131; // Altium TSK3000 core
	EM_RS08         = 132; // Freescale RS08 embedded processor
	EM_SHARC        = 133; // Analog Devices SHARC family of 32-bit DSP processors
	EM_ECOG2        = 134; // Cyan Technology eCOG2 microprocessor
	EM_SCORE7       = 135; // Sunplus S+core7 RISC processor
	EM_DSP24        = 136; // New Japan Radio (NJR) 24-bit DSP Processor
	EM_VIDEOCORE3   = 137; // Broadcom VideoCore III processor
	EM_LATTICEMICO32= 138; // RISC processor for Lattice FPGA architecture
	EM_SE_C17       = 139; // Seiko Epson C17 family
	EM_TI_C6000     = 140; // The Texas Instruments TMS320C6000 DSP family
	EM_TI_C2000     = 141; // The Texas Instruments TMS320C2000 DSP family
	EM_TI_C5500     = 142; // The Texas Instruments TMS320C55x DSP family
  EM_TI_ARP32     = 143; // Texas Instruments Application Specific RISC Processor, 32bit fetch
  EM_TI_PRU       = 144; // Texas Instruments Programmable Realtime Unit
  // 145-159 Reserved for future use
	EM_MMDSP_PLUS   = 160; // STMicroelectronics 64bit VLIW Data Signal Processor
	EM_CYPRESS_M8C  = 161; // Cypress M8C microprocessor
	EM_R32C         = 162; // Renesas R32C series microprocessors
	EM_TRIMEDIA     = 163; // NXP Semiconductors TriMedia architecture family
	EM_HEXAGON      = 164; // Qualcomm Hexagon processor
	EM_8051         = 165; // Intel 8051 and variants
	EM_STXP7X       = 166; // STMicroelectronics STxP7x family of configurable and extensible RISC processors
	EM_NDS32        = 167; // Andes Technology compact code size embedded RISC processor family
	EM_ECOG1X       = 168; // Cyan Technology eCOG1X family
	EM_MAXQ30       = 169; // Dallas Semiconductor MAXQ30 Core Micro-controllers
	EM_XIMO16       = 170; // New Japan Radio (NJR) 16-bit DSP Processor
	EM_MANIK        = 171; // M2000 Reconfigurable RISC Microprocessor
	EM_CRAYNV2      = 172; // Cray Inc. NV2 vector architecture
	EM_RX           = 173; // Renesas RX family
	EM_METAG        = 174; // Imagination Technologies META processor architecture
	EM_MCST_ELBRUS  = 175; // MCST Elbrus general purpose hardware architecture
	EM_ECOG16       = 176; // Cyan Technology eCOG16 family
	EM_CR16         = 177; // National Semiconductor CompactRISC CR16 16-bit microprocessor
	EM_ETPU         = 178; // Freescale Extended Time Processing Unit
	EM_SLE9X        = 179; // Infineon Technologies SLE9X core
	EM_L10M         = 180; // Intel L10M
	EM_K10M         = 181; // Intel K10M
  // 182 Reserved for future Intel use
	EM_AARCH64      = 183; // ARM AArch64
  // 184 Reserved for future ARM use
	EM_AVR32        = 185; // Atmel Corporation 32-bit microprocessor family
	EM_STM8         = 186; // STMicroeletronics STM8 8-bit microcontroller
	EM_TILE64       = 187; // Tilera TILE64 multicore architecture family
	EM_TILEPRO      = 188; // Tilera TILEPro multicore architecture family
	EM_CUDA         = 190; // NVIDIA CUDA architecture
	EM_TILEGX       = 191; // Tilera TILE-Gx multicore architecture family
	EM_CLOUDSHIELD  = 192; // CloudShield architecture family
	EM_COREA_1ST    = 193; // KIPO-KAIST Core-A 1st generation processor family
	EM_COREA_2ND    = 194; // KIPO-KAIST Core-A 2nd generation processor family
	EM_ARC_COMPACT2 = 195; // Synopsys ARCompact V2
	EM_OPEN8        = 196; // Open8 8-bit RISC soft processor core
	EM_RL78         = 197; // Renesas RL78 family
	EM_VIDEOCORE5   = 198; // Broadcom VideoCore V processor
	EM_78KOR        = 199; // Renesas 78KOR family
	EM_56800EX      = 200; // Freescale 56800EX Digital Signal Controller (DSC)
	EM_BA1          = 201; // Beyond BA1 CPU architecture
	EM_BA2          = 202; // Beyond BA2 CPU architecture
	EM_XCORE        = 203; // XMOS xCORE processor family
	EM_MCHP_PIC     = 204; // Microchip 8-bit PIC(r) family
  // 205-209 Reserved for future Intel use
	EM_KM32         = 210; // KM211 KM32 32-bit processor
	EM_KMX32        = 211; // KM211 KMX32 32-bit processor
	EM_KMX16        = 212; // KM211 KMX16 16-bit processor
	EM_KMX8         = 213; // KM211 KMX8 8-bit processor
	EM_KVARC        = 214; // KM211 KVARC processor
	EM_CDP          = 215; // Paneve CDP architecture family
	EM_COGE         = 216; // Cognitive Smart Memory Processor
	EM_COOL         = 217; // iCelero CoolEngine
	EM_NORC         = 218; // Nanoradio Optimized RISC
	EM_CSR_KALIMBA  = 219; // CSR Kalimba architecture family

  EM_Z80          = 220; // Zilog Z80
  EM_VISIUM       = 221; // Controls and Data Services VISIUMcore processor
  EM_FT32         = 222; // FTDI Chip FT32 high performance 32-bit RISC architecture
  EM_MOXIE        = 223; // Moxie processor family
  EM_AMDGPU       = 224; // AMD GPU architecture
  EM_RISCV        = 243; // RISC-V
  EM_LANAI        = 244; // Lanai 32-bit processor
  EM_BPF          = 247; // Linux BPF
  EM_VE           = 251; // NEC SX-Aurora VE
  EM_CSKY         = 252; // C-Sky
  EM_LOONGARCH    = 258; // LoongArch
  EM_FRV          = $5441; // Fujitsu FR-V


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

  // Section data should be writable during execution.
  SHF_WRITE             = $1;

  // Section occupies memory during program execution.
  SHF_ALLOC             = $2;

  // Section contains executable machine instructions.
  SHF_EXECINSTR         = $4;

  // The data in this section may be merged.
  SHF_MERGE             = $10;

  // The data in this section is null-terminated strings.
  SHF_STRINGS           = $20;

  // A field in this section holds a section header table index.
  SHF_INFO_LINK         = $40;

  // Adds special ordering requirements for link editors.
  SHF_LINK_ORDER        = $80;

  // This section requires special OS-specific processing to avoid incorrect behavior.
  SHF_OS_NONCONFORMING  = $100;

  // This section is a member of a section group.
  SHF_GROUP             = $200;

  // This section holds Thread-Local Storage.
  SHF_TLS               = $400;

  // Identifies a section containing compressed data.
  SHF_COMPRESSED        = $800;

  // This section should not be garbage collected by the linker.
  SHF_GNU_RETAIN        = $200000;

  // This section is excluded from the final executable or shared library.
  SHF_EXCLUDE           = $80000000;

  // Start of target-specific flags.
  SHF_MASKOS            = $0FF00000;

  // Solaris equivalent of SHF_GNU_RETAIN.
  SHF_SUNW_NODISCARD    = $00100000;

  // Bits indicating processor-specific flags.
  SHF_MASKPROC          = $F0000000;

  /// All sections with the "d" flag are grouped together by the linker to form
  /// the data section and the dp register is set to the start of the section by
  /// the boot code.
  XCORE_SHF_DP_SECTION  = $10000000;

  /// All sections with the "c" flag are grouped together by the linker to form
  /// the constant pool and the cp register is set to the start of the constant
  /// pool by the boot code.
  XCORE_SHF_CP_SECTION  = $20000000;

  // If an object file section does not have this flag set, then it may not hold
  // more than 2GB and can be freely referred to in objects using smaller code
  // models. Otherwise, only objects using larger code models can refer to them.
  // For example, a medium code model object can refer to data in a section that
  // sets this flag besides being able to refer to data in a section that does
  // not set it; likewise, a small code model object can refer only to code in a
  // section that does not set this flag.
  SHF_X86_64_LARGE      = $10000000;

  // All sections with the GPREL flag are grouped into a global data area
  // for faster accesses
  SHF_HEX_GPREL         = $10000000;

  // Section contains text/data which may be replicated in other sections.
  // Linker must retain only one copy.
  SHF_MIPS_NODUPES      = $01000000;

  // Linker must generate implicit hidden weak names.
  SHF_MIPS_NAMES        = $02000000;

  // Section data local to process.
  SHF_MIPS_LOCAL        = $04000000;

  // Do not strip this section.
  SHF_MIPS_NOSTRIP      = $08000000;

  // Section must be part of global data area.
  SHF_MIPS_GPREL        = $10000000;

  // This section should be merged.
  SHF_MIPS_MERGE        = $20000000;

  // Address size to be inferred from section entry size.
  SHF_MIPS_ADDR         = $40000000;

  // Section data is string data by default.
  SHF_MIPS_STRING       = $80000000;

  // Section contains only program instructions and no program data.
  SHF_ARM_PURECODE      = $20000000;

  // Section contains only program instructions and no program data.
  SHF_AARCH64_PURECODE  = $20000000;

  // Special Section Indexes
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

  // Symbol Binding - ELF32_ST_BIND - st_info
  STB_LOCAL       = 0;  // Local symbol, not visible outside obj file containing def
  STB_GLOBAL      = 1;  // Global symbol, visible to all object files being combined
  STB_WEAK        = 2;  // Weak symbol, like global but lower-precedence
  STB_NUM         = 3;
  STB_GNU_UNIQUE	= 10;
  STB_LOPROC	    = 13;	// processor specific range
  STB_HIPROC	    = 15;

  // Symbol type - ELF32_ST_TYPE - st_info
  STT_NOTYPE	    = 0;  // Symbol's type is not specified
  STT_OBJECT	    = 1;  // Symbol is a data object (variable, array, etc.)
  STT_FUNC	      = 2;  // Symbol is executable code (function, etc.)
  STT_SECTION	    = 3;  // Symbol refers to a section
  STT_FILE	      = 4;  // Local, absolute symbol that refers to a file
  STT_COMMON	    = 5;  // An uninitialized common block
  STT_TLS		      = 6;  // Thread local data object
  STT_NUM		      = 7;
  STT_GNU_IFUNC	  = 10; // GNU indirect function
  STT_LOPROC	    = 13;	// processor specific range
  STT_HIPROC	    = 15;

  STV_DEFAULT     = 0;  // Visibility is specified by binding type
  STV_INTERNAL    = 1;  // Defined by processor supplements
  STV_HIDDEN      = 2;  // Not visible to other components
  STV_PROTECTED   = 3;  // Visible in other components but not preemptable

  // Symbol number.

  STN_UNDEF = 0;

  // Dynamic Array Tags - d_tag
  DT_NULL		          = 0;  	// Marks end of dynamic section
  DT_NEEDED	          = 1;  	// Name of needed library
  DT_PLTRELSZ	        = 2;  	// Size in bytes of PLT relocs
  DT_PLTGOT	          = 3;  	// Processor defined value
  DT_HASH		          = 4;  	// Address of symbol hash table
  DT_STRTAB	          = 5;  	// Address of string table
  DT_SYMTAB	          = 6;  	// Address of symbol table
  DT_RELA		          = 7;  	// Address of Rela relocs
  DT_RELASZ	          = 8;  	// Total size of Rela relocs
  DT_RELAENT	        = 9;  	// Size of one Rela reloc
  DT_STRSZ            = 10;		// Size of string table
  DT_SYMENT	          = 11;		// Size of one symbol table entry
  DT_INIT		          = 12;		// Address of init function
  DT_FINI		          = 13;		// Address of termination function
  DT_SONAME	          = 14;		// Name of shared object
  DT_RPATH	          = 15;		// Library search path (deprecated)
  DT_SYMBOLIC	        = 16;		// Start symbol search here
  DT_REL		          = 17;		// Address of Rel relocs
  DT_RELSZ	          = 18;		// Total size of Rel relocs
  DT_RELENT	          = 19;		// Size of one Rel reloc
  DT_PLTREL	          = 20;		// Type of reloc in PLT
  DT_DEBUG	          = 21;		// For debugging; unspecified
  DT_TEXTREL	        = 22;		// Reloc might modify .text
  DT_JMPREL	          = 23;		// Address of PLT relocs
  DT_BIND_NOW	        = 24;		// Process relocations of object
  DT_INIT_ARRAY	      = 25;		// Array with addresses of init fct
  DT_FINI_ARRAY	      = 26;		// Array with addresses of fini fct
  DT_INIT_ARRAYSZ	    = 27;		// Size in bytes of DT_INIT_ARRAY
  DT_FINI_ARRAYSZ     = 28;		// Size in bytes of DT_FINI_ARRAY
  DT_RUNPATH	        = 29;		// Library search path
  DT_FLAGS	          = 30;		// Flags for the object being loaded
  DT_ENCODING	        = 32;		// Start of encoded range
  DT_PREINIT_ARRAY    = 32;		// Array with addresses of preinit fc
  DT_PREINIT_ARRAYSZ  = 33;		// size in bytes of DT_PREINIT_ARRAY
  DT_SYMTAB_SHNDX	    = 34;		// Address of SYMTAB_SHNDX section
  DT_NUM		          = 35;		// Number used
  DT_LOOS		          = $6000000d;	// Start of OS-specific
  DT_HIOS		          = $6ffff000;	// End of OS-specific
  DT_LOPROC	          = $70000000;	// Start of processor-specific
  DT_HIPROC	          = $7fffffff;	// End of processor-specific
//  DT_PROCNUM	        = DT_MIPS_NUM;	// Most used by any processor

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
    e_ident: EIdent;       // ELF Identification bytes
    e_type: UInt16;        // Type of file (see ET_* below)
    e_machine: UInt16;     // Required architecture for this file (see EM_*)
    e_version: UInt32;     // Must be equal to 1
    e_entry: Elf32_Addr;   // Address to jump to in order to start program
    e_phoff: Elf32_Off;    // Program header table's file offset, in bytes
    e_shoff: Elf32_Off;    // Section header table's file offset, in bytes
    e_flags: UInt32;       // Processor-specific flags
    e_ehsize: UInt16;      // Size of ELF header, in bytes
    e_phentsize: UInt16;   // Size of an entry in the program header table
    e_phnum: UInt16;       // Number of entries in the program header table
    e_shentsize: UInt16;   // Size of an entry in the section header table
    e_shnum: UInt16;       // Number of entries in the section header table
    e_shstrndx: UInt16;    // Sect hdr table index of sect name string table
  end;

  // 64-bit ELF header. Fields are the same as for ELF32, but with different
  // types (see above).
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
    p_type: UInt32;        // Type of segment
    p_offset: Elf32_Off;   // File offset where segment is located, in bytes
    p_vaddr: Elf32_Addr;   // Virtual address of beginning of segment
    p_paddr: Elf32_Addr;   // Physical address of beginning of segment (OS-specific)
    p_filesz: UInt32;      // Num. of bytes in file image of segment (may be zero)
    p_memsz: UInt32;       // Num. of bytes in mem image of segment (may be zero)
    p_flags: UInt32;       // Segment flags
    p_align: UInt32;       // Segment alignment constraint
  end;

  Elf64_Phdr = record
    p_type: UInt32;        // Type of segment
    p_flags: UInt32;       // Segment flags
    p_offset: Elf64_Off;   // File offset where segment is located, in bytes
    p_vaddr: Elf64_Addr;   // Virtual address of beginning of segment
    p_paddr: Elf64_Addr;   // Physical addr of beginning of segment (OS-specific)
    p_filesz: UInt64;      // Num. of bytes in file image of segment (may be zero)
    p_memsz: UInt64;       // Num. of bytes in mem image of segment (may be zero)
    p_align: UInt64;       // Segment alignment constraint
  end;

  // Заголовок раздела

  Elf32_Shdr = record
    sh_name: UInt32;       // Section name (index into string table)
    sh_type: UInt32;       // Section type (SHT_*)
    sh_flags: UInt32;      // Section flags (SHF_*)
    sh_addr: Elf32_Addr;   // Address where section is to be loaded
    sh_offset: Elf32_Off;  // File offset of section data, in bytes
    sh_size: UInt32;       // Size of section, in bytes
    sh_link: UInt32;       // Section type-specific header table index link
    sh_info: UInt32;       // Section type-specific extra information
    sh_addralign: UInt32;  // Section address alignment
    sh_entsize: UInt32;    // Size of records contained within the section
  end;

  Elf64_Shdr = record
    sh_name: UInt32;       // Section name (index into string table)
    sh_type: UInt32;       // Section type (SHT_*)
    sh_flags: UInt64;      // Section flags (SHF_*)
    sh_addr: Elf64_Addr;   // Address where section is to be loaded
    sh_offset: Elf64_Off;  // File offset of section data, in bytes
    sh_size: UInt64;       // Size of section, in bytes
    sh_link: UInt32;       // Section type-specific header table index link
    sh_info: UInt32;       // Section type-specific extra information
    sh_addralign: UInt64;  // Section address alignment
    sh_entsize: UInt64;    // Size of records contained within the section
  end;

  // Зпголовок таблицы символов

  Elf32_Sym = record
    st_name: UInt32;       // Symbol name (index into string table)
    st_value: Elf32_Addr;  // Value or address associated with the symbol
    st_size: UInt32;       // Size of the symbol
    st_info: Byte;         // Symbol's type and binding attributes
    st_other: Byte;        // Must be zero; reserved
    st_shndx: UInt16;      // Which section (header table index) it's defined in
  end;

  pElf64_Sym = ^Elf64_Sym;
  Elf64_Sym = record
    st_name: UInt32;       // Symbol name (index into string table)
    st_info: Byte;         // Symbol's type and binding attributes
    st_other: Byte;        // Must be zero; reserved
    st_shndx: UInt16;      // Which section (header tbl index) it's defined in
    st_value: Elf64_Addr;  // Value or address associated with the symbol
    st_size: UInt64;       // Size of the symbol
  end;

  Elf32_Dyn = record
    d_tag: Elf32_Sword;       // Type of dynamic table entry.
    case Integer of
      0: (d_val: Elf32_Word); // Integer value of entry.
      1: (d_ptr: Elf32_Addr); // Pointer value of entry.
  end;

  Elf64_Dyn = record
    d_tag: Elf64_Sxword;       // Type of dynamic table entry.
    case Integer of
      0: (d_val: Elf64_Xword); // Integer value of entry.
      1: (d_ptr: Elf64_Addr);  // Pointer value of entry.
  end;

  // Relocation entry with implicit addend
  Elf32_Rel = record
    r_offset: Elf32_Addr;   // offset of relocation
    r_info: Elf32_Word;     // symbol table index and type
  end;

  // Relocation entry with explicit addend
  Elf32_Rela = record
    r_offset: Elf32_Addr;   // offset of relocation
    r_info: Elf32_Word;     // symbol table index and type
    r_addend: Elf32_Sword;
  end;

  // Relocation entry with implicit addend
  Elf64_Rel = record
    r_offset: Elf64_Xword;   // where to do it
    r_info: Elf64_Xword;     // index & type of relocation
  end;

  // Relocation entry with explicit addend
  PElf64_Rela = ^Elf64_Rela;
  Elf64_Rela = record
    r_offset: Elf64_Xword;   // where to do it
    r_info: Elf64_Xword;     // index & type of relocation
    r_addend: Elf64_Sxword;  // adjustment value
  end;

  // .gnu.hash header
  TGnuHashHeader = packed record
    nbuckets: Integer;
    symndx: UInt32;
    maskwords: Integer;
    shift2: UInt32;
  end;

  // Extract symbol info - st_info
  function ELF32_ST_BIND(Info: Byte): Byte;
  function ELF32_ST_TYPE(Info: Byte): Byte;
  function ELF32_ST_VISIBLITY(Info: Byte): Byte;

  // Extract relocation info - r_info
  function ELF32_R_SYM(Info: Elf32_Word): Elf32_Word;
  function ELF32_R_TYPE(Info: Elf32_Word): Elf32_Word;
  function ELF32_R_INFO(s, t: Elf32_Word): Elf32_Word;
  function ELF64_R_SYM(Info: Elf64_Xword): Elf64_Word;
  function ELF64_R_TYPE(Info: Elf64_Xword): Elf64_Word;
  function ELF64_R_INFO(s, t: Elf64_Word): Elf64_Xword;

  function CalculateElfHash(const Name: AnsiString): UInt32;
  function CalculateGnuHash(const Name: AnsiString): UInt32;

implementation

function ELF32_ST_BIND(Info: Byte): Byte;
begin
  Result := Info shr 4;
end;

function ELF32_ST_TYPE(Info: Byte): Byte;
begin
  Result := Info and $F;
end;

function ELF32_ST_VISIBLITY(Info: Byte): Byte;
begin
  Result := Info and 3;
end;

function ELF32_R_SYM(Info: Elf32_Word): Elf32_Word;
begin
  Result := Info shr 8;
end;

function ELF32_R_TYPE(Info: Elf32_Word): Elf32_Word;
begin
  Result := Info and $FF;
end;

function ELF32_R_INFO(s, t: Elf32_Word): Elf32_Word;
begin
  Result := s shl 8 + t;
end;

function ELF64_R_SYM(Info: Elf64_Xword): Elf64_Word;
begin
  Result := Info shr 32;
end;

function ELF64_R_TYPE(Info: Elf64_Xword): Elf64_Word;
begin
  Result := Info;
end;

function ELF64_R_INFO(s, t: Elf64_Word): Elf64_Xword;
begin
  Result := s shl 32 + t;
end;

function CalculateElfHash(const Name: AnsiString): UInt32;
var
  I: Integer;
  Tmp: UInt32;
begin
  Result := 0;
  for I := 1 to Length(Name) do
  begin
    Result := Result shl 4 + Ord(Name[I]);
    Tmp := Result and $F0000000;
    if Tmp <> 0 then
      Result := Result xor (Tmp shr 24);
    Result := Result and not Tmp;
  end;
end;

function CalculateGnuHash(const Name: AnsiString): UInt32;
var
  I: Integer;
begin
  Result := 5381;
  for I := 1 to Length(Name) do
    Result := Result shl 5 + Result + Ord(Name[I]);
end;


end.
