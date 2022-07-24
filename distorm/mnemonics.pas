﻿{
mnemonics.h

diStorm3 - Powerful disassembler for X86/AMD64
http://ragestorm.net/distorm/
distorm at gmail dot com
Copyright (C) 2003-2021 Gil Dabah
This library is licensed under the BSD license. See the file COPYING.

================================================================================
Delphi port: Alexander (Rouse_) Bagel. May 2016.
Update to 3.5.3: July 2022
WARNINIG: Support Delphi XE2 and higher
https://github.com/AlexanderBagel/distorm
================================================================================
}

unit mnemonics;

interface

uses
  Windows;

  // 0. Open distorm solution in Microsoft Visual Studio
  // 1. Remove "Security Check" from Project -> Properties -> C/C++ -> Code Generation
  // 2. Build "clib" configuration
  {$IFDEF WIN32}
    {$L 32\mnemonics.obj}
  {$ELSE}
    {$L 64\mnemonics.obj}
  {$ENDIF}

type
  _InstructionType = (
    I_UNDEFINED = 0, I_AAA = 66, I_AAD = 388, I_AAM = 383, I_AAS = 76, I_ADC = 31, I_ADD = 11, I_ADDPD = 3143,
    I_ADDPS = 3136, I_ADDSD = 3157, I_ADDSS = 3150, I_ADDSUBPD = 6427, I_ADDSUBPS = 6437,
    I_AESDEC = 9242, I_AESDECLAST = 9259, I_AESENC = 9200, I_AESENCLAST = 9217,
    I_AESIMC = 9183, I_AESKEYGENASSIST = 9828, I_AND = 41, I_ANDNPD = 3054, I_ANDNPS = 3046,
    I_ANDPD = 3023, I_ANDPS = 3016, I_ARPL = 111, I_BLENDPD = 9405, I_BLENDPS = 9386,
    I_BLENDVPD = 7652, I_BLENDVPS = 7642, I_BOUND = 104, I_BSF = 4379, I_BSR = 4391,
    I_BSWAP = 959, I_BT = 871, I_BTC = 933, I_BTR = 911, I_BTS = 886, I_CALL = 455,
    I_CALL_FAR = 260, I_CBW = 228, I_CDQ = 250, I_CDQE = 239, I_CLAC = 1786, I_CLC = 491,
    I_CLD = 511, I_CLFLUSH = 4362, I_CLGI = 1866, I_CLI = 501, I_CLTS = 540, I_CMC = 486,
    I_CMOVA = 693, I_CMOVAE = 662, I_CMOVB = 655, I_CMOVBE = 685, I_CMOVG = 753,
    I_CMOVGE = 737, I_CMOVL = 730, I_CMOVLE = 745, I_CMOVNO = 647, I_CMOVNP = 722,
    I_CMOVNS = 707, I_CMOVNZ = 677, I_CMOVO = 640, I_CMOVP = 715, I_CMOVS = 700,
    I_CMOVZ = 670, I_CMP = 71, I_CMPEQPD = 4482, I_CMPEQPS = 4403, I_CMPEQSD = 4640,
    I_CMPEQSS = 4561, I_CMPLEPD = 4500, I_CMPLEPS = 4421, I_CMPLESD = 4658, I_CMPLESS = 4579,
    I_CMPLTPD = 4491, I_CMPLTPS = 4412, I_CMPLTSD = 4649, I_CMPLTSS = 4570, I_CMPNEQPD = 4521,
    I_CMPNEQPS = 4442, I_CMPNEQSD = 4679, I_CMPNEQSS = 4600, I_CMPNLEPD = 4541,
    I_CMPNLEPS = 4462, I_CMPNLESD = 4699, I_CMPNLESS = 4620, I_CMPNLTPD = 4531,
    I_CMPNLTPS = 4452, I_CMPNLTSD = 4689, I_CMPNLTSS = 4610, I_CMPORDPD = 4551,
    I_CMPORDPS = 4472, I_CMPORDSD = 4709, I_CMPORDSS = 4630, I_CMPS = 301, I_CMPUNORDPD = 4509,
    I_CMPUNORDPS = 4430, I_CMPUNORDSD = 4667, I_CMPUNORDSS = 4588, I_CMPXCHG = 897,
    I_CMPXCHG16B = 6406, I_CMPXCHG8B = 6395, I_COMISD = 2812, I_COMISS = 2804,
    I_CPUID = 864, I_CQO = 255, I_CRC32 = 9291, I_CVTDQ2PD = 6820, I_CVTDQ2PS = 3340,
    I_CVTPD2DQ = 6830, I_CVTPD2PI = 2714, I_CVTPD2PS = 3266, I_CVTPH2PS = 4194,
    I_CVTPI2PD = 2528, I_CVTPI2PS = 2518, I_CVTPS2DQ = 3350, I_CVTPS2PD = 3256,
    I_CVTPS2PH = 4204, I_CVTPS2PI = 2704, I_CVTSD2SI = 2734, I_CVTSD2SS = 3286,
    I_CVTSI2SD = 2548, I_CVTSI2SS = 2538, I_CVTSS2SD = 3276, I_CVTSS2SI = 2724,
    I_CVTTPD2DQ = 6809, I_CVTTPD2PI = 2647, I_CVTTPS2DQ = 3360, I_CVTTPS2PI = 2636,
    I_CVTTSD2SI = 2669, I_CVTTSS2SI = 2658, I_CWD = 245, I_CWDE = 233, I_DAA = 46,
    I_DAS = 56, I_DEC = 86, I_DIV = 1645, I_DIVPD = 3532, I_DIVPS = 3525, I_DIVSD = 3546,
    I_DIVSS = 3539, I_DPPD = 9648, I_DPPS = 9635, I_EMMS = 4133, I_ENTER = 340,
    I_EXTRACTPS = 9513, I_EXTRQ = 4169, I_F2XM1 = 1191, I_FABS = 1122, I_FADD = 1022,
    I_FADDP = 1548, I_FBLD = 1600, I_FBSTP = 1606, I_FCHS = 1116, I_FCLEX = 7322,
    I_FCMOVB = 1375, I_FCMOVBE = 1391, I_FCMOVE = 1383, I_FCMOVNB = 1444, I_FCMOVNBE = 1462,
    I_FCMOVNE = 1453, I_FCMOVNU = 1472, I_FCMOVU = 1400, I_FCOM = 1034, I_FCOMI = 1511,
    I_FCOMIP = 1622, I_FCOMP = 1040, I_FCOMPP = 1562, I_FCOS = 1310, I_FDECSTP = 1237,
    I_FDIV = 1060, I_FDIVP = 1593, I_FDIVR = 1066, I_FDIVRP = 1585, I_FEDISI = 1487,
    I_FEMMS = 573, I_FENI = 1481, I_FFREE = 1526, I_FIADD = 1316, I_FICOM = 1330,
    I_FICOMP = 1337, I_FIDIV = 1360, I_FIDIVR = 1367, I_FILD = 1417, I_FIMUL = 1323,
    I_FINCSTP = 1246, I_FINIT = 7337, I_FIST = 1431, I_FISTP = 1437, I_FISTTP = 1423,
    I_FISUB = 1345, I_FISUBR = 1352, I_FLD = 1073, I_FLD1 = 1140, I_FLDCW = 1097,
    I_FLDENV = 1089, I_FLDL2E = 1154, I_FLDL2T = 1146, I_FLDLG2 = 1169, I_FLDLN2 = 1177,
    I_FLDPI = 1162, I_FLDZ = 1185, I_FMUL = 1028, I_FMULP = 1555, I_FNCLEX = 7314,
    I_FNINIT = 7329, I_FNOP = 1110, I_FNSAVE = 7344, I_FNSTCW = 7299, I_FNSTENV = 7282,
    I_FNSTSW = 7359, I_FPATAN = 1212, I_FPREM = 1255, I_FPREM1 = 1229, I_FPTAN = 1205,
    I_FRNDINT = 1287, I_FRSTOR = 1518, I_FSAVE = 7352, I_FSCALE = 1296, I_FSETPM = 1495,
    I_FSIN = 1304, I_FSINCOS = 1278, I_FSQRT = 1271, I_FST = 1078, I_FSTCW = 7307,
    I_FSTENV = 7291, I_FSTP = 1083, I_FSTSW = 7367, I_FSUB = 1047, I_FSUBP = 1578,
    I_FSUBR = 1053, I_FSUBRP = 1570, I_FTST = 1128, I_FUCOM = 1533, I_FUCOMI = 1503,
    I_FUCOMIP = 1613, I_FUCOMP = 1540, I_FUCOMPP = 1408, I_FXAM = 1134, I_FXCH = 1104,
    I_FXRSTOR = 9925, I_FXRSTOR64 = 9934, I_FXSAVE = 9897, I_FXSAVE64 = 9905,
    I_FXTRACT = 1220, I_FYL2X = 1198, I_FYL2XP1 = 1262, I_GETSEC = 632, I_HADDPD = 4214,
    I_HADDPS = 4222, I_HLT = 481, I_HSUBPD = 4248, I_HSUBPS = 4256, I_IDIV = 1650,
    I_IMUL = 117, I_IN = 446, I_INC = 81, I_INS = 123, I_INSERTPS = 9580, I_INSERTQ = 4176,
    I_INT = 366, I_INT1 = 475, I_INT3 = 360, I_INTO = 371, I_INVD = 554, I_INVEPT = 8317,
    I_INVLPG = 1726, I_INVLPGA = 1880, I_INVPCID = 8334, I_INVVPID = 8325, I_IRET = 377,
    I_JA = 166, I_JAE = 147, I_JB = 143, I_JBE = 161, I_JCXZ = 426, I_JECXZ = 432,
    I_JG = 202, I_JGE = 192, I_JL = 188, I_JLE = 197, I_JMP = 461, I_JMP_FAR = 466,
    I_JNO = 138, I_JNP = 183, I_JNS = 174, I_JNZ = 156, I_JO = 134, I_JP = 179,
    I_JRCXZ = 439, I_JS = 170, I_JZ = 152, I_LAHF = 289, I_LAR = 521, I_LDDQU = 7027,
    I_LDMXCSR = 9955, I_LDS = 335, I_LEA = 223, I_LEAVE = 347, I_LES = 330, I_LFENCE = 4298,
    I_LFS = 916, I_LGDT = 1702, I_LGS = 921, I_LIDT = 1708, I_LLDT = 1667, I_LMSW = 1720,
    I_LODS = 313, I_LOOP = 420, I_LOOPNZ = 405, I_LOOPZ = 413, I_LSL = 526, I_LSS = 906,
    I_LTR = 1673, I_LZCNT = 4396, I_MASKMOVDQU = 7152, I_MASKMOVQ = 7142, I_MAXPD = 3592,
    I_MAXPS = 3585, I_MAXSD = 3606, I_MAXSS = 3599, I_MFENCE = 4324, I_MINPD = 3472,
    I_MINPS = 3465, I_MINSD = 3486, I_MINSS = 3479, I_MONITOR = 1770, I_MOV = 218,
    I_MOVAPD = 2492, I_MOVAPS = 2484, I_MOVBE = 9284, I_MOVD = 3953, I_MOVDDUP = 2219,
    I_MOVDQ2Q = 6555, I_MOVDQA = 3979, I_MOVDQU = 3987, I_MOVHLPS = 2184, I_MOVHPD = 2378,
    I_MOVHPS = 2370, I_MOVLHPS = 2361, I_MOVLPD = 2201, I_MOVLPS = 2193, I_MOVMSKPD = 2848,
    I_MOVMSKPS = 2838, I_MOVNTDQ = 6882, I_MOVNTDQA = 7928, I_MOVNTI = 951, I_MOVNTPD = 2589,
    I_MOVNTPS = 2580, I_MOVNTQ = 6874, I_MOVNTSD = 2607, I_MOVNTSS = 2598, I_MOVQ = 3959,
    I_MOVQ2DQ = 6546, I_MOVS = 295, I_MOVSD = 2143, I_MOVSHDUP = 2386, I_MOVSLDUP = 2209,
    I_MOVSS = 2136, I_MOVSX = 938, I_MOVSXD = 10038, I_MOVUPD = 2128, I_MOVUPS = 2120,
    I_MOVZX = 926, I_MPSADBW = 9661, I_MUL = 1640, I_MULPD = 3203, I_MULPS = 3196,
    I_MULSD = 3217, I_MULSS = 3210, I_MWAIT = 1779, I_NEG = 1635, I_NOP = 580,
    I_NOT = 1630, I_OR = 27, I_ORPD = 3086, I_ORPS = 3080, I_OUT = 450, I_OUTS = 128,
    I_PABSB = 7721, I_PABSD = 7751, I_PABSW = 7736, I_PACKSSDW = 3882, I_PACKSSWB = 3714,
    I_PACKUSDW = 7949, I_PACKUSWB = 3792, I_PADDB = 7237, I_PADDD = 7267, I_PADDQ = 6514,
    I_PADDSB = 6963, I_PADDSW = 6980, I_PADDUSB = 6653, I_PADDUSW = 6672, I_PADDW = 7252,
    I_PALIGNR = 9443, I_PAND = 6640, I_PANDN = 6698, I_PAUSE = 10046, I_PAVGB = 6713,
    I_PAVGUSB = 2111, I_PAVGW = 6758, I_PBLENDVB = 7632, I_PBLENDW = 9424, I_PCLMULQDQ = 9680,
    I_PCMPEQB = 4076, I_PCMPEQD = 4114, I_PCMPEQQ = 7909, I_PCMPEQW = 4095, I_PCMPESTRI = 9759,
    I_PCMPESTRM = 9736, I_PCMPGTB = 3735, I_PCMPGTD = 3773, I_PCMPGTQ = 8120,
    I_PCMPGTW = 3754, I_PCMPISTRI = 9805, I_PCMPISTRM = 9782, I_PEXTRB = 9462,
    I_PEXTRD = 9479, I_PEXTRQ = 9487, I_PEXTRW = 6344, I_PF2ID = 1947, I_PF2IW = 1940,
    I_PFACC = 2061, I_PFADD = 2010, I_PFCMPEQ = 2068, I_PFCMPGE = 1971, I_PFCMPGT = 2017,
    I_PFMAX = 2026, I_PFMIN = 1980, I_PFMUL = 2077, I_PFNACC = 1954, I_PFPNACC = 1962,
    I_PFRCP = 1987, I_PFRCPIT1 = 2033, I_PFRCPIT2 = 2084, I_PFRSQIT1 = 2043, I_PFRSQRT = 1994,
    I_PFSUB = 2003, I_PFSUBR = 2053, I_PHADDD = 7408, I_PHADDSW = 7425, I_PHADDW = 7391,
    I_PHMINPOSUW = 8292, I_PHSUBD = 7484, I_PHSUBSW = 7501, I_PHSUBW = 7467, I_PI2FD = 1933,
    I_PI2FW = 1926, I_PINSRB = 9563, I_PINSRD = 9601, I_PINSRQ = 9609, I_PINSRW = 6327,
    I_PMADDUBSW = 7444, I_PMADDWD = 7106, I_PMAXSB = 8207, I_PMAXSD = 8224, I_PMAXSW = 6997,
    I_PMAXUB = 6681, I_PMAXUD = 8258, I_PMAXUW = 8241, I_PMINSB = 8139, I_PMINSD = 8156,
    I_PMINSW = 6935, I_PMINUB = 6623, I_PMINUD = 8190, I_PMINUW = 8173, I_PMOVMSKB = 6564,
    I_PMOVSXBD = 7787, I_PMOVSXBQ = 7808, I_PMOVSXBW = 7766, I_PMOVSXDQ = 7871,
    I_PMOVSXWD = 7829, I_PMOVSXWQ = 7850, I_PMOVZXBD = 8015, I_PMOVZXBQ = 8036,
    I_PMOVZXBW = 7994, I_PMOVZXDQ = 8099, I_PMOVZXWD = 8057, I_PMOVZXWQ = 8078,
    I_PMULDQ = 7892, I_PMULHRSW = 7571, I_PMULHRW = 2094, I_PMULHUW = 6773, I_PMULHW = 6792,
    I_PMULLD = 8275, I_PMULLW = 6529, I_PMULUDQ = 7087, I_POP = 22, I_POPA = 98,
    I_POPCNT = 4371, I_POPF = 277, I_POR = 6952, I_PREFETCH = 1905, I_PREFETCHNTA = 2435,
    I_PREFETCHT0 = 2448, I_PREFETCHT1 = 2460, I_PREFETCHT2 = 2472, I_PREFETCHW = 1915,
    I_PSADBW = 7125, I_PSHUFB = 7374, I_PSHUFD = 4021, I_PSHUFHW = 4029, I_PSHUFLW = 4038,
    I_PSHUFW = 4013, I_PSIGNB = 7520, I_PSIGND = 7554, I_PSIGNW = 7537, I_PSLLD = 7057,
    I_PSLLDQ = 9880, I_PSLLQ = 7072, I_PSLLW = 7042, I_PSRAD = 6743, I_PSRAW = 6728,
    I_PSRLD = 6484, I_PSRLDQ = 9863, I_PSRLQ = 6499, I_PSRLW = 6469, I_PSUBB = 7177,
    I_PSUBD = 7207, I_PSUBQ = 7222, I_PSUBSB = 6901, I_PSUBSW = 6918, I_PSUBUSB = 6585,
    I_PSUBUSW = 6604, I_PSUBW = 7192, I_PSWAPD = 2103, I_PTEST = 7662, I_PUNPCKHBW = 3813,
    I_PUNPCKHDQ = 3859, I_PUNPCKHQDQ = 3928, I_PUNPCKHWD = 3836, I_PUNPCKLBW = 3645,
    I_PUNPCKLDQ = 3691, I_PUNPCKLQDQ = 3903, I_PUNPCKLWD = 3668, I_PUSH = 16,
    I_PUSHA = 91, I_PUSHF = 270, I_PXOR = 7014, I_RCL = 976, I_RCPPS = 2986, I_RCPSS = 2993,
    I_RCR = 981, I_RDFSBASE = 9915, I_RDGSBASE = 9945, I_RDMSR = 599, I_RDPMC = 606,
    I_RDRAND = 10059, I_RDTSC = 592, I_RDTSCP = 1897, I_RET = 325, I_RETF = 354,
    I_ROL = 966, I_ROR = 971, I_ROUNDPD = 9329, I_ROUNDPS = 9310, I_ROUNDSD = 9367,
    I_ROUNDSS = 9348, I_RSM = 881, I_RSQRTPS = 2948, I_RSQRTSS = 2957, I_SAHF = 283,
    I_SAL = 996, I_SALC = 393, I_SAR = 1001, I_SBB = 36, I_SCAS = 319, I_SETA = 806,
    I_SETAE = 779, I_SETB = 773, I_SETBE = 799, I_SETG = 858, I_SETGE = 844, I_SETL = 838,
    I_SETLE = 851, I_SETNO = 766, I_SETNP = 831, I_SETNS = 818, I_SETNZ = 792,
    I_SETO = 760, I_SETP = 825, I_SETS = 812, I_SETZ = 786, I_SFENCE = 4354, I_SGDT = 1690,
    I_SHL = 986, I_SHLD = 875, I_SHR = 991, I_SHRD = 891, I_SHUFPD = 6369, I_SHUFPS = 6361,
    I_SIDT = 1696, I_SKINIT = 1872, I_SLDT = 1656, I_SMSW = 1714, I_SQRTPD = 2888,
    I_SQRTPS = 2880, I_SQRTSD = 2904, I_SQRTSS = 2896, I_STAC = 1792, I_STC = 496,
    I_STD = 516, I_STGI = 1860, I_STI = 506, I_STMXCSR = 9984, I_STOS = 307, I_STR = 1662,
    I_SUB = 51, I_SUBPD = 3412, I_SUBPS = 3405, I_SUBSD = 3426, I_SUBSS = 3419,
    I_SWAPGS = 1889, I_SYSCALL = 531, I_SYSENTER = 613, I_SYSEXIT = 623, I_SYSRET = 546,
    I_TEST = 206, I_TZCNT = 4384, I_UCOMISD = 2775, I_UCOMISS = 2766, I_UD2 = 568,
    I_UNPCKHPD = 2329, I_UNPCKHPS = 2319, I_UNPCKLPD = 2287, I_UNPCKLPS = 2277,
    I_VADDPD = 3172, I_VADDPS = 3164, I_VADDSD = 3188, I_VADDSS = 3180, I_VADDSUBPD = 6447,
    I_VADDSUBPS = 6458, I_VAESDEC = 9250, I_VAESDECLAST = 9271, I_VAESENC = 9208,
    I_VAESENCLAST = 9229, I_VAESIMC = 9191, I_VAESKEYGENASSIST = 9845, I_VANDNPD = 3071,
    I_VANDNPS = 3062, I_VANDPD = 3038, I_VANDPS = 3030, I_VBLENDPD = 9414, I_VBLENDPS = 9395,
    I_VBLENDVPD = 9714, I_VBLENDVPS = 9703, I_VBROADCASTF128 = 7705, I_VBROADCASTSD = 7691,
    I_VBROADCASTSS = 7677, I_VCMPEQPD = 5121, I_VCMPEQPS = 4719, I_VCMPEQSD = 5925,
    I_VCMPEQSS = 5523, I_VCMPEQ_OSPD = 5302, I_VCMPEQ_OSPS = 4900, I_VCMPEQ_OSSD = 6106,
    I_VCMPEQ_OSSS = 5704, I_VCMPEQ_UQPD = 5208, I_VCMPEQ_UQPS = 4806, I_VCMPEQ_UQSD = 6012,
    I_VCMPEQ_UQSS = 5610, I_VCMPEQ_USPD = 5411, I_VCMPEQ_USPS = 5009, I_VCMPEQ_USSD = 6215,
    I_VCMPEQ_USSS = 5813, I_VCMPFALSEPD = 5243, I_VCMPFALSEPS = 4841, I_VCMPFALSESD = 6047,
    I_VCMPFALSESS = 5645, I_VCMPFALSE_OSPD = 5452, I_VCMPFALSE_OSPS = 5050, I_VCMPFALSE_OSSD = 6256,
    I_VCMPFALSE_OSSS = 5854, I_VCMPGEPD = 5270, I_VCMPGEPS = 4868, I_VCMPGESD = 6074,
    I_VCMPGESS = 5672, I_VCMPGE_OQPD = 5482, I_VCMPGE_OQPS = 5080, I_VCMPGE_OQSD = 6286,
    I_VCMPGE_OQSS = 5884, I_VCMPGTPD = 5280, I_VCMPGTPS = 4878, I_VCMPGTSD = 6084,
    I_VCMPGTSS = 5682, I_VCMPGT_OQPD = 5495, I_VCMPGT_OQPS = 5093, I_VCMPGT_OQSD = 6299,
    I_VCMPGT_OQSS = 5897, I_VCMPLEPD = 5141, I_VCMPLEPS = 4739, I_VCMPLESD = 5945,
    I_VCMPLESS = 5543, I_VCMPLE_OQPD = 5328, I_VCMPLE_OQPS = 4926, I_VCMPLE_OQSD = 6132,
    I_VCMPLE_OQSS = 5730, I_VCMPLTPD = 5131, I_VCMPLTPS = 4729, I_VCMPLTSD = 5935,
    I_VCMPLTSS = 5533, I_VCMPLT_OQPD = 5315, I_VCMPLT_OQPS = 4913, I_VCMPLT_OQSD = 6119,
    I_VCMPLT_OQSS = 5717, I_VCMPNEQPD = 5164, I_VCMPNEQPS = 4762, I_VCMPNEQSD = 5968,
    I_VCMPNEQSS = 5566, I_VCMPNEQ_OQPD = 5256, I_VCMPNEQ_OQPS = 4854, I_VCMPNEQ_OQSD = 6060,
    I_VCMPNEQ_OQSS = 5658, I_VCMPNEQ_OSPD = 5468, I_VCMPNEQ_OSPS = 5066, I_VCMPNEQ_OSSD = 6272,
    I_VCMPNEQ_OSSS = 5870, I_VCMPNEQ_USPD = 5356, I_VCMPNEQ_USPS = 4954, I_VCMPNEQ_USSD = 6160,
    I_VCMPNEQ_USSS = 5758, I_VCMPNGEPD = 5221, I_VCMPNGEPS = 4819, I_VCMPNGESD = 6025,
    I_VCMPNGESS = 5623, I_VCMPNGE_UQPD = 5424, I_VCMPNGE_UQPS = 5022, I_VCMPNGE_UQSD = 6228,
    I_VCMPNGE_UQSS = 5826, I_VCMPNGTPD = 5232, I_VCMPNGTPS = 4830, I_VCMPNGTSD = 6036,
    I_VCMPNGTSS = 5634, I_VCMPNGT_UQPD = 5438, I_VCMPNGT_UQPS = 5036, I_VCMPNGT_UQSD = 6242,
    I_VCMPNGT_UQSS = 5840, I_VCMPNLEPD = 5186, I_VCMPNLEPS = 4784, I_VCMPNLESD = 5990,
    I_VCMPNLESS = 5588, I_VCMPNLE_UQPD = 5384, I_VCMPNLE_UQPS = 4982, I_VCMPNLE_UQSD = 6188,
    I_VCMPNLE_UQSS = 5786, I_VCMPNLTPD = 5175, I_VCMPNLTPS = 4773, I_VCMPNLTSD = 5979,
    I_VCMPNLTSS = 5577, I_VCMPNLT_UQPD = 5370, I_VCMPNLT_UQPS = 4968, I_VCMPNLT_UQSD = 6174,
    I_VCMPNLT_UQSS = 5772, I_VCMPORDPD = 5197, I_VCMPORDPS = 4795, I_VCMPORDSD = 6001,
    I_VCMPORDSS = 5599, I_VCMPORD_SPD = 5398, I_VCMPORD_SPS = 4996, I_VCMPORD_SSD = 6202,
    I_VCMPORD_SSS = 5800, I_VCMPTRUEPD = 5290, I_VCMPTRUEPS = 4888, I_VCMPTRUESD = 6094,
    I_VCMPTRUESS = 5692, I_VCMPTRUE_USPD = 5508, I_VCMPTRUE_USPS = 5106, I_VCMPTRUE_USSD = 6312,
    I_VCMPTRUE_USSS = 5910, I_VCMPUNORDPD = 5151, I_VCMPUNORDPS = 4749, I_VCMPUNORDSD = 5955,
    I_VCMPUNORDSS = 5553, I_VCMPUNORD_SPD = 5341, I_VCMPUNORD_SPS = 4939, I_VCMPUNORD_SSD = 6145,
    I_VCMPUNORD_SSS = 5743, I_VCOMISD = 2829, I_VCOMISS = 2820, I_VCVTDQ2PD = 6852,
    I_VCVTDQ2PS = 3371, I_VCVTPD2DQ = 6863, I_VCVTPD2PS = 3307, I_VCVTPS2DQ = 3382,
    I_VCVTPS2PD = 3296, I_VCVTSD2SI = 2755, I_VCVTSD2SS = 3329, I_VCVTSI2SD = 2569,
    I_VCVTSI2SS = 2558, I_VCVTSS2SD = 3318, I_VCVTSS2SI = 2744, I_VCVTTPD2DQ = 6840,
    I_VCVTTPS2DQ = 3393, I_VCVTTSD2SI = 2692, I_VCVTTSS2SI = 2680, I_VDIVPD = 3561,
    I_VDIVPS = 3553, I_VDIVSD = 3577, I_VDIVSS = 3569, I_VDPPD = 9654, I_VDPPS = 9641,
    I_VERR = 1678, I_VERW = 1684, I_VEXTRACTF128 = 9549, I_VEXTRACTPS = 9524,
    I_VFMADD132PD = 8420, I_VFMADD132PS = 8407, I_VFMADD132SD = 8446, I_VFMADD132SS = 8433,
    I_VFMADD213PD = 8700, I_VFMADD213PS = 8687, I_VFMADD213SD = 8726, I_VFMADD213SS = 8713,
    I_VFMADD231PD = 8980, I_VFMADD231PS = 8967, I_VFMADD231SD = 9006, I_VFMADD231SS = 8993,
    I_VFMADDSUB132PD = 8359, I_VFMADDSUB132PS = 8343, I_VFMADDSUB213PD = 8639,
    I_VFMADDSUB213PS = 8623, I_VFMADDSUB231PD = 8919, I_VFMADDSUB231PS = 8903,
    I_VFMSUB132PD = 8472, I_VFMSUB132PS = 8459, I_VFMSUB132SD = 8498, I_VFMSUB132SS = 8485,
    I_VFMSUB213PD = 8752, I_VFMSUB213PS = 8739, I_VFMSUB213SD = 8778, I_VFMSUB213SS = 8765,
    I_VFMSUB231PD = 9032, I_VFMSUB231PS = 9019, I_VFMSUB231SD = 9058, I_VFMSUB231SS = 9045,
    I_VFMSUBADD132PD = 8391, I_VFMSUBADD132PS = 8375, I_VFMSUBADD213PD = 8671,
    I_VFMSUBADD213PS = 8655, I_VFMSUBADD231PD = 8951, I_VFMSUBADD231PS = 8935,
    I_VFNMADD132PD = 8525, I_VFNMADD132PS = 8511, I_VFNMADD132SD = 8553, I_VFNMADD132SS = 8539,
    I_VFNMADD213PD = 8805, I_VFNMADD213PS = 8791, I_VFNMADD213SD = 8833, I_VFNMADD213SS = 8819,
    I_VFNMADD231PD = 9085, I_VFNMADD231PS = 9071, I_VFNMADD231SD = 9113, I_VFNMADD231SS = 9099,
    I_VFNMSUB132PD = 8581, I_VFNMSUB132PS = 8567, I_VFNMSUB132SD = 8609, I_VFNMSUB132SS = 8595,
    I_VFNMSUB213PD = 8861, I_VFNMSUB213PS = 8847, I_VFNMSUB213SD = 8889, I_VFNMSUB213SS = 8875,
    I_VFNMSUB231PD = 9141, I_VFNMSUB231PS = 9127, I_VFNMSUB231SD = 9169, I_VFNMSUB231SS = 9155,
    I_VHADDPD = 4230, I_VHADDPS = 4239, I_VHSUBPD = 4264, I_VHSUBPS = 4273, I_VINSERTF128 = 9536,
    I_VINSERTPS = 9590, I_VLDDQU = 7034, I_VLDMXCSR = 9974, I_VMASKMOVDQU = 7164,
    I_VMASKMOVPD = 7982, I_VMASKMOVPS = 7970, I_VMAXPD = 3621, I_VMAXPS = 3613,
    I_VMAXSD = 3637, I_VMAXSS = 3629, I_VMCALL = 1734, I_VMCLEAR = 10022, I_VMFUNC = 1814,
    I_VMINPD = 3501, I_VMINPS = 3493, I_VMINSD = 3517, I_VMINSS = 3509, I_VMLAUNCH = 1742,
    I_VMLOAD = 1844, I_VMMCALL = 1835, I_VMOVAPD = 2509, I_VMOVAPS = 2500, I_VMOVD = 3965,
    I_VMOVDDUP = 2267, I_VMOVDQA = 3995, I_VMOVDQU = 4004, I_VMOVHLPS = 2228,
    I_VMOVHPD = 2415, I_VMOVHPS = 2406, I_VMOVLHPS = 2396, I_VMOVLPD = 2247, I_VMOVLPS = 2238,
    I_VMOVMSKPD = 2869, I_VMOVMSKPS = 2858, I_VMOVNTDQ = 6891, I_VMOVNTDQA = 7938,
    I_VMOVNTPD = 2626, I_VMOVNTPS = 2616, I_VMOVQ = 3972, I_VMOVSD = 2176, I_VMOVSHDUP = 2424,
    I_VMOVSLDUP = 2256, I_VMOVSS = 2168, I_VMOVUPD = 2159, I_VMOVUPS = 2150, I_VMPSADBW = 9670,
    I_VMPTRLD = 10013, I_VMPTRST = 6418, I_VMREAD = 4161, I_VMRESUME = 1752, I_VMRUN = 1828,
    I_VMSAVE = 1852, I_VMULPD = 3232, I_VMULPS = 3224, I_VMULSD = 3248, I_VMULSS = 3240,
    I_VMWRITE = 4185, I_VMXOFF = 1762, I_VMXON = 10031, I_VORPD = 3099, I_VORPS = 3092,
    I_VPABSB = 7728, I_VPABSD = 7758, I_VPABSW = 7743, I_VPACKSSDW = 3892, I_VPACKSSWB = 3724,
    I_VPACKUSDW = 7959, I_VPACKUSWB = 3802, I_VPADDB = 7244, I_VPADDD = 7274,
    I_VPADDQ = 6521, I_VPADDSB = 6971, I_VPADDSW = 6988, I_VPADDUSW = 6662, I_VPADDW = 7259,
    I_VPALIGNR = 9452, I_VPAND = 6646, I_VPANDN = 6705, I_VPAVGB = 6720, I_VPAVGW = 6765,
    I_VPBLENDVB = 9725, I_VPBLENDW = 9433, I_VPCLMULQDQ = 9691, I_VPCMPEQB = 4085,
    I_VPCMPEQD = 4123, I_VPCMPEQQ = 7918, I_VPCMPEQW = 4104, I_VPCMPESTRI = 9770,
    I_VPCMPESTRM = 9747, I_VPCMPGTB = 3744, I_VPCMPGTD = 3782, I_VPCMPGTQ = 8129,
    I_VPCMPGTW = 3763, I_VPCMPISTRI = 9816, I_VPCMPISTRM = 9793, I_VPERM2F128 = 9298,
    I_VPERMILPD = 7603, I_VPERMILPS = 7592, I_VPEXTRB = 9470, I_VPEXTRD = 9495,
    I_VPEXTRQ = 9504, I_VPEXTRW = 6352, I_VPHADDD = 7416, I_VPHADDSW = 7434, I_VPHADDW = 7399,
    I_VPHMINPOSUW = 8304, I_VPHSUBD = 7492, I_VPHSUBSW = 7510, I_VPHSUBW = 7475,
    I_VPINSRB = 9571, I_VPINSRD = 9617, I_VPINSRQ = 9626, I_VPINSRW = 6335, I_VPMADDUBSW = 7455,
    I_VPMADDWD = 7115, I_VPMAXSB = 8215, I_VPMAXSD = 8232, I_VPMAXSW = 7005, I_VPMAXUB = 6689,
    I_VPMAXUD = 8266, I_VPMAXUW = 8249, I_VPMINSB = 8147, I_VPMINSD = 8164, I_VPMINSW = 6943,
    I_VPMINUB = 6631, I_VPMINUD = 8198, I_VPMINUW = 8181, I_VPMOVMSKB = 6574,
    I_VPMOVSXBD = 7797, I_VPMOVSXBQ = 7818, I_VPMOVSXBW = 7776, I_VPMOVSXDQ = 7881,
    I_VPMOVSXWD = 7839, I_VPMOVSXWQ = 7860, I_VPMOVZXBD = 8025, I_VPMOVZXBQ = 8046,
    I_VPMOVZXBW = 8004, I_VPMOVZXDQ = 8109, I_VPMOVZXWD = 8067, I_VPMOVZXWQ = 8088,
    I_VPMULDQ = 7900, I_VPMULHRSW = 7581, I_VPMULHUW = 6782, I_VPMULHW = 6800,
    I_VPMULLD = 8283, I_VPMULLW = 6537, I_VPMULUDQ = 7096, I_VPOR = 6957, I_VPSADBW = 7133,
    I_VPSHUFB = 7382, I_VPSHUFD = 4047, I_VPSHUFHW = 4056, I_VPSHUFLW = 4066,
    I_VPSIGNB = 7528, I_VPSIGND = 7562, I_VPSIGNW = 7545, I_VPSLLD = 7064, I_VPSLLDQ = 9888,
    I_VPSLLQ = 7079, I_VPSLLW = 7049, I_VPSRAD = 6750, I_VPSRAW = 6735, I_VPSRLD = 6491,
    I_VPSRLDQ = 9871, I_VPSRLQ = 6506, I_VPSRLW = 6476, I_VPSUBB = 7184, I_VPSUBD = 7214,
    I_VPSUBQ = 7229, I_VPSUBSB = 6909, I_VPSUBSW = 6926, I_VPSUBUSB = 6594, I_VPSUBUSW = 6613,
    I_VPSUBW = 7199, I_VPTEST = 7669, I_VPUNPCKHBW = 3824, I_VPUNPCKHDQ = 3870,
    I_VPUNPCKHQDQ = 3940, I_VPUNPCKHWD = 3847, I_VPUNPCKLBW = 3656, I_VPUNPCKLDQ = 3702,
    I_VPUNPCKLQDQ = 3915, I_VPUNPCKLWD = 3679, I_VPXOR = 7020, I_VRCPPS = 3000,
    I_VRCPSS = 3008, I_VROUNDPD = 9338, I_VROUNDPS = 9319, I_VROUNDSD = 9376,
    I_VROUNDSS = 9357, I_VRSQRTPS = 2966, I_VRSQRTSS = 2976, I_VSHUFPD = 6386,
    I_VSHUFPS = 6377, I_VSQRTPD = 2921, I_VSQRTPS = 2912, I_VSQRTSD = 2939, I_VSQRTSS = 2930,
    I_VSTMXCSR = 10003, I_VSUBPD = 3441, I_VSUBPS = 3433, I_VSUBSD = 3457, I_VSUBSS = 3449,
    I_VTESTPD = 7623, I_VTESTPS = 7614, I_VUCOMISD = 2794, I_VUCOMISS = 2784,
    I_VUNPCKHPD = 2350, I_VUNPCKHPS = 2339, I_VUNPCKLPD = 2308, I_VUNPCKLPS = 2297,
    I_VXORPD = 3128, I_VXORPS = 3120, I_VZEROALL = 4151, I_VZEROUPPER = 4139,
    I_WAIT = 10053, I_WBINVD = 560, I_WRFSBASE = 9964, I_WRGSBASE = 9993, I_WRMSR = 585,
    I_XABORT = 1006, I_XADD = 945, I_XBEGIN = 1014, I_XCHG = 212, I_XEND = 1822,
    I_XGETBV = 1798, I_XLAT = 399, I_XOR = 61, I_XORPD = 3113, I_XORPS = 3106,
    I_XRSTOR = 4306, I_XRSTOR64 = 4314, I_XSAVE = 4282, I_XSAVE64 = 4289, I_XSAVEOPT = 4332,
    I_XSAVEOPT64 = 4342, I_XSETBV = 1806, I__3DNOW = 10067
  );

  _RegisterType = (
    R_RAX, R_RCX, R_RDX, R_RBX, R_RSP, R_RBP, R_RSI, R_RDI, R_R8, R_R9, R_R10, R_R11, R_R12, R_R13, R_R14, R_R15,
    R_EAX, R_ECX, R_EDX, R_EBX, R_ESP, R_EBP, R_ESI, R_EDI, R_R8D, R_R9D, R_R10D, R_R11D, R_R12D, R_R13D, R_R14D, R_R15D,
    R_AX, R_CX, R_DX, R_BX, R_SP, R_BP, R_SI, R_DI, R_R8W, R_R9W, R_R10W, R_R11W, R_R12W, R_R13W, R_R14W, R_R15W,
    R_AL, R_CL, R_DL, R_BL, R_AH, R_CH, R_DH, R_BH, R_R8B, R_R9B, R_R10B, R_R11B, R_R12B, R_R13B, R_R14B, R_R15B,
    R_SPL, R_BPL, R_SIL, R_DIL,
    R_ES, R_CS, R_SS, R_DS, R_FS, R_GS,
    R_RIP,
    R_ST0, R_ST1, R_ST2, R_ST3, R_ST4, R_ST5, R_ST6, R_ST7,
    R_MM0, R_MM1, R_MM2, R_MM3, R_MM4, R_MM5, R_MM6, R_MM7,
    R_XMM0, R_XMM1, R_XMM2, R_XMM3, R_XMM4, R_XMM5, R_XMM6, R_XMM7, R_XMM8, R_XMM9, R_XMM10, R_XMM11, R_XMM12, R_XMM13, R_XMM14, R_XMM15,
    R_YMM0, R_YMM1, R_YMM2, R_YMM3, R_YMM4, R_YMM5, R_YMM6, R_YMM7, R_YMM8, R_YMM9, R_YMM10, R_YMM11, R_YMM12, R_YMM13, R_YMM14, R_YMM15,
    R_CR0, R_UNUSED0, R_CR2, R_CR3, R_CR4, R_UNUSED1, R_UNUSED2, R_UNUSED3, R_CR8,
    R_DR0, R_DR1, R_DR2, R_DR3, R_UNUSED4, R_UNUSED5, R_DR6, R_DR7
  );

type
  PMnemonic = ^_WMnemonic;
  _WMnemonic = record
  	length: UInt8;
	  p: array [0..0] of UChar; // p is a null terminated string, which contains 'length' characters.
  end;
  WMnemonic = _WMnemonic;

  PRegister = ^_WRegister;
  _WRegister = record
  	length: UInt32;
	  p: array [0..5] of UChar; // p is a null terminated string.
  end;
  WRegister = _WRegister;

  function GET_REGISTER_NAME(r: _RegisterType): string;
  function GET_MNEMONIC_NAME(m: _InstructionType): string;

implementation

{$IFDEF WIN32}
  procedure __MNEMONICS; external;
  procedure __REGISTERS; external;
{$ELSE}
  procedure _MNEMONICS; external;
  procedure _REGISTERS; external;
{$ENDIF}

function _GET_REGISTER_TABLE: PRegister;
asm
  {$IFDEF WIN32}
  lea eax, __REGISTERS
  {$ELSE}
  lea rax, _REGISTERS
  {$ENDIF}
end;

function GET_REGISTER_NAME(r: _RegisterType): string;
var
  reg: PRegister;
begin
  reg := _GET_REGISTER_TABLE;
  Inc(reg, Integer(r));
  Result := string(PAnsiChar(@(reg^).p[0]));
end;

function _GET_MNEMONIC_TABLE: PByte;
asm
  {$IFDEF WIN32}
  lea eax, __MNEMONICS
  {$ELSE}
  lea rax, _MNEMONICS
  {$ENDIF}
end;

function GET_MNEMONIC_NAME(m: _InstructionType): string;
var
  mnemonic: PMnemonic;
begin
  mnemonic := PMnemonic(_GET_MNEMONIC_TABLE + Integer(m));
  Result := string(PAnsiChar(@(mnemonic^).p[0]));
end;

end.
