////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Project   : ProcessMM
//  * Unit Name : RawScanner.CoffDwarf.pas
//  * Purpose   : Декларация типов используемых для чтения отладочной
//  *           : информации в форматах COFF и DWARF.
//  * Author    : Александр (Rouse_) Багель
//  * Copyright : © Fangorn Wizards Lab 1998 - 2024.
//  * Version   : 1.1.24
//  * Home Page : http://rouse.drkb.ru
//  * Home Blog : http://alexander-bagel.blogspot.ru
//  ****************************************************************************
//  * Stable Release : http://rouse.drkb.ru/winapi.php#pmm2
//  * Latest Source  : https://github.com/AlexanderBagel/ProcessMemoryMap
//  ****************************************************************************
//

// https://www.singlix.org/trdos/archive/OSDev_Wiki/pecoff_v83.pdf
// https://dwarfstd.org/doc/dwarf_1_1_0.pdf
// https://dwarfstd.org/doc/dwarf-2.0.0.pdf
// https://dwarfstd.org/doc/Dwarf3.pdf
// https://dwarfstd.org/doc/DWARF4.pdf
// https://dwarfstd.org/doc/DWARF5.pdf
// https://llvm.org/
// https://drh.github.io/lcc/
// https://web.archive.org/web/20140605053710/http://www.ibm.com/developerworks/library/os-debugging/os-debugging-pdf.pdf
// http://sourceware.org/gdb/onlinedocs/stabs.html

unit RawScanner.CoffDwarf;

interface

{-$define debug_dump}
{$define debug_offset}

  {$I rawscanner.inc}

uses
  Windows,
  Classes,
  SysUtils,
  Math,
  AnsiStrings,
  {$IFDEF USE_PROFILING}
  Diagnostics,
  {$ENDIF}
  Generics.Collections,
  RawScanner.Types,
  RawScanner.SymbolStorage;

const
  Header64Magic: DWORD = DWORD(-1);

  // Table 7.25: Line number standard opcode encodings
  DW_LNS_copy                     = $01;
  DW_LNS_advance_pc               = $02;
  DW_LNS_advance_line             = $03;
  DW_LNS_set_file                 = $04;
  DW_LNS_set_column               = $05;
  DW_LNS_negate_stmt              = $06;
  DW_LNS_set_basic_block          = $07;
  DW_LNS_const_add_pc             = $08;
  DW_LNS_fixed_advance_pc         = $09;
  DW_LNS_set_prologue_end         = $0a;
  DW_LNS_set_epilogue_begin       = $0b;
  DW_LNS_set_isa                  = $0c;

  // Table 7.26: Line number extended opcode encodings
  DW_LNE_end_sequence             = $01;
  DW_LNE_set_address              = $02;
  DW_LNE_define_file              = $03; // not used in DWARF 5 - Reserved
  DW_LNE_set_discriminator        = $04; // DWARF 4-5

  // Table 7.27: Line number header entry format encodings
  // DWARF 5 only!
  DW_LNCT_path                    = $01;
  DW_LNCT_directory_index         = $02;
  DW_LNCT_timestamp               = $03;
  DW_LNCT_size                    = $04;
  DW_LNCT_MD5                     = $05;

  // Table 7.3: Tag encodings
  DW_TAG_invalid                  = $00;
  DW_TAG_array_type               = $01;
  DW_TAG_class_type               = $02;
  DW_TAG_entry_point              = $03;
  DW_TAG_enumeration_type         = $04;
  DW_TAG_formal_parameter         = $05;
  DW_TAG_reserved_6               = $06;
  DW_TAG_reserved_7               = $07;
  DW_TAG_imported_declaration     = $08;
  DW_TAG_reserved_9               = $09;
  DW_TAG_label                    = $0a;
  DW_TAG_lexical_block            = $0b;
  DW_TAG_reserved_c               = $0c;
  DW_TAG_member                   = $0d;
  DW_TAG_reserved_e               = $0e;
  DW_TAG_pointer_type             = $0f;
  DW_TAG_reference_type           = $10;
  DW_TAG_compile_unit             = $11;
  DW_TAG_string_type              = $12;
  DW_TAG_structure_type           = $13;
  DW_TAG_reserved_14              = $14;
  DW_TAG_subroutine_type          = $15;
  DW_TAG_typedef                  = $16;
  DW_TAG_union_type               = $17;
  DW_TAG_unspecified_parameters   = $18;
  DW_TAG_variant                  = $19;
  DW_TAG_common_block             = $1a;
  DW_TAG_common_inclusion         = $1b;
  DW_TAG_inheritance              = $1c;
  DW_TAG_inlined_subroutine       = $1d;
  DW_TAG_module                   = $1e;
  DW_TAG_ptr_to_member_type       = $1f;
  DW_TAG_set_type                 = $20;
  DW_TAG_subrange_type            = $21;
  DW_TAG_with_stmt                = $22;
  DW_TAG_access_declaration       = $23;
  DW_TAG_base_type                = $24;
  DW_TAG_catch_block              = $25;
  DW_TAG_const_type               = $26;
  DW_TAG_constant                 = $27;
  DW_TAG_enumerator               = $28;
  DW_TAG_file_type                = $29;
  DW_TAG_friend                   = $2a;
  DW_TAG_namelist                 = $2b;
  DW_TAG_namelist_item            = $2c;
  DW_TAG_packed_type              = $2d;
  DW_TAG_subprogram               = $2e;
  DW_TAG_template_type_parameter  = $2f;
  DW_TAG_template_value_parameter = $30;
  DW_TAG_thrown_type              = $31;
  DW_TAG_try_block                = $32;
  DW_TAG_variant_part             = $33;
  DW_TAG_variable                 = $34;
  DW_TAG_volatile_type            = $35;
  // ---- DWARF 3 ----
  DW_TAG_dwarf_procedure          = $36;
  DW_TAG_restrict_type            = $37;
  DW_TAG_interface_type           = $38;
  DW_TAG_namespace                = $39;
  DW_TAG_imported_module          = $3a;
  DW_TAG_unspecified_type         = $3b;
  DW_TAG_partial_unit             = $3c;
  DW_TAG_imported_unit            = $3d;
  DW_TAG_reserved_3e              = $3e;
  DW_TAG_condition                = $3f;
  DW_TAG_shared_type              = $40;
  // ---- DWARF 4 ----
  DW_TAG_type_unit                = $41;
  DW_TAG_rvalue_reference_type    = $42;
  DW_TAG_template_alias           = $43;
  // ---- DWARF 5 ----
  DW_TAG_coarray_type             = $44;
  DW_TAG_generic_subrange         = $45;
  DW_TAG_dynamic_type             = $46;
  DW_TAG_atomic_type              = $47;
  DW_TAG_call_site                = $48;
  DW_TAG_call_site_parameter      = $49;
  DW_TAG_skeleton_unit            = $4a;
  DW_TAG_immutable_type           = $4b;

  // Table 7.6: Attribute form encodings
  DW_FORM_addr                    = $01;    // address
  DW_FORM_reserved_2              = $02;
  DW_FORM_block2                  = $03;    // block
  DW_FORM_block4                  = $04;    // block
  DW_FORM_data2                   = $05;    // constant
  DW_FORM_data4                   = $06;    // constant, lineptr, loclistptr, macptr, rangelistptr
  DW_FORM_data8                   = $07;    // constant, lineptr, loclistptr, macptr, rangelistptr
  DW_FORM_string                  = $08;    // string
  DW_FORM_block                   = $09;    // block
  DW_FORM_block1                  = $0a;    // block
  DW_FORM_data1                   = $0b;    // constant
  DW_FORM_flag                    = $0c;    // flag
  DW_FORM_sdata                   = $0d;    // constant
  DW_FORM_strp                    = $0e;    // string
  DW_FORM_udata                   = $0f;    // constant
  DW_FORM_ref_addr                = $10;    // reference
  DW_FORM_ref1                    = $11;    // reference
  DW_FORM_ref2                    = $12;    // reference
  DW_FORM_ref4                    = $13;    // reference
  DW_FORM_ref8                    = $14;    // reference
  DW_FORM_ref_udata               = $15;    // reference
  DW_FORM_indirect                = $16;    // (see Section 7.5.3)
  // ---- DWARF 4 ----
  DW_FORM_sec_offset              = $17;    // lineptr, loclistptr, macptr, rangelistptr
  DW_FORM_exprloc                 = $18;    // exprloc
  DW_FORM_flag_present            = $19;    // flag
  DW_FORM_ref_sig8                = $20;    // reference
  // ---- DWARF 5 ----
  DW_FORM_strx                    = $1a;    // string
  DW_FORM_addrx                   = $1b;    // address
  DW_FORM_ref_sup4                = $1c;    // reference
  DW_FORM_strp_sup                = $1d;    // string
  DW_FORM_data16                  = $1e;    // constant
  DW_FORM_line_strp               = $1f;    // string
  DW_FORM_implicit_const          = $21;    // constant
  DW_FORM_loclistx                = $22;    // loclist
  DW_FORM_rnglistx                = $23;    // rnglist
  DW_FORM_ref_sup8                = $24;    // reference
  DW_FORM_strx1                   = $25;    // string
  DW_FORM_strx2                   = $26;    // string
  DW_FORM_strx3                   = $27;    // string
  DW_FORM_strx4                   = $28;    // string
  DW_FORM_addrx1                  = $29;    // address
  DW_FORM_addrx2                  = $2a;    // address
  DW_FORM_addrx3                  = $2b;    // address
  DW_FORM_addrx4                  = $2c;    // address
  // ---- Alternative debug info at .gnu_debugaltlink
  DW_FORM_GNU_addr_index          = $1F01;
  DW_FORM_GNU_str_index           = $1F02;
  DW_FORM_GNU_ref_alt             = $1F20;
  DW_FORM_GNU_strp_alt            = $1F21;

  // Table 7.9: DWARF operation encodings
  DW_OP_reserved0                 = $00;    // - reserved
  DW_OP_reserved1                 = $01;    // - reserved
  DW_OP_reserved2                 = $02;    // - reserved
  DW_OP_addr                      = $03;    // 1 constant address (size target specific)
  DW_OP_reserved4                 = $04;    // - reserved
  DW_OP_reserved5                 = $05;    // - reserved
  DW_OP_deref                     = $06;    // 0
  DW_OP_reserved7                 = $07;    // - reserved
  DW_OP_const1u                   = $08;    // 1 1-byte constant
  DW_OP_const1s                   = $09;    // 1 1-byte constant
  DW_OP_const2u                   = $0a;    // 1 2-byte constant
  DW_OP_const2s                   = $0b;    // 1 2-byte constant
  DW_OP_const4u                   = $0c;    // 1 4-byte constant
  DW_OP_const4s                   = $0d;    // 1 4-byte constant
  DW_OP_const8u                   = $0e;    // 1 8-byte constant
  DW_OP_const8s                   = $0f;    // 1 8-byte constant
  DW_OP_constu                    = $10;    // 1 ULEB128 constant
  DW_OP_consts                    = $11;    // 1 SLEB128 constant
  DW_OP_dup                       = $12;    // 0
  DW_OP_drop                      = $13;    // 0
  DW_OP_over                      = $14;    // 0
  DW_OP_pick                      = $15;    // 1 1-byte stack index
  DW_OP_swap                      = $16;    // 0
  DW_OP_rot                       = $17;    // 0
  DW_OP_xderef                    = $18;    // 0
  DW_OP_abs                       = $19;    // 0
  DW_OP_and                       = $1a;    // 0
  DW_OP_div                       = $1b;    // 0
  DW_OP_minus                     = $1c;    // 0
  DW_OP_mod                       = $1d;    // 0
  DW_OP_mul                       = $1e;    // 0
  DW_OP_neg                       = $1f;    // 0
  DW_OP_not                       = $20;    // 0
  DW_OP_or                        = $21;    // 0
  DW_OP_plus                      = $22;    // 0
  DW_OP_plus_uconst               = $23;    // 1 ULEB128 addend
  DW_OP_shl                       = $24;    // 0
  DW_OP_shr                       = $25;    // 0
  DW_OP_shra                      = $26;    // 0
  DW_OP_xor                       = $27;    // 0
  DW_OP_bra                       = $28;    // 1 signed 2-byte constant
  DW_OP_eq                        = $29;    // 0
  DW_OP_ge                        = $2a;    // 0
  DW_OP_gt                        = $2b;    // 0
  DW_OP_le                        = $2c;    // 0
  DW_OP_lt                        = $2d;    // 0
  DW_OP_ne                        = $2e;    // 0
  DW_OP_skip                      = $2f;    // 1 signed 2-byte constant
  DW_OP_lit0                      = $30;    // 0 literals 0..31 = (DW_OP_lit0 + literal)
  DW_OP_lit1                      = $31;    // 0
  DW_OP_lit2                      = $32;    // 0
  DW_OP_lit3                      = $33;    // 0
  DW_OP_lit4                      = $34;    // 0
  DW_OP_lit5                      = $35;    // 0
  DW_OP_lit6                      = $36;    // 0
  DW_OP_lit7                      = $37;    // 0
  DW_OP_lit8                      = $38;    // 0
  DW_OP_lit9                      = $39;    // 0
  DW_OP_lit10                     = $3a;    // 0
  DW_OP_lit11                     = $3b;    // 0
  DW_OP_lit12                     = $3c;    // 0
  DW_OP_lit13                     = $3d;    // 0
  DW_OP_lit14                     = $3e;    // 0
  DW_OP_lit15                     = $3f;    // 0
  DW_OP_lit16                     = $40;    // 0
  DW_OP_lit17                     = $41;    // 0
  DW_OP_lit18                     = $42;    // 0
  DW_OP_lit19                     = $43;    // 0
  DW_OP_lit20                     = $44;    // 0
  DW_OP_lit21                     = $45;    // 0
  DW_OP_lit22                     = $46;    // 0
  DW_OP_lit23                     = $47;    // 0
  DW_OP_lit24                     = $48;    // 0
  DW_OP_lit25                     = $49;    // 0
  DW_OP_lit26                     = $4a;    // 0
  DW_OP_lit27                     = $4b;    // 0
  DW_OP_lit28                     = $4c;    // 0
  DW_OP_lit29                     = $4d;    // 0
  DW_OP_lit30                     = $4e;    // 0
  DW_OP_lit31                     = $4f;    // 0
  DW_OP_reg0                      = $50;    // 0 reg 0..31 = (DW_OP_reg0 + regnum)
  DW_OP_reg1                      = $51;    // 0
  DW_OP_reg2                      = $52;    // 0
  DW_OP_reg3                      = $53;    // 0
  DW_OP_reg4                      = $54;    // 0
  DW_OP_reg5                      = $55;    // 0
  DW_OP_reg6                      = $56;    // 0
  DW_OP_reg7                      = $57;    // 0
  DW_OP_reg8                      = $58;    // 0
  DW_OP_reg9                      = $59;    // 0
  DW_OP_reg10                     = $5a;    // 0
  DW_OP_reg11                     = $5b;    // 0
  DW_OP_reg12                     = $5c;    // 0
  DW_OP_reg13                     = $5d;    // 0
  DW_OP_reg14                     = $5e;    // 0
  DW_OP_reg15                     = $5f;    // 0
  DW_OP_reg16                     = $60;    // 0
  DW_OP_reg17                     = $61;    // 0
  DW_OP_reg18                     = $62;    // 0
  DW_OP_reg19                     = $63;    // 0
  DW_OP_reg20                     = $64;    // 0
  DW_OP_reg21                     = $65;    // 0
  DW_OP_reg22                     = $66;    // 0
  DW_OP_reg23                     = $67;    // 0
  DW_OP_reg24                     = $68;    // 0
  DW_OP_reg25                     = $69;    // 0
  DW_OP_reg26                     = $6a;    // 0
  DW_OP_reg27                     = $6b;    // 0
  DW_OP_reg28                     = $6c;    // 0
  DW_OP_reg29                     = $6d;    // 0
  DW_OP_reg30                     = $6e;    // 0
  DW_OP_reg31                     = $6f;    // 0
  DW_OP_breg0                     = $70;    // 1 SLEB128 offsetbase register 0..31 = (DW_OP_breg0 + regnum)
  DW_OP_breg1                     = $71;    // 1
  DW_OP_breg2                     = $72;    // 1
  DW_OP_breg3                     = $73;    // 1
  DW_OP_breg4                     = $74;    // 1
  DW_OP_breg5                     = $75;    // 1
  DW_OP_breg6                     = $76;    // 1
  DW_OP_breg7                     = $77;    // 1
  DW_OP_breg8                     = $78;    // 1
  DW_OP_breg9                     = $79;    // 1
  DW_OP_breg10                    = $7a;    // 1
  DW_OP_breg11                    = $7b;    // 1
  DW_OP_breg12                    = $7c;    // 1
  DW_OP_breg13                    = $7d;    // 1
  DW_OP_breg14                    = $7e;    // 1
  DW_OP_breg15                    = $7f;    // 1
  DW_OP_breg16                    = $80;    // 1
  DW_OP_breg17                    = $81;    // 1
  DW_OP_breg18                    = $82;    // 1
  DW_OP_breg19                    = $83;    // 1
  DW_OP_breg20                    = $84;    // 1
  DW_OP_breg21                    = $85;    // 1
  DW_OP_breg22                    = $86;    // 1
  DW_OP_breg23                    = $87;    // 1
  DW_OP_breg24                    = $88;    // 1
  DW_OP_breg25                    = $89;    // 1
  DW_OP_breg26                    = $8a;    // 1
  DW_OP_breg27                    = $8b;    // 1
  DW_OP_breg28                    = $8c;    // 1
  DW_OP_breg29                    = $8d;    // 1
  DW_OP_breg30                    = $8e;    // 1
  DW_OP_breg31                    = $8f;    // 1
  DW_OP_regx                      = $90;    // 1 ULEB128 register
  DW_OP_fbreg                     = $91;    // 1 SLEB128 offset
  DW_OP_bregx                     = $92;    // 2 ULEB128 register + SLEB128 offset
  DW_OP_piece                     = $93;    // 1 ULEB128 size of piece addressed
  DW_OP_deref_size                = $94;    // 1 1-byte size of data retrieved
  DW_OP_xderef_size               = $95;    // 1 1-byte size of data retrieved
  DW_OP_nop                       = $96;    // 0
  // ---- DWARF 3 ----
  DW_OP_push_object_address       = $97;    // 0
  DW_OP_call2                     = $98;    // 1 2-byte offset of DIE
  DW_OP_call4                     = $99;    // 1 4-byte offset of DIE
  DW_OP_call_ref                  = $9a;    // 1 4- or 8-byte offset of DIE
  DW_OP_form_tls_address          = $9b;    // 0
  DW_OP_call_frame_cfa            = $9c;    // 0
  DW_OP_bit_piece                 = $9d;    // 2
  // ---- DWARF 4 ----
  DW_OP_implicit_value            = $9e;    // 2 ULEB128 size, block of that size
  DW_OP_stack_value               = $9f;    // 0
  // ---- DWARF 5 ----
  DW_OP_implicit_pointer          = $a0;    // 2 4- or 8-byte offset of DIE, SLEB128 constant offset
  DW_OP_addrx                     = $a1;    // 1 ULEB128 indirect address
  DW_OP_constx                    = $a2;    // 1 ULEB128 indirect constant
  DW_OP_entry_value               = $a3;    // 2 ULEB128 size, block of that size
  DW_OP_const_type                = $a4;    // 3 ULEB128 type entry offset, 1-byte size, constant value
  DW_OP_regval_type               = $a5;    // 2 ULEB128 register number, ULEB128 constant offset
  DW_OP_deref_type                = $a6;    // 2 1-byte size, ULEB128 type entry offset
  DW_OP_xderef_type               = $a7;    // 2 1-byte size, ULEB128 type entry offset
  DW_OP_convert                   = $a8;    // 1 ULEB128 type entry offset
  DW_OP_reinterpret               = $a9;    // 1 ULEB128 type entry offset
  DW_OP_reserved170               = $aa;    // - reserved
  DW_OP_reserved255               = $ff;    // - reserved

  // 7.5.4 Attribute Encodings
  DW_AT_sibling                   = $01;    // reference
  DW_AT_location                  = $02;    // block, loclistptr
  DW_AT_name                      = $03;    // string
  DW_AT_Reserved_04               = $04;
  DW_AT_Reserved_05               = $05;
  DW_AT_Reserved_06               = $06;
  DW_AT_Reserved_07               = $07;
  DW_AT_Reserved_08               = $08;
  DW_AT_ordering                  = $09;    // constant
  DW_AT_Reserved_0a               = $0a;
  DW_AT_byte_size                 = $0b;    // block, constant, reference
  DW_AT_bit_offset                = $0c;    // block, constant, reference
  DW_AT_bit_size                  = $0d;    // block, constant, reference
  DW_AT_Reserved_0e               = $0e;
  DW_AT_Reserved_0f               = $0f;
  DW_AT_stmt_list                 = $10;    // lineptr
  DW_AT_low_pc                    = $11;    // address
  DW_AT_high_pc                   = $12;    // address
  DW_AT_language                  = $13;    // constant
  DW_AT_Reserved_14               = $14;
  DW_AT_discr                     = $15;    // reference
  DW_AT_discr_value               = $16;    // constant
  DW_AT_visibility                = $17;    // constant
  DW_AT_import                    = $18;    // reference
  DW_AT_string_length             = $19;    // block, loclistptr
  DW_AT_common_reference          = $1a;    // reference
  DW_AT_comp_dir                  = $1b;    // string
  DW_AT_const_value               = $1c;    // block, constant, string
  DW_AT_containing_type           = $1d;    // reference
  DW_AT_default_value             = $1e;    // reference
  DW_AT_Reserved_1f               = $1f;
  DW_AT_inline                    = $20;    // constant
  DW_AT_is_optional               = $21;    // flag
  DW_AT_lower_bound               = $22;    // block, constant, reference
  DW_AT_Reserved_23               = $23;
  DW_AT_Reserved_24               = $24;
  DW_AT_producer                  = $25;    // string
  DW_AT_prototyped                = $27;    // flag
  DW_AT_Reserved_28               = $28;
  DW_AT_Reserved_29               = $29;
  DW_AT_return_addr               = $2a;    // block, loclistptr
  DW_AT_Reserved_2b               = $2b;
  DW_AT_start_scope               = $2c;    // constant
  DW_AT_Reserved_2d               = $2d;
  DW_AT_bit_stride                = $2e;    // constant, exprloc, reference
  DW_AT_upper_bound               = $2f;    // constant, exprloc, reference
  DW_AT_Reserved_30               = $30;
  DW_AT_abstract_origin           = $31;    // reference
  DW_AT_accessibility             = $32;    // constant
  DW_AT_address_class             = $33;    // constant
  DW_AT_artificial                = $34;    // flag
  DW_AT_base_types                = $35;    // reference
  {$MESSAGE 'Добавить'}
  DW_AT_calling_convention        = $36;    // constant
  DW_AT_count                     = $37;    // block, constant, reference
  DW_AT_data_member_location      = $38;    // block, constant, loclistptr
  DW_AT_decl_column               = $39;    // constant
  DW_AT_decl_file                 = $3a;    // constant
  DW_AT_decl_line                 = $3b;    // constant
  DW_AT_declaration               = $3c;    // flag
  DW_AT_discr_list                = $3d;    // block
  DW_AT_encoding                  = $3e;    // constant
  DW_AT_external                  = $3f;    // flag
  DW_AT_frame_base                = $40;    // block, loclistptr
  DW_AT_friend                    = $41;    // reference
  DW_AT_identifier_case           = $42;    // constant
  DW_AT_macro_info                = $43;    // macptr
  DW_AT_namelist_item             = $44;    // block
  DW_AT_priority                  = $45;    // reference
  DW_AT_segment                   = $46;    // block, loclistptr
  DW_AT_specification             = $47;    // reference
  DW_AT_static_link               = $48;    // block, loclistptr
  DW_AT_type                      = $49;    // reference
  DW_AT_use_location              = $4a;    // block, loclistptr
  DW_AT_variable_parameter        = $4b;    // flag
  DW_AT_virtuality                = $4c;    // constant
  DW_AT_vtable_elem_location      = $4d;    // block, loclistptr
  // ---- DWARF 3 ----
  DW_AT_allocated                 = $4e;    // block, constant, reference
  DW_AT_associated                = $4f;    // block, constant, reference
  DW_AT_data_location             = $50;    // block
  DW_AT_byte_stride               = $51;    // block, constant, reference
  DW_AT_entry_pc                  = $52;    // address
  DW_AT_use_UTF8                  = $53;    // flag
  DW_AT_extension                 = $54;    // reference
  DW_AT_ranges                    = $55;    // rangelistptr
  DW_AT_trampoline                = $56;    // address, flag, reference, string
  DW_AT_call_column               = $57;    // constant
  DW_AT_call_file                 = $58;    // constant
  DW_AT_call_line                 = $59;    // constant
  DW_AT_description               = $5a;    // string
  DW_AT_binary_scale              = $5b;    // constant
  DW_AT_decimal_scale             = $5c;    // constant
  DW_AT_small                     = $5d;    // reference
  DW_AT_decimal_sign              = $5e;    // constant
  DW_AT_digit_count               = $5f;    // constant
  DW_AT_picture_string            = $60;    // string
  DW_AT_mutable                   = $61;    // flag
  DW_AT_threads_scaled            = $62;    // flag
  DW_AT_explicit                  = $63;    // flag
  DW_AT_object_pointer            = $64;    // reference
  DW_AT_endianity                 = $65;    // constant
  DW_AT_elemental                 = $66;    // flag
  DW_AT_pure                      = $67;    // flag
  DW_AT_recursive                 = $68;    // flag
  // ---- DWARF 4 ----
  DW_AT_signature                 = $69;    // reference
  DW_AT_main_subprogram           = $6a;    // flag
  DW_AT_data_bit_offset           = $6b;    // constant
  DW_AT_const_expr                = $6c;    // flag
  DW_AT_enum_class                = $6d;    // flag
  DW_AT_linkage_name              = $6e;    // string
  // ---- DWARF 5 ----
  DW_AT_string_length_bit_size    = $6f;    // constant
  DW_AT_string_length_byte_size   = $70;    // constant
  DW_AT_rank                      = $71;    // constant, exprloc
  DW_AT_str_offsets_base          = $72;    // stroffsetsptr
  DW_AT_addr_base                 = $73;    // addrptr
  DW_AT_rnglists_base             = $74;    // rnglistsptr
  DW_AT_Reserved_75               = $75;
  DW_AT_dwo_name                  = $76;    // string
  DW_AT_reference                 = $77;    // flag
  DW_AT_rvalue_reference          = $78;    // flag
  DW_AT_macros                    = $79;    // macptr
  DW_AT_call_all_calls            = $7a;    // flag
  DW_AT_call_all_source_calls     = $7b;    // flag
  DW_AT_call_all_tail_calls       = $7c;    // flag
  DW_AT_call_return_pc            = $7d;    // address
  DW_AT_call_value                = $7e;    // exprloc
  DW_AT_call_origin               = $7f;    // exprloc
  DW_AT_call_parameter            = $80;    // reference
  DW_AT_call_pc                   = $81;    // address
  DW_AT_call_tail_call            = $82;    // flag
  DW_AT_call_target               = $83;    // exprloc
  DW_AT_call_target_clobbered     = $84;    // exprloc
  DW_AT_call_data_location        = $85;    // exprloc
  DW_AT_call_data_value           = $86;    // exprloc
  DW_AT_noreturn                  = $87;    // flag
  DW_AT_alignment                 = $88;    // constant
  DW_AT_export_symbols            = $89;    // flag
  DW_AT_deleted                   = $8a;    // flag
  DW_AT_defaulted                 = $8b;    // constant
  DW_AT_loclists_base             = $8c;    // loclistsptr
  // ---- extensions ----
  DW_AT_MIPS_fde                        = $2001;
  DW_AT_MIPS_loop_begin                 = $2002;
  DW_AT_MIPS_tail_loop_begin            = $2003;
  DW_AT_MIPS_epilog_begin               = $2004;
  DW_AT_MIPS_loop_unroll_factor         = $2005;
  DW_AT_MIPS_software_pipeline_depth    = $2006;
  DW_AT_MIPS_linkage_name               = $2007;
  DW_AT_MIPS_stride                     = $2008;
  DW_AT_MIPS_abstract_name              = $2009;
  DW_AT_MIPS_clone_origin               = $200a;
  DW_AT_MIPS_has_inlines                = $200b;
  DW_AT_sf_names                        = $2101;
  DW_AT_src_info                        = $2102;
  DW_AT_mac_info                        = $2103;
  DW_AT_src_coords                      = $2104;
  DW_AT_body_begin                      = $2105;
  DW_AT_body_end                        = $2106;
  DW_AT_GNU_vector                      = $2107;
  DW_AT_GNU_guarded_by                  = $2108;
  DW_AT_GNU_pt_guarded_by               = $2109;
  DW_AT_GNU_guarded                     = $210a;
  DW_AT_GNU_pt_guarded                  = $210b;
  DW_AT_GNU_locks_excluded              = $210c;
  DW_AT_GNU_exclusive_locks_required    = $210d;
  DW_AT_GNU_shared_locks_required       = $210e;
  DW_AT_GNU_odr_signature               = $210f;
  DW_AT_GNU_template_name               = $2110;
  DW_AT_GNU_call_site_value             = $2111;
  DW_AT_GNU_call_site_data_value        = $2112;
  DW_AT_GNU_call_site_target            = $2113;
  DW_AT_GNU_call_site_target_clobbered  = $2114;
  DW_AT_GNU_tail_call                   = $2115;
  DW_AT_GNU_all_tail_call_sites         = $2116;
  DW_AT_GNU_all_call_sites              = $2117;
  DW_AT_GNU_all_source_call_sites       = $2118;

  // Table 7.18: Identifier case encodings
  DW_ID_case_sensitive            = $00;
  DW_ID_up_case                   = $01;
  DW_ID_down_case                 = $02;
  DW_ID_case_insensitive          = $03;

  // Table 7.19: Calling convention encodings
  DW_CC_normal                    = $01;
  DW_CC_program                   = $02;
  DW_CC_nocall                    = $03;
  // ---- DWARF 5 ----
  DW_CC_pass_by_reference         = $04;
  DW_CC_pass_by_value             = $05;

  // DWARF language codes are documented in Table 7.17
  DW_LANG_C89	                    = $0001;
  DW_LANG_C	                      = $0002;
  DW_LANG_Ada83	                  = $0003;
  DW_LANG_C_plus_plus	            = $0004;
  DW_LANG_Cobol74	                = $0005;
  DW_LANG_Cobol85	                = $0006;
  DW_LANG_Fortran77	              = $0007;
  DW_LANG_Fortran90	              = $0008;
  DW_LANG_Pascal83	              = $0009;
  DW_LANG_Modula2	                = $000a;
  DW_LANG_Java	                  = $000b;
  DW_LANG_C99	                    = $000c;
  DW_LANG_Ada95	                  = $000d;
  DW_LANG_Fortran95	              = $000e;
  DW_LANG_PLI	                    = $000f;
  DW_LANG_ObjC	                  = $0010;
  DW_LANG_ObjC_plus_plus	        = $0011;
  DW_LANG_UPC	                    = $0012;
  DW_LANG_D	                      = $0013;
  // ---- DWARF 4 ----    
  DW_LANG_Python	                = $0014;
  // ---- DWARF 5 ----    
  DW_LANG_OpenCL	                = $0015;
  DW_LANG_Go	                    = $0016;
  DW_LANG_Modula3	                = $0017;
  DW_LANG_Haskell	                = $0018;
  DW_LANG_C_plus_plus_03	        = $0019;
  DW_LANG_C_plus_plus_11	        = $001a;
  DW_LANG_OCaml	                  = $001b;
  DW_LANG_Rust	                  = $001c;
  DW_LANG_C11	                    = $001d;
  DW_LANG_Swift	                  = $001e;
  DW_LANG_Julia	                  = $001f;
  DW_LANG_Dylan	                  = $0020;
  DW_LANG_C_plus_plus_14	        = $0021;
  DW_LANG_Fortran03	              = $0022;
  DW_LANG_Fortran08	              = $0023;
  DW_LANG_RenderScript	          = $0024;
  DW_LANG_BLISS	                  = $0025;
  // ---- DWARF 5+ ----  
  DW_LANG_Kotlin	                = $0026;
  DW_LANG_Zig	                    = $0027;
  DW_LANG_Crystal	                = $0028;
  DW_LANG_C_plus_plus_17	        = $002a;
  DW_LANG_C_plus_plus_20	        = $002b;
  DW_LANG_C17	                    = $002c;
  DW_LANG_Fortran18	              = $002d;
  DW_LANG_Ada2005	                = $002e;
  DW_LANG_Ada2012	                = $002f;
  DW_LANG_HIP	                    = $0030;
  DW_LANG_Assembly	              = $0031;
  DW_LANG_C_sharp	                = $0032;
  DW_LANG_Mojo	                  = $0033;
  DW_LANG_GLSL	                  = $0034;
  DW_LANG_GLSL_ES	                = $0035;
  DW_LANG_HLSL	                  = $0036;
  DW_LANG_OpenCL_CPP	            = $0037;
  DW_LANG_CPP_for_OpenCL	        = $0038;
  DW_LANG_SYCL                    = $0039;

  N_GSYM		= $20;	// global symbol
  N_FNAME		= $22;	// F77 function name
  N_FUN	    = $24;	// procedure name
  N_STSYM		= $26;	// data segment variable
  N_LCSYM		= $28;	// bss segment variable
  N_MAIN		= $2a;	// main function name
  N_PC		  = $30;	// global Pascal symbol
  N_RSYM		= $40;	// register variable
  N_SLINE		= $44;	// text segment line number
  N_DSLINE	= $46;	// data segment line number
  N_BSLINE	= $48;	// bss segment line number
  N_SSYM		= $60;	// structure/union element
  N_SO		  = $64;	// main source file name
  N_LSYM		= $80;	// stack variable
  N_BINCL		= $82;	// include file beginning
  N_SOL		  = $84;	// included source file name
  N_PSYM		= $a0;	// parameter variable
  N_EINCL		= $a2;	// include file end
  N_ENTRY		= $a4;	// alternate entry point
  N_LBRAC		= $c0;	// left bracket
  N_EXCL		= $c2;	// deleted include file
  N_RBRAC		= $e0;	// right bracket
  N_BCOMM		= $e2;	// begin common
  N_ECOMM		= $e4;	// end common
  N_ECOML		= $e8;  // end common (local name)
  N_LENG		= $fe;  // length of preceding entry

  Reg32Str: array [0..36] of string = (
    'EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP', 'EFLAGS',
    '0xA???',
    'ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7',
    '0x13???', '0x14???',
    'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7',
    'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7'
  );


  Reg64Str: array [0..49] of string = (
    'RAX', 'RDX', 'RCX', 'RBX', 'RSI', 'RDI', 'RBP', 'RSP',
    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RIP',
    'XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7',
    'XMM8', 'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15',
    'ST0', 'ST1', 'ST2', 'ST3', 'ST4', 'ST5', 'ST6', 'ST7',
    'MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7', 'RFLAGS'
  );
  
type
  TDebugInfoType = (ditCoff, ditDwarfDie, ditDwarfLines, ditStab, ditPdb, ditSymbols);
  TDebugInfoTypes = set of TDebugInfoType;

  // 4.4.1. Symbol Name Representation

  TCOFFSymbolRecordName = packed record
    case Integer of
      0: (ShortName: array [0..7] of AnsiChar);
      1: (Zeroes, Offset: DWORD);
  end;

  // 4.4. COFF Symbol Table

  TCOFFSymbolRecord = packed record

    // The name of the symbol, represented by a union
    // of three structures. An array of 8 bytes is used if
    // the name is not more than 8 bytes long. For more
    // information, see section 4.4.1, “Symbol Name
    // Representation.”
  
    Name: TCOFFSymbolRecordName;

    // The value that is associated with the symbol. The
    // interpretation of this field depends on
    // SectionNumber and StorageClass. A typical
    // meaning is the relocatable address.

    Value: DWORD;

    // The signed integer that identifies the section,
    // using a one-based index into the section table.
    // Some values have special meaning, as defined in
    // section 4.4.2, "Section Number Values."

    SectionNumber: SmallInt;

    // A number that represents type. Microsoft tools set
    // this field to 0x20 (function) or 0x0 (not a function).
    // For more information, see section 4.4.3, "Type
    // Representation."

    Typ: Word;

    // An enumerated value that represents storage
    // class. For more information, see section 4.4.4,
    // "Storage Class."

    StorageClass: Byte;

    // The number of auxiliary symbol table entries that
    // follow this record.

    NumberOfAuxSymbols: Byte;

  end;  

  // 6.2.2 State Machine Registers
  TStateMachineRegisters = record

    // The program-counter value corresponding to a machine instruction
    // generated by the compiler.

    address : ULONG_PTR64;

    // An unsigned integer indicating the identity of the source file
    // corresponding to a machine instruction.

    file_id : DWORD;

    // An unsigned integer indicating a source line number. Lines are numbered
    // beginning at 1. The compiler may emit the value 0 in cases where an
    // instruction cannot be attributed to any source line.

    line : Integer;

    // An unsigned integer indicating a column number within a source line.
    // Columns are numbered beginning at 1. The value 0 is reserved to indicate
    // that a statement begins at the “left edge” of the line.

    column : DWORD;

    // A boolean indicating that the current instruction is a recommended
    // breakpoint location. A recommended breakpoint location is intended to
    // "represent" a line, a statement and/or a semantically distinct subpart
    // of a statement.

    is_stmt : Boolean;

    // A boolean indicating that the current instruction is the beginning
    // of a basic block

    basic_block : Boolean;

    // A boolean indicating that the current address is that of the first byte after
    // the end of a sequence of target machine instructions.

    end_sequence : Boolean;

    // DWARF3

    // A boolean indicating that the current address is one (of possibly many)
    // where execution should be suspended for an entry breakpoint of a function.

    prolouge_end : Boolean;

    // A boolean indicating that the current address is one (of possibly many)
    // where execution should be suspended for an exit breakpoint of a function.

    epilouge_begin : Boolean;

    // An unsigned integer whose value encodes the applicable instruction set
    // architecture for the current instruction.

    // The encoding of instruction sets should be shared by all users of a given
    // architecture. It is recommended that this encoding be defined by the ABI
    // authoring committee for each architecture.

    isa : DWORD;

    // DWARF 4

    // An unsigned integer identifying the block to
    // which the current instruction belongs.
    // Discriminator values are assigned arbitrarily by
    // the DWARF producer and serve to distinguish
    // among multiple blocks that may all be
    // associated with the same source file, line, and
    // column. Where only one block exists for a given
    // source position, the discriminator value is be
    // zero.

    discriminator: DWORD;

    // DWARF 5

    // An unsigned integer representing the index of
    // an operation within a VLIW instruction. The
    // index of the first operation is 0. For non-VLIW
    // architectures, this register will always be 0.

    op_index: DWORD;

  end;

  TFileEntry = record
    FileName: string;
    DirectoryIndex: Int64;
    FileTime: UInt64;
    FileLength: UInt64;
  end;

  // 6.2.4 The Line Number Program Header (for DWARF 1-4)
  TDwarfLineNumberProgramHeader32 = packed record

    // The size in bytes of the line number information for this compilation unit,
    // not including the unit_length field itself

    unit_length: DWORD;

    // This number is specific to the line number information and
    // is independent of the DWARF version number.

    version: Word;

    // The number of bytes following the header_length field to the beginning
    // of the first byte of the line number program itself.

    header_length: DWORD;

    // The size in bytes of the smallest target machine instruction. Line number program opcodes
    // that alter the address register first multiply their operands by this value.

    minimum_instruction_length: Byte;

    // A simple approach to building line number information when machine instructions are
    // emitted in an order corresponding to the source program is to set default_is_stmt to “true”
    // and to not change the value of the is_stmt register within the line number program. One
    // matrix entry is produced for each line that has code generated for it. The effect is that every
    // entry in the matrix recommends the beginning of each represented line as a breakpoint
    // location. This is the traditional practice for unoptimized code.
    // A more sophisticated approach might involve multiple entries in the matrix for a line
    // number; in this case, at least one entry (often but not necessarily only one) specifies a
    // recommended breakpoint location for the line number. DW_LNS_negate_stmt opcodes in
    // the line number program control which matrix entries constitute such a recommendation and
    // default_is_stmt might be either “true” or “false”. This approach might be used as part of
    // support for debugging optimized code.

    default_is_stmt: Boolean;

    // This parameter affects the meaning of the special opcodes.

    line_base: ShortInt;

    // This parameter affects the meaning of the special opcodes.

    line_range: Byte;

    // The number assigned to the first special opcode.
    // Opcode base is typically one greater than the highest-numbered standard opcode defined for
    // the specified version of the line number information (12 in DWARF Version 3, 9 in DWARF
    // Version 2). If opcode_base is less than the typical value, then standard opcode numbers
    // greater than or equal to the opcode base are not used in the line number table of this unit
    // (and the codes are treated as special opcodes). If opcode_base is greater than the typical
    // value, then the numbers between that of the highest standard opcode and the first special
    // opcode (not inclusive) are used for vendor specific extensions.

    opcode_base: Byte;

    // This array specifies the number of LEB128 operands for each of the standard opcodes. The
    // first element of the array corresponds to the opcode whose value is 1, and the last element
    // corresponds to the opcode whose value is opcode_base - 1. By increasing opcode_base,
    // and adding elements to this array, new standard opcodes can be added, while allowing
    // consumers who do not know about these new opcodes to be able to skip them.

    // standard_opcode_lengths: array of Byte;

    // The sequence contains an entry for each path that was searched for included source files in
    // this compilation. (The paths include those directories specified explicitly by the user for the
    // compiler to search and those the compiler searches without explicit direction). Each path
    // entry is either a full path name or is relative to the current directory of the compilation. The
    // current directory of the compilation is understood to be the first entry and is not explicitly
    // represented. Each entry is a null-terminated string containing a full path name. The last entry
    // is followed by a single null byte.

    // include_directories: array of string;

    // The sequence contains an entry for each source file that contributed to the line number
    // information for this compilation unit or is used in other contexts, such as in a declaration
    // coordinate or a macro file inclusion. Each entry consists of the following values:
    // • A null-terminated string containing the file name.
    // • An unsigned LEB128 number representing the directory index of the directory in which
    // the file was found.
    // • An unsigned LEB128 number representing the (implementation-defined) time of last
    // modification for the file.
    // • An unsigned LEB128 number representing the length in bytes of the file.
    // A compiler may choose to emit LEB128(0) for the time and length fields to indicate that this
    // information is not available. The last entry is followed by a single null byte.
    // The directory index represents an entry in the include_directories section. The index is
    // LEB128(0) if the file was found in the current directory of the compilation, LEB128(1) if it
    // was found in the first directory in the include_directories section, and so on. The
    // directory index is ignored for file names that represent full path names.

    // file_names: array of TFileEtry;

  end;

  TDwarfLineNumberProgramHeader64 = packed record
    magic: DWORD;
    unit_length: UInt64;
    version: Word;
    header_length: UInt64;
    minimum_instruction_length: Byte;
    default_is_stmt: Boolean;
    line_base: ShortInt;
    line_range: Byte;
    opcode_base: Byte;
  end;

  // 7.5.1 Compilation Unit Header
  TDebugInfoProgramHeader32 = packed record

    // A 4-byte or 12-byte unsigned integer representing the length of the .debug_info
    // contribution for that compilation unit, not including the length field itself. In the 32-bit
    // DWARF format, this is a 4-byte unsigned integer (which must be less than 0xffffff00); in
    // the 64-bit DWARF format, this consists of the 4-byte value 0xffffffff followed by an 8-
    // byte unsigned integer that gives the actual length (see Section 7.4).

    unit_length: DWORD;

    // A 2-byte unsigned integer representing the version of the DWARF information for the
    // compilation unit (see Appendix F). For DWARF Version 3, the value in this field is 3.

    version: Word;

    // A 4-byte or 8-byte unsigned offset into the .debug_abbrev section. This offset associates the
    // compilation unit with a particular set of debugging information entry abbreviations. In the
    // 32-bit DWARF format, this is a 4-byte unsigned length; in the 64-bit DWARF format, this is
    // an 8-byte unsigned length (see Section 7.4).

    debug_abbrev_offset: DWORD;

    // A 1-byte unsigned integer representing the size in bytes of an address on the target
    // architecture. If the system uses segmented addressing, this value represents the size of the
    // offset portion of an address.

    address_size: Byte;
  end;

  TDebugInfoProgramHeader64 = packed record
    magic: DWORD;
    unit_length: UInt64;
    version: Word;
    debug_abbrev_offset: UInt64;
    address_size: Byte;
  end;

  TStab = packed record
    n_strx: LongInt;  // index into file string table
    n_type: Byte;     // type flag (N_TEXT,..)
    n_other: Byte;    // unused
    n_desc: Word;     // see <stab.h>
    n_value: DWORD;   // value of symbol (or sdb offset)
  end;

  TSectionParams = record
    AddressVA: ULONG_PTR64;
    AddressRaw: DWORD;
    DisplayName: string;
    SizeOfRawData: DWORD;
    IsExecutable: Boolean;
  end;

  // для PE и ELF реализации разные, поэтому работаем через абстракцию
  TAbstractImageGate = class
  private
    FModuleIndex: Integer;
  public
    function IsObjectFile: Boolean; virtual; abstract;
    function GetIs64Image: Boolean; virtual; abstract;
    function NumberOfSymbols: Integer; virtual; abstract;
    function SectionAtIndex(AIndex: Integer; out ASection: TSectionParams): Boolean; virtual; abstract;
    function SectionAtName(const AName: string; out ASection: TSectionParams): Boolean; virtual; abstract;
    function PointerToSymbolTable: ULONG_PTR64; virtual; abstract;
    function Rebase(Value: ULONG_PTR64): ULONG_PTR64; virtual; abstract;
    property ModuleIndex: Integer read FModuleIndex write FModuleIndex;
  end;

  TCoffFunction = record
    FuncAddrVA: ULONG_PTR64;
    SectionIndex: Integer;
    DisplayName: string;
    Executable: Boolean;
  end;

  TCoffDebugInfo = class
  private
    FImage: TAbstractImageGate;
    FCoffList: TList<TCOFFSymbolRecord>;
    FCoffStrings: TList<TCoffFunction>;
  public
    constructor Create(AImage: TAbstractImageGate);
    destructor Destroy; override;
    function Load(AStream: TStream): Boolean;
    function SymbolAtName(const AName: string): Integer;
    property CoffStrings: TList<TCoffFunction> read FCoffStrings;
  end;

  EOverDataStreamException = class(Exception);

  /// <summary>
  ///  Стрим сидит поверх другого стрима и дает читать/писать
  ///  только в пределах указанной области
  /// </summary>
  TDwarfStream = class(TStream)
  strict private
    FOwnDataStream: Boolean;
    FDataStream: TStream;
    FStartData, FEndData,
    FSize, FPosition: Int64;
    FPreviosPosition, FPreviosNativePosition, FAbsolutePosition: Int64;
    function GetMemory: Pointer;
    function GetNativeStartOffset: Int64;
    procedure UpdatePrevios;
  protected
    function GetSize: Int64; override;
    procedure ReNew(ASize: Int64); overload;
    procedure ReNew(AStartData, ASize: Int64); overload;
    procedure ReNew(ADataStream: TStream; AStartData, ASize: Int64); overload;
  public
    constructor Create(ADataStream: TStream; AStartData, AEndData: Int64;
      ADataStreamOwner: Boolean = False);
    destructor Destroy; override;
    function GetNativePosition: Int64;
    function EOF: Boolean;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; overload; override;
    procedure SeekToEnd;
    function ReadByte: Byte;
    function ReadWord: Word;
    function ReadDWORD: DWORD;
    function ReadUInt64: Uint64;
    // 7.6 Variable Length Data
    function ReadLEB128: Int64;
    function ReadULEB128: UInt64;
    function ReadPAnsiChar: PAnsiChar;
    function ReadString: string;
    property AbsolutePosition: Int64 read FAbsolutePosition;
    property PreviosPosition: Int64 read FPreviosPosition;
    property PreviosNativePosition: Int64 read FPreviosNativePosition;
  end;

  // класс хранящий ссылки на отладочные секции
  // для поддержки редиректов данных между секциями
  // и настройки параметров загрузки
  TDwarfContext = class
  strict private const
    KnownSectionCount = 8;
    SectionName: array [0..KnownSectionCount - 1] of string = (
      '.debug_line',
      '.debug_info',
      '.debug_abbrev',
      '.debug_str',
      '.debug_line_str',
      '.stab',
      '.stabstr',
      '.debug_loc'
    );
  strict private
    FImage: TAbstractImageGate;
    FStreams: array [0..KnownSectionCount - 1] of TDwarfStream;
    FAppendNoAddrVADie: Boolean;
    FAppentUnitName: Boolean;
    {$ifdef debug_dump}
    FDebug: TStringList;
    {$endif}
  public
    constructor Create(AImage: TAbstractImageGate; AImageStream: TStream);
    destructor Destroy; override;
    property AppendNoAddrVADie: Boolean read FAppendNoAddrVADie write FAppendNoAddrVADie;
    property AppendUnitName: Boolean read FAppentUnitName write FAppentUnitName;
    property debug_line: TDwarfStream read FStreams[0];
    property debug_info: TDwarfStream read FStreams[1];
    property debug_abbrev: TDwarfStream read FStreams[2];
    property debug_str: TDwarfStream read FStreams[3];
    property debug_line_str: TDwarfStream read FStreams[4];
    property stab: TDwarfStream read FStreams[5];
    property stabstr: TDwarfStream read FStreams[6];
    property debug_loc: TDwarfStream read FStreams[7];
    property Image: TAbstractImageGate read FImage;
    {$ifdef debug_dump}
    property Debug: TStringList read FDebug;
    {$endif}
  end;

  TLineData = record
    AddrVA: ULONG_PTR64;
    FileId: Word;
    Line: DWORD;
    IsStmt: Boolean;
  end;

  TLineList = TList<TLineData>;

  EDwarfNotImplemented = class(Exception);

  TDwarfLinesUnit = class
  strict private
    FModuleIndex, FUnitIndex: Integer;
    FDirList: TStringList;
    FFiles: TList<TFileEntry>;
    FLines: TLineList;
    FMappedUnitIndex: Integer;
    FElapsed: Int64;
    function ReadFileEntry(AStream: TDwarfStream): TFileEntry;
  protected
    procedure AddLine(ACtx: TDwarfContext;
      AAddrVA: UInt64; AFileId: Word; ALine: DWORD; IsStmt: Boolean);
    property DirList: TStringList read FDirList;
    property Files: TList<TFileEntry> read FFiles;
  public
    constructor Create(AModuleIndex, AUnitIndex, AMappedUnitIndex: Integer);
    destructor Destroy; override;
    function Load(ACtx: TDwarfContext): Boolean;
    function GetFilePath(FileId: Word): string;
    property Lines: TLineList read FLines;
    property MappedUnitIndex: Integer read FMappedUnitIndex;
    property Elapsed: Int64 read FElapsed write FElapsed;
  end;

  TDebugInformationEntry = class
  protected
    function GetParam(Index: Integer): string; virtual;
  public
    AddrVA: ULONG_PTR64;
    EndOfCode: ULONG_PTR64;
    Executable: Boolean;
    AName, AType: string;
    function ShortName: string; virtual; abstract;
    function LongName: string; virtual; abstract;
    function ParamCount: Integer; virtual;
    property Param[Index: Integer]: string read GetParam;
  end;

  TDebugInformationEntrySubProgramm = class(TDebugInformationEntry)
  protected type
    TParamType = (ptFormalParam, ptArtificialParam, ptLocalVariable);
    TParam = record
      AParamType: TParamType;
      AName, AType: string;
      BpLocation: Boolean;
      BpOffset: Integer;
      BpRegister: Byte;
      ByRef: Boolean;
      ATypeSize: DWORD;
    end;
  strict private
    FIs64: Boolean;
    FParamList: TList<TParam>;
  protected
    procedure AddParam(const Value: TParam);
    function GetParam(Index: Integer): string; override;
  public
    constructor Create(AImage64: Boolean);
    destructor Destroy; override;
    function ShortName: string; override;
    function LongName: string; override;
    function ParamCount: Integer; override;
  end;

  TDebugInformationEntryData = class(TDebugInformationEntry)
  public
    function ShortName: string; override;
    function LongName: string; override;
  end;

  TDwarfDataList = TObjectList<TDebugInformationEntry>;

  TByteSet = set of Byte;
  TAddrDict = TDictionary<UInt64, Integer>;

  TDwarfInfoUnit = class;
  TDie = class;

  TDieList = class (TObjectList<TDie>);

  TDie = class
  public
    // Данные для построения дерева
    Parent,
    Child,
    LastChild,
    Sibling: TDie;

    // общие для всех свойства

    // Уникальный индекс элемента (оффсет от начала модуля)
    OffsetID: UInt64;
    // Уникальный индекс элемента (оффсет от начала секции)
    AbsoluteOffset: UInt64;
    // Идентификатор типа элемента
    Tag: DWORD;
    // Имя
    AName: PAnsiChar;
    // ID элемента который содержит описание типа текущего элемента
    ATypeID,
    // индекс в масссиве с типом элемента (массив, базовый тип, ссылка и т.п.)
    ATypeIndex,
    // индекс в масссиве с именем элемента (не обязательно будет идти самым первым в дереве)
    ATypeNameIndex: DWORD;
    // Флаг что ATypeID зачиталось через DW_FORM_ref_addr и содержит абсолютный офсет от секции а не от модуля
    ATypeIDIsAbsolute: Boolean;
    // размер типа (рассчитывается от базового)
    ATypeSize: UInt64;
    // вспомогательный сет, содержащий из каких типов состоит текущий
    ATypeSet: TByteSet;

    // вспомогательные

    AddrVA: ULONG_PTR64;    // VA адрес элемента в адресном пространстве
    EndOfCode: ULONG_PTR64;

    Artificial: Boolean;    // флаг неявного параметра
    ByRef: Boolean;         // идущий по ссылке
    BpOffset: Integer;      // смещение
    BpRegister: Byte;       // от какого регистра
    BpLocation: Boolean;    // флаг что используется Bp смещение для записи

    ByteStride: DWORD;      // размер элемента для масссивов
                            // если указан ATypeSize то можно рассчитать длину статического масссива
    LowerBound: Int64;      // начальный индекс массива

    {$ifdef debug_dump}
    DebugLevel: Integer;
    {$endif}

    procedure CalcTypeParam(AOwner: TDwarfInfoUnit;
      ADieList: TDieList; AAbsoluteAddrDict, AAddrDict: TAddrDict);
    // имя включая какому классу и неймспейсу принадлежит
    function GetCaption(AOwner: TDwarfInfoUnit;
      ADieList: TDieList): string; virtual;
    // приведение типа к строке включая обработку массивов
    function GetType(AOwner: TDwarfInfoUnit;
      ADieList: TDieList): string;
  end;

  TDieProgramm = class(TDie)
    function GetCaption(AOwner: TDwarfInfoUnit;
      ADieList: TDieList): string; override;
  end;

  TDieArray = class(TDie)
    function GetCaption(AOwner: TDwarfInfoUnit;
      ADieList: TDieList): string; override;
  end;

  TDwarfInfoUnit = class
  private type
    TAbbrevDescr = record
      Tag: UInt64;
      Children: Byte;
      AttrIndex: Integer;
      AttrCount: Integer;
    end;

    TAttribute = record
      ID: UInt64;
      Form: UInt64;
    end;

    TLocationData = record
      AddrVA: ULONG_PTR64;
      BpRegister: Byte;
      BpOffset: Integer;
      OperandSet: TByteSet;
    end;

  strict private
    FModuleIndex, FUnitIndex: Integer;
    FCtx: TDwarfContext;
    FStream: TDwarfStream;
    FHeader64: TDebugInfoProgramHeader64;
    FAbbrevDescrList: TList<TAbbrevDescr>;
    FDieOffsetInUnit: UInt64;
    FDieOffsetInImage: Int64;
    FAttributes: TList<TAttribute>;
    FUnitName, FProducer, FSourceDir: string;
    FIdentifierCase: Byte;
    FLanguage: DWORD;
    FAddrStart, FAddrEnd: UInt64;
    FData: TDwarfDataList;
    FStmtOffset: DWORD;
    FLocationBuff: TMemoryStream;
    FLocationStream: TDwarfStream;
    FLoadedCount: Integer;
    FElapsed: Int64;

    procedure AddToList(ACurrent, ANew: TDie;
      List: TDieList);
    function CreateDie(AAbbrevDescr: TAbbrevDescr): TDie;
    function FixedFormByteSize(AForm: UInt64): Byte;
    procedure LoadAbbrev(AAbbrevData: TDwarfStream);
    procedure LoadCompileUnit(const AAbbrevDescr: TAbbrevDescr);
    procedure LoadDIE(const AAbbrevDescr: TAbbrevDescr; ADie: TDie);
    function LoadLocation(const Attribute: TAttribute): TLocationData;
    function LoadUnit(ADieList: TDieList): Boolean;
    procedure RaiseInternal(const AMessage: string);
    function ReadAttribute(const Attribute: TAttribute;
      pBuff: Pointer; ASize: UInt64; AttributeStream: TDwarfStream = nil): Int64;
    function RevertToParent(var ACurrent: TDie): Boolean;
    procedure SkipUnknownAttribute(AForm: UInt64);
  public
    constructor Create(AModuleIndex, AUnitIndex: Integer);
    destructor Destroy; override;
    procedure FillDwarfData(ADieList: TDieList; AAbsoluteDict: TAddrDict; AFromIndex: Integer);
    function Load(Ctx: TDwarfContext; ADieList: TDieList): Boolean;
    function UnitName: string;
    property Data: TDwarfDataList read FData;
    property Producer: string read FProducer;
    property SourceDir: string read FSourceDir;
    property AddrStart: UInt64 read FAddrStart;
    property AddrEnd: UInt64 read FAddrEnd;
    property Elapsed: Int64 read FElapsed write FElapsed;
    property Header64: TDebugInfoProgramHeader64 read FHeader64;
    property Language: DWORD read FLanguage;
    property LoadedCount: Integer read FLoadedCount;
    property ModuleIndex: Integer read FModuleIndex;
    property StmtOffset: DWORD read FStmtOffset;
    property UnitIndex: Integer read FUnitIndex;
  end;

  TDwarfDebugInfo = class;
  TUnitLinesList = TObjectList<TDwarfLinesUnit>;
  TUnitInfosList = TObjectList<TDwarfInfoUnit>;
  TDwarfBeforeLoadCallback = reference to procedure(ADwarfDebugInfo: TDwarfDebugInfo);

  TLoadCallbackStep = (lcsLoadInfo, lcsProcessInfo, lcsLoadLines);
  TDwarfLoadCallback = reference to procedure(AStep: TLoadCallbackStep; ACurrent, AMax: Int64);

  TDwarfDebugInfo = class
  public class var
    BeforeLoadCallback: TDwarfBeforeLoadCallback;
    LoadCallback: TDwarfLoadCallback;
  strict private
    FAppendNoAddrVADie: Boolean;
    FAppentUnitName: Boolean;
    FImage: TAbstractImageGate;
    FMappedUnit: Integer;
    FMappedUnitLines: TList<TDwarfLinesUnit>;
    FUnitLines: TUnitLinesList;
    FUnitInfos: TUnitInfosList;
    function LoadInfo(Ctx: TDwarfContext): Boolean;
    function LoadLines(Ctx: TDwarfContext): Boolean;
    function LoadStub(Ctx: TDwarfContext): Boolean;
    function GetUnitAtStmt(StmtOffset: DWORD): Integer;
  protected
    procedure DoBeforeLoadCallback;
    procedure DoCallback(AStep: TLoadCallbackStep; ACurrent, AMax: Int64);
  public
    constructor Create(AImage: TAbstractImageGate);
    destructor Destroy; override;
    function Load(AStream: TStream): TDebugInfoTypes;
    function MappedUnitLines(AUnitInfoIndex: Integer): TList<TDwarfLinesUnit>;
    property AppendNoAddrVADie: Boolean read FAppendNoAddrVADie write FAppendNoAddrVADie;
    property AppendUnitName: Boolean read FAppentUnitName write FAppentUnitName;
    property Image: TAbstractImageGate read FImage;
    property UnitInfos: TUnitInfosList read FUnitInfos;
    property UnitLines: TUnitLinesList read FUnitLines;
  end;

  TStabSubProgramm = class(TDebugInformationEntrySubProgramm)
  protected
    AUnitName: string;
  public
    function LongName: string; override;
  end;

  TStabLoader = class
  private
    FCtx: TDwarfContext;
    FDwarf: TDwarfDebugInfo;
    FDirAndFilesDict: TDictionary<string, Integer>;
    function ReadString(strx: LongInt): string;
    procedure Split(var AUnitName: string; out AUnitPath: string);
  public
    constructor Create(ADwarf: TDwarfDebugInfo; ACtx: TDwarfContext);
    destructor Destroy; override;
    function Load: Boolean;
  end;

  function DemangleName(const AName: string; Executable: Boolean): string;

implementation

procedure RaiseNotImplemented(ADwarfVersion: Word);
begin
  {$MESSAGE 'Поддержка DWARF5'}
  raise EDwarfNotImplemented.CreateFmt('DWARF %d not implemented.', [ADwarfVersion]);
end;

{$MESSAGE 'выпилить потом'}
function DbgTagToStr(Value: Integer): string;
begin
  case Value of
  DW_TAG_array_type: result := 'DW_TAG_array_type';
  DW_TAG_class_type: result := 'DW_TAG_class_type';
  DW_TAG_entry_point: result := 'DW_TAG_entry_point';
  DW_TAG_enumeration_type: result := 'DW_TAG_enumeration_type';
  DW_TAG_formal_parameter: result := 'DW_TAG_formal_parameter';
  DW_TAG_reserved_6: result := 'DW_TAG_reserved_6';
  DW_TAG_reserved_7: result := 'DW_TAG_reserved_7';
  DW_TAG_imported_declaration: result := 'DW_TAG_imported_declaration';
  DW_TAG_reserved_9: result := 'DW_TAG_reserved_9';
  DW_TAG_label: result := 'DW_TAG_label';
  DW_TAG_lexical_block: result := 'DW_TAG_lexical_block';
  DW_TAG_reserved_c: result := 'DW_TAG_reserved_c';
  DW_TAG_member: result := 'DW_TAG_member';
  DW_TAG_reserved_e: result := 'DW_TAG_reserved_e';
  DW_TAG_pointer_type: result := 'DW_TAG_pointer_type';
  DW_TAG_reference_type: result := 'DW_TAG_reference_type';
  DW_TAG_compile_unit: result := 'DW_TAG_compile_unit';
  DW_TAG_string_type: result := 'DW_TAG_string_type';
  DW_TAG_structure_type: result := 'DW_TAG_structure_type';
  DW_TAG_reserved_14: result := 'DW_TAG_reserved_14';
  DW_TAG_subroutine_type: result := 'DW_TAG_subroutine_type';
  DW_TAG_typedef: result := 'DW_TAG_typedef';
  DW_TAG_union_type: result := 'DW_TAG_union_type';
  DW_TAG_unspecified_parameters: result := 'DW_TAG_unspecified_parameters';
  DW_TAG_variant: result := 'DW_TAG_variant';
  DW_TAG_common_block: result := 'DW_TAG_common_block';
  DW_TAG_common_inclusion: result := 'DW_TAG_common_inclusion';
  DW_TAG_inheritance: result := 'DW_TAG_inheritance';
  DW_TAG_inlined_subroutine: result := 'DW_TAG_inlined_subroutine';
  DW_TAG_module: result := 'DW_TAG_module';
  DW_TAG_ptr_to_member_type: result := 'DW_TAG_ptr_to_member_type';
  DW_TAG_set_type: result := 'DW_TAG_set_type';
  DW_TAG_subrange_type: result := 'DW_TAG_subrange_type';
  DW_TAG_with_stmt: result := 'DW_TAG_with_stmt';
  DW_TAG_access_declaration: result := 'DW_TAG_access_declaration';
  DW_TAG_base_type: result := 'DW_TAG_base_type';
  DW_TAG_catch_block: result := 'DW_TAG_catch_block';
  DW_TAG_const_type: result := 'DW_TAG_const_type';
  DW_TAG_constant: result := 'DW_TAG_constant';
  DW_TAG_enumerator: result := 'DW_TAG_enumerator';
  DW_TAG_file_type: result := 'DW_TAG_file_type';
  DW_TAG_friend: result := 'DW_TAG_friend';
  DW_TAG_namelist: result := 'DW_TAG_namelist';
  DW_TAG_namelist_item: result := 'DW_TAG_namelist_item';
  DW_TAG_packed_type: result := 'DW_TAG_packed_type';
  DW_TAG_subprogram: result := 'DW_TAG_subprogram';
  DW_TAG_template_type_parameter: result := 'DW_TAG_template_type_parameter';
  DW_TAG_template_value_parameter: result := 'DW_TAG_template_value_parameter';
  DW_TAG_thrown_type: result := 'DW_TAG_thrown_type';
  DW_TAG_try_block: result := 'DW_TAG_try_block';
  DW_TAG_variant_part: result := 'DW_TAG_variant_part';
  DW_TAG_variable: result := 'DW_TAG_variable';
  DW_TAG_volatile_type: result := 'DW_TAG_volatile_type';
  DW_TAG_dwarf_procedure: result := 'DW_TAG_dwarf_procedure';
  DW_TAG_restrict_type: result := 'DW_TAG_restrict_type';
  DW_TAG_interface_type: result := 'DW_TAG_interface_type';
  DW_TAG_namespace: result := 'DW_TAG_namespace';
  DW_TAG_imported_module: result := 'DW_TAG_imported_module';
  DW_TAG_unspecified_type: result := 'DW_TAG_unspecified_type';
  DW_TAG_partial_unit: result := 'DW_TAG_partial_unit';
  DW_TAG_imported_unit: result := 'DW_TAG_imported_unit';
  DW_TAG_reserved_3e: result := 'DW_TAG_reserved_3e';
  DW_TAG_condition: result := 'DW_TAG_condition';
  DW_TAG_shared_type: result := 'DW_TAG_shared_type';
  else
    Result := 'unknown ' + IntToStr(Value);
  end;
end;

function DbgNToStr(Value: Integer): string;
begin
  case value of
  N_GSYM: Result := 'N_GSYM';
  N_FNAME: Result := 'N_FNAME';
  N_FUN: Result := 'N_FUN';
  N_STSYM: Result := 'N_STSYM';
  N_LCSYM: Result := 'N_LCSYM';
  N_MAIN: Result := 'N_MAIN';
  N_PC: Result := 'N_PC';
  N_RSYM: Result := 'N_RSYM';
  N_SLINE: Result := 'N_SLINE';
  N_DSLINE: Result := 'N_DSLINE';
  N_BSLINE: Result := 'N_BSLINE';
  N_SSYM: Result := 'N_SSYM';
  N_SO: Result := 'N_SO';
  N_LSYM: Result := 'N_LSYM';
  N_BINCL: Result := 'N_BINCL';
  N_SOL: Result := 'N_SOL';
  N_PSYM: Result := 'N_PSYM';
  N_EINCL: Result := 'N_EINCL';
  N_ENTRY: Result := 'N_ENTRY';
  N_LBRAC: Result := 'N_LBRAC';
  N_EXCL: Result := 'N_EXCL';
  N_RBRAC: Result := 'N_RBRAC';
  N_BCOMM: Result := 'N_BCOMM';
  N_ECOMM: Result := 'N_ECOMM';
  N_ECOML: Result := 'N_ECOML';
  N_LENG: Result := 'N_LENG';
  else
    Result := 'unknown ' + IntToStr(Value);
  end;
end;

function DemangleName(const AName: string; Executable: Boolean): string;
const
  indClassOperatorMethod = '_$__$$_$';
  indClassMethod = '_$__$$_';
  indMethod = '_$$_';
  indClass = '$_$';
  indResult = '$$';
  indSeparator = '_';
  indParam = '$';

type
  TIdentifierType = (itUnknown, itUnit, itClass, itMethod, itParamType, itResultType, itEnd);
  TIdentifierTypes = set of TIdentifierType;

var
  pCursor, pMax: PChar;

  function Check(const Ind: string): Boolean;
  begin
    if pCursor + Length(Ind) > pMax then
      Result := False
    else
      Result := StrLComp(pCursor, @Ind[1], Length(Ind)) = 0;
  end;

  function ReadStr: string;
  var
    pStart: PChar;
  begin
    pStart := pCursor;
    while (pCursor < pMax) and (pCursor^ <> indParam) do
    begin
      if pCursor^ = indSeparator then
      begin
        if Check(indMethod) or Check(indClassMethod) or Check(indClassOperatorMethod) then
          Break;
      end;
      Inc(pCursor);
    end;
    SetLength(Result, pCursor - pStart);
    if Result <> '' then
      Move(pStart^, Result[1], Length(Result) * SizeOf(Char));
  end;

  function ReadIdentifierType(APrevios: TIdentifierType): TIdentifierType;
  begin
    if pCursor >= pMax then
      Exit(itEnd);
    Result := itUnknown;

    if Check(indClassOperatorMethod) then
    begin
      if APrevios = itClass then
      begin
        Result := itMethod;
        Inc(pCursor, Length(indClassOperatorMethod));
      end
      else
        Result := itUnknown;
      Exit;
    end;

    if Check(indClassMethod) then
    begin
      if APrevios = itClass then
      begin
        Result := itMethod;
        Inc(pCursor, Length(indClassMethod));
      end
      else
        Result := itUnknown;
      Exit;
    end;

    if Check(indMethod) then
    begin
      if APrevios = itUnit then
      begin
        Result := itMethod;
        Inc(pCursor, Length(indMethod));
      end
      else
        Result := itUnknown;
      Exit;
    end;

    if Check(indClass) then
    begin
      if APrevios = itUnit then
      begin
        Result := itClass;
        Inc(pCursor, Length(indClass));
      end
      else
        Result := itUnknown;
      Exit;
    end;

    if Check(indResult) then
    begin
      if APrevios in [itMethod, itParamType] then
      begin
        Result := itResultType;
        Inc(pCursor, Length(indResult));
      end
      else
        Result := itUnknown;
      Exit;
    end;

    if Check(indParam) then
    begin
      if APrevios in [itMethod, itParamType] then
      begin
        Result := itParamType;
        Inc(pCursor, Length(indParam));
      end
      else
        Result := itUnknown;
      Exit;
    end;

  end;

var
  AUnitName, AClassName, AMethodName, AParamsTypeList, AResultType: string;
  NextIdentifierType: TIdentifierType;
begin
  if AName = '' then
  begin
    Result := '';
    Exit;
  end;

  if not Executable then
  begin
    Result := AName;
    Exit;
  end;

  // системные функции
  if AName[1] = '_' then
  begin
    Result := AName;
    Exit;
  end;

  pCursor := @AName[1];
  pMax := pCursor;
  Inc(pMax, Length(AName));

  AUnitName := ReadStr;
  NextIdentifierType := itUnit;
  while NextIdentifierType <> itEnd do
  begin
    NextIdentifierType := ReadIdentifierType(NextIdentifierType);
    case NextIdentifierType of
      itUnknown: Break;
      itClass: AClassName := ReadStr;
      itMethod: AMethodName := ReadStr;
      itParamType:
      begin
        if AParamsTypeList = '' then
          AParamsTypeList := ReadStr
        else
          AParamsTypeList := AParamsTypeList + ', ' + ReadStr;
      end;
      itResultType:
        AResultType := ReadStr;
    end;
  end;

  // не смогли распасить или имя метода отсутствует, значит оставляем как есть
  if (NextIdentifierType = itUnknown) or (AMethodName = '') then
  begin
    Result := AName;
    Exit;
  end;

  Result := '[' + AUnitName + '] ';
  if AClassName <> '' then
    Result := Result + AClassName + '.';
  Result := Result + AMethodName;
  if AParamsTypeList <> '' then
    Result := Result + '(' + AParamsTypeList + ')';
  if AResultType <> '' then
    Result := Result + ': ' + AResultType;
end;

function InitStateMachineRegisters(DefaultIsStmt: Boolean): TStateMachineRegisters;
begin
  FillChar(Result, SizeOf(Result), 0);
  Result.file_id := 1;
  Result.line := 1;
  Result.is_stmt := DefaultIsStmt;
end;

function CalcAddPCValue(Opcode: Byte; const AHeader: TDwarfLineNumberProgramHeader64): ULONG_PTR64;
begin
  Result := (Opcode - AHeader.opcode_base) div AHeader.line_range * AHeader.minimum_instruction_length;
end;

{ TCoffDebugInfo }

constructor TCoffDebugInfo.Create(AImage: TAbstractImageGate);
begin
  FImage := AImage;
  FCoffList := TList<TCOFFSymbolRecord>.Create;
  FCoffStrings := TList<TCoffFunction>.Create;
end;

destructor TCoffDebugInfo.Destroy;
begin
  FCoffList.Free;
  FCoffStrings.Free;
  inherited;
end;

function TCoffDebugInfo.Load(AStream: TStream): Boolean;
const
  // 4.4.4. Storage Class
  IMAGE_SYM_CLASS_STATIC = 3;
var
  I: Integer;
  Buff: array [Byte] of AnsiChar;
  ASection: TSectionParams;
  StrStartPosition, StrEndPosition: Int64;
  ACoffFunction: TCoffFunction;
  SymbolData: TSymbolData;
begin
  Result := False;
  FCoffList.Count := FImage.NumberOfSymbols;
  AStream.Position := FImage.PointerToSymbolTable;
  for I := 0 to FCoffList.Count - 1 do
  begin
    if AStream.Read(FCoffList.List[I], SizeOf(TCOFFSymbolRecord)) <> SizeOf(TCOFFSymbolRecord) then
      Exit;
  end;
  StrStartPosition := AStream.Position;
  StrEndPosition := AStream.Size;
  Buff[255] := #0;
  for I := 0 to FCoffList.Count - 1 do
  begin
    // если у символа не указан номер секции, значит мы не можем рассчитать его адрес
    // но тогда нам и имя его не нужно
    ACoffFunction.SectionIndex := FCoffList.List[I].SectionNumber - 1;
    if ACoffFunction.SectionIndex < 0 then
      Continue;

    if FCoffList.List[I].Name.Zeroes = 0 then
    begin
      {$MESSAGE 'переделать на пчары'}
      AStream.Position := StrStartPosition + FCoffList.List[I].Name.Offset;
      AStream.ReadBuffer(Buff[0], Min(255, StrEndPosition - AStream.Position));
    end
    else
    begin
      Move(FCoffList.List[I].Name, Buff[0], 8);
      Buff[9] := #0;
    end;
    if FImage.SectionAtIndex(ACoffFunction.SectionIndex, ASection) then
      ACoffFunction.FuncAddrVA := FCoffList.List[I].Value + ASection.AddressVA
    else
      // если секции нет, то и работать с таким символом не получится
      Continue;

    ACoffFunction.Executable := ASection.IsExecutable;
    ACoffFunction.DisplayName := string(PAnsiChar(@Buff[0]));

    // The offset of the symbol within the section. If the Value field is zero,
    // then the symbol represents a section name.
    if FCoffList.List[I].StorageClass = IMAGE_SYM_CLASS_STATIC then
      if Buff[0] = '.' then
        Continue;

    SymbolData.AddrVA := ACoffFunction.FuncAddrVA;
    if ACoffFunction.Executable then
      SymbolData.DataType := sdtCoffFunction
    else
      SymbolData.DataType := sdtCoffData;
    SymbolData.Binary.ModuleIndex := FImage.ModuleIndex;
    SymbolData.Binary.ListIndex := FCoffStrings.Count;
    SymbolStorage.Add(SymbolData);

    FCoffStrings.Add(ACoffFunction);
  end;

  Result := FCoffStrings.Count > 0;
end;

function TCoffDebugInfo.SymbolAtName(const AName: string): Integer;
begin
  Result := -1;
  for var I := 0 to FCoffStrings.Count - 1 do
    if AnsiSameText(AName, FCoffStrings.List[I].DisplayName) then
      Exit(I);
end;

{ TDwarfStream }

constructor TDwarfStream.Create(ADataStream: TStream; AStartData,
  AEndData: Int64; ADataStreamOwner: Boolean);
begin
  FOwnDataStream := ADataStreamOwner;
  ReNew(ADataStream, AStartData, AEndData);
end;

destructor TDwarfStream.Destroy;
begin
  if FOwnDataStream then
    FDataStream.Free;
  inherited;
end;

function TDwarfStream.EOF: Boolean;
begin
  Result := FPosition >= FSize;
end;

function TDwarfStream.GetMemory: Pointer;
begin
  if FDataStream is TDwarfStream then
    Result := TDwarfStream(FDataStream).GetMemory
  else
    if FDataStream is TMemoryStream then
      Result := TMemoryStream(FDataStream).Memory
    else
      Result := nil;
end;

function TDwarfStream.GetNativePosition: Int64;
begin
  Result := GetNativeStartOffset + FPosition;
end;

function TDwarfStream.GetNativeStartOffset: Int64;
begin
  if FDataStream is TDwarfStream then
    Result := TDwarfStream(FDataStream).GetNativeStartOffset + FStartData
  else
    Result := FStartData;
end;

function TDwarfStream.GetSize: Int64;
begin
  Result := FSize;
end;

function TDwarfStream.Read(var Buffer; Count: Longint): Longint;
begin
  FDataStream.Position := FStartData + FPosition;
  FPreviosPosition := FPosition;
  FPreviosNativePosition := GetNativePosition;
  if Count > FSize - FPosition then
    Count := FSize - FPosition;
  Result := FDataStream.Read(Buffer, Count);
  Inc(FPosition, Result);
end;

function TDwarfStream.ReadByte: Byte;
begin
  ReadBuffer(Result, SizeOf(Result));
end;

function TDwarfStream.ReadDWORD: DWORD;
begin
  ReadBuffer(Result, SizeOf(Result));
end;

function TDwarfStream.ReadLEB128: Int64;
var
  Chunk, ChunkShift: Int64;
  SavePos, SaveNativePos: Int64;
begin
  Result := 0;
  ChunkShift := 0;
  Chunk := 0;
  SavePos := FPosition;
  SaveNativePos := GetNativePosition;
  ReadBuffer(Chunk, 1);
  while ChunkShift < 63 do
  begin
    Result := Result or ((Chunk and $7F) shl ChunkShift);
    Inc(ChunkShift, 7);
    if Chunk and $80 = 0 then
      Break;
    ReadBuffer(Chunk, 1);
  end;
  // выставление знака который хранится в 7 бите
  // последнего прочитанного семибитного чанка
  ChunkShift := 1 shl (ChunkShift - 1);
  Result := Result or not ((Result and ChunkShift) - 1);
  FPreviosPosition := SavePos;
  FPreviosNativePosition := SaveNativePos;
  FAbsolutePosition := SavePos;
  if FDataStream is TDwarfStream then
    FAbsolutePosition := FStartData + SavePos;
end;

function TDwarfStream.ReadPAnsiChar: PAnsiChar;
begin
  Result := GetMemory;
  Inc(Result, GetNativePosition);
  Seek(AnsiStrings.StrLen(Result) + 1, soFromCurrent);
end;

function TDwarfStream.ReadString: string;
begin
  Result := string(AnsiString(ReadPAnsiChar));
end;

function TDwarfStream.ReadUInt64: Uint64;
begin
  ReadBuffer(Result, SizeOf(Result));
end;

function TDwarfStream.ReadULEB128: UInt64;
var
  Chunk, ChunkShift: Int64;
  SavePos, SavewNativePos: Int64;
begin
  Result := 0;
  ChunkShift := 0;
  Chunk := 0;
  SavePos := FPosition;
  SavewNativePos := GetNativePosition;
  ReadBuffer(Chunk, 1);
  while ChunkShift < 63 do
  begin
    Result := Result or ((Chunk and $7F) shl ChunkShift);
    Inc(ChunkShift, 7);
    if Chunk and $80 = 0 then
      Break;
    ReadBuffer(Chunk, 1);
  end;
  FPreviosPosition := SavePos;
  FPreviosNativePosition := SavewNativePos;
  FAbsolutePosition := SavePos;
  if FDataStream is TDwarfStream then
    FAbsolutePosition := FStartData + SavePos;
end;

function TDwarfStream.ReadWord: Word;
begin
  ReadBuffer(Result, SizeOf(Result));
end;

procedure TDwarfStream.ReNew(ADataStream: TStream; AStartData,
  ASize: Int64);
begin
  FDataStream := ADataStream;
  FStartData := AStartData;
  FEndData := FStartData + ASize;
  FPosition := 0;
  FSize := ASize;
end;

procedure TDwarfStream.ReNew(ASize: Int64);
begin
  ReNew(FDataStream, FStartData, ASize);
end;

procedure TDwarfStream.ReNew(AStartData, ASize: Int64);
begin
  ReNew(FDataStream, AStartData, ASize);
end;

function TDwarfStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  UpdatePrevios;
  case Origin of
    soBeginning: FPosition := Offset;
    soCurrent: Inc(FPosition, Offset);
    soEnd: FPosition := Size + Offset;
  end;
  if FPosition < 0 then
    FPosition := 0;
  if FPosition > FSize then
    FPosition := FSize;
  Result := FPosition;
end;

procedure TDwarfStream.SeekToEnd;
begin
  UpdatePrevios;
  FDataStream.Position := FStartData + FSize;
  FPosition := FSize;
end;

procedure TDwarfStream.UpdatePrevios;
begin
  FAbsolutePosition := FPosition;
  if FDataStream is TDwarfStream then
    FAbsolutePosition := FStartData + FPosition;
  FPreviosPosition := FPosition;
  FPreviosNativePosition := GetNativePosition;
end;

{ TDwarfContext }

constructor TDwarfContext.Create(AImage: TAbstractImageGate;
  AImageStream: TStream);
var
  I: Integer;
  ASection: TSectionParams;
  IsMemoryStream: Boolean;
  DataStream: TMemoryStream;
begin
  {$ifdef debug_dump}
  FDebug := TStringList.Create;
  {$endif}
  FImage := AImage;
  IsMemoryStream := AImageStream is TMemoryStream;
  for I := 0 to KnownSectionCount - 1 do
    if Image.SectionAtName(SectionName[I], ASection) then
    begin
      // в целях оптимизации строки читаются как PAnsiChar, поэтому
      // нужно контролировать что TDwarfStream гарантированно сидит поверх
      // TMemoryStream, иначе никакого фокуса не получится.
      if IsMemoryStream then
        FStreams[I] := TDwarfStream.Create(AImageStream, ASection.AddressRaw, ASection.SizeOfRawData)
      else
      begin
        DataStream := TMemoryStream.Create;
        AImageStream.Position := ASection.AddressRaw;
        DataStream.CopyFrom(AImageStream, ASection.SizeOfRawData);
        FStreams[I] := TDwarfStream.Create(DataStream, 0, ASection.SizeOfRawData, True);
      end;
    end;
end;

destructor TDwarfContext.Destroy;
var
  I: Integer;
begin
  {$ifdef debug_dump}
  if FDebug.Count > 0 then
    FDebug.SaveToFile('d:\tmp\s\dump.txt');
  FDebug.Free;
  {$endif}
  for I := 0 to KnownSectionCount - 1 do
    FStreams[I].Free;
  inherited;
end;

{ TDwarfLinesUnit }

procedure TDwarfLinesUnit.AddLine(ACtx: TDwarfContext;
  AAddrVA: UInt64; AFileId: Word; ALine: DWORD; IsStmt: Boolean);
var
  LineData: TLineData;
  SymbolData: TSymbolData;
begin
  // учитываем rebase
  AAddrVA := ACtx.Image.Rebase(AAddrVA);
  SymbolData := MakeItem(AAddrVA, sdtDwarfLine);
  SymbolData.Binary.ModuleIndex := FModuleIndex;
  SymbolData.Binary.ListIndex := FUnitIndex;
  SymbolData.Binary.Param := FLines.Count;
  SymbolStorage.Add(SymbolData);

  LineData.AddrVA := AAddrVA;
  LineData.FileId := AFileId;
  LineData.Line := ALine;
  LineData.IsStmt := IsStmt;
  FLines.Add(LineData);
end;

constructor TDwarfLinesUnit.Create(AModuleIndex, AUnitIndex,
  AMappedUnitIndex: Integer);
begin
  FModuleIndex := AModuleIndex;
  FUnitIndex := AUnitIndex;
  FMappedUnitIndex := AMappedUnitIndex;
  FDirList := TStringList.Create;
  FFiles := TList<TFileEntry>.Create;
  FLines := TLineList.Create;
end;

destructor TDwarfLinesUnit.Destroy;
begin
  FDirList.Free;
  FFiles.Free;
  FLines.Free;
  inherited;
end;

function TDwarfLinesUnit.GetFilePath(FileId: Word): string;
begin
  Result := '';
  if FileId > FFiles.Count then
    Exit;
  with FFiles.List[FileId - 1] do
  begin
    if (DirectoryIndex > 0) and (FDirList.Count >= DirectoryIndex) then
      Result := IncludeTrailingPathDelimiter(FDirList[DirectoryIndex - 1]);
    Result := Result + FileName;
  end;
  Result := StringReplace(Result, '/', PathDelim, [rfReplaceAll]);
  Result := StringReplace(Result, '\', PathDelim, [rfReplaceAll]);
end;

function TDwarfLinesUnit.Load(ACtx: TDwarfContext): Boolean;
var
  UnitStream: TDwarfStream;
  Magic: DWORD;
  Header32: TDwarfLineNumberProgramHeader32;
  Header64: TDwarfLineNumberProgramHeader64;
  HeaderLength: UInt64;
  OpcodeLen: array of Byte;
  TmpString: string;
  FileEntry: TFileEntry;
  SmRegisters: TStateMachineRegisters;
  opcode: Byte;
  ExtendedLength: UInt64;
  AddToMatrix: Boolean;
  AddrVAInited: Boolean;
begin
  Result := True;

  if ACtx.debug_line.Size - ACtx.debug_line.Position < SizeOf(TDwarfLineNumberProgramHeader64)  then
  begin
    ACtx.debug_line.SeekToEnd;
    Result := False;
    Exit;
  end;

  UnitStream := TDwarfStream.Create(ACtx.debug_line, ACtx.debug_line.Position, 0);
  try

    //  In the 32-bit DWARF format, an initial length field (see Section 7.2.2) is an unsigned 32-bit
    // integer (which must be less than 0xffffff00); in the 64-bit DWARF format, an initial
    // length field is 96 bits in size, and has two parts:
    // • The first 32-bits have the value 0xffffffff.
    // • The following 64-bits contain the actual length represented as an unsigned 64-bit integer.
    // This representation allows a DWARF consumer to dynamically detect that a DWARF section
    // contribution is using the 64-bit format and to adapt its processing accordingly.

    ACtx.debug_line.ReadBuffer(Magic, SizeOf(Magic));
    if Magic = Header64Magic then
    begin
      Header64.magic := Header64Magic;
      ACtx.debug_line.ReadBuffer(Header64.unit_length, SizeOf(Header64) - SizeOf(Magic));
      if Header64.unit_length = 0 then
        Exit(False);
      Inc(Header64.unit_length, SizeOf(Header64.unit_length) + SizeOf(Magic));
      HeaderLength := SizeOf(Header64);
    end
    else
    begin
      Header32.unit_length := Magic;
      if Header32.unit_length = 0 then
        Exit(False);
      ACtx.debug_line.ReadBuffer(Header32.version, SizeOf(Header32) - SizeOf(Magic));
      Header64.Magic := 0;
      Header64.unit_length := Header32.unit_length + SizeOf(Header32.unit_length);
      Header64.version := Header32.version;
      Header64.header_length := Header32.header_length;
      Header64.minimum_instruction_length := Header32.minimum_instruction_length;
      Header64.default_is_stmt := Header32.default_is_stmt;
      Header64.line_base := Header32.line_base;
      Header64.line_range := Header32.line_range;
      Header64.opcode_base := Header32.opcode_base;
      HeaderLength := SizeOf(Header32);
    end;

    UnitStream.ReNew(Header64.unit_length);
    UnitStream.Position := HeaderLength;

    if Header64.version = 5 then
    begin
      UnitStream.SeekToEnd;
      Exit;
    end;

    // читаем размеры LEB128 операндов для каждого опкода
    SetLength(OpcodeLen, Header64.opcode_base);
    UnitStream.ReadBuffer(OpcodeLen[1], Header64.opcode_base - 1);

    // начиная с пятого в заголовке пошли изменения, надо тестировать
    if Header64.version >= 5 then
      RaiseNotImplemented(Header64.version);

    // читаем директории
    repeat
      TmpString := UnitStream.ReadString;
      if TmpString <> '' then
        FDirList.Add(TmpString);
    until TmpString = '';

    // читаем список файлов
    repeat
      FileEntry := ReadFileEntry(UnitStream);
      if FileEntry.FileName <> '' then
        FFiles.Add(FileEntry);
    until FileEntry.FileName = '';

    // через машину состояний парсим информацию о линиях
    SmRegisters := InitStateMachineRegisters(Header64.default_is_stmt);
    AddrVAInited := False;
    AddToMatrix := False;

    // могут быть пустые модули, просто задекларированые, но не содержащие кода
    // поэтому добавлю проверку
    if UnitStream.EOF then
    begin
      UnitStream.SeekToEnd;
      Exit;
    end;

    opcode := UnitStream.ReadByte;
    while not UnitStream.EOF do
    begin
      case opcode of
        // обработка расширенных опкодов, начинающихся с нуля
        0:
        begin
          // минус один т.к. включает размер опкода
          ExtendedLength := UnitStream.ReadULEB128 - 1;
          opcode := UnitStream.ReadByte;

          case opcode of

            // The DW_LINE_end_sequence opcode takes no operands. It sets the end_sequence register
            // of the state machine to “true” and appends a row to the matrix using the current values of the
            // state-machine registers. Then it resets the registers to the initial values specified above (see
            // Section 6.2.2). Every line number program sequence must end with a
            // DW_LNE_end_sequence instruction which creates a row whose address is that of the byte
            // after the last target machine instruction of the sequence.

            DW_LNE_end_sequence:
            begin
              SmRegisters.end_sequence := True;
              AddToMatrix := True;
            end;

            // The DW_LNE_set_address opcode takes a single relocatable address as an
            // operand. The size of the operand is the size of an address on the target
            // machine. It sets the address register to the value given by the relocatable
            // address and sets the op_index register to 0.

            // All of the other line number program opcodes that affect the address register add a delta to
            // it. This instruction stores a relocatable value into it instead.

            DW_LNE_set_address:
            begin
              SmRegisters.address := 0;
              SmRegisters.op_index := 0;
              UnitStream.ReadBuffer(SmRegisters.address, ExtendedLength);
              AddrVAInited := SmRegisters.address <> 0;
            end;

            // The DW_LNE_define_file opcode takes four operands:
            // 1. A null-terminated string containing a source file name.
            // 2. An unsigned LEB128 number representing the directory index of the directory in which
            // the file was found.
            // 3. An unsigned LEB128 number representing the time of last modification of the file.
            // 4. An unsigned LEB128 number representing the length in bytes of the file.
            // The time and length fields may contain LEB128(0) if the information is not available.

            // The directory index represents an entry in the include_directories section of the line
            // number program header. The index is LEB128(0) if the file was found in the current
            // directory of the compilation, LEB128(1) if it was found in the first directory in the
            // include_directories section, and so on. The directory index is ignored for file names that
            // represent full path names.
            // The files are numbered, starting at 1, in the order in which they appear; the names in the
            // header come before names defined by the DW_LNE_define_file instruction. These numbers
            // are used in the file register of the state machine.

            DW_LNE_define_file:
            begin
              if Header64.version < 5 then
              begin
                FileEntry := ReadFileEntry(UnitStream);
                if FileEntry.FileName <> '' then
                  FFiles.Add(FileEntry);
              end
              else
              begin
                // The DW_LNE_define_file operation defined in earlier versions of DWARF is deprecated
                // 5 in DWARF Version 5.
                RaiseNotImplemented(Header64.version);
              end;
            end;

            // The DW_LNE_set_discriminator opcode takes a single parameter, an
            // unsigned LEB128 integer. It sets the discriminator register to the new value.

            DW_LNE_set_discriminator:
            begin

              // используется для многострочных инструкций чтобы отделять
              // строки друг от друга, читай оффсет к изначальному номеру строки
              // типа такого:
              //
              // 100: if (a = 1) and
              // 101:    (b = 2) and // -> 100 + discriminator 1
              // 102:    (c = 3) and // -> 100 + discriminator 2

              if Header64.version >= 5 then
                SmRegisters.discriminator := UnitStream.ReadULEB128
              else
                UnitStream.Seek(ExtendedLength, soFromCurrent);
            end;

          else
            // unknown extended opcode
            UnitStream.Seek(ExtendedLength, soFromCurrent);
          end;
        end;

        // The DW_LNS_copy opcode takes no operands. It appends a row to the matrix using the
        // current values of the state-machine registers. Then it sets the discriminator register
        // to 0, and sets the basic_block, prologue_end and epilogue_begin registers to “false.”

        DW_LNS_copy:
        begin
          SmRegisters.discriminator := 0;
          SmRegisters.basic_block := False;
          SmRegisters.prolouge_end := False;
          SmRegisters.epilouge_begin := False;
          AddToMatrix := True;
        end;

        // The DW_LNS_advance_pc opcode takes a single unsigned LEB128 operand, multiplies it by
        // the minimum_instruction_length field of the header, and adds the result to the address
        // register of the state machine.

        DW_LNS_advance_pc:
        begin
          if Header64.version < 5 then
            SmRegisters.address := SmRegisters.address +
              UnitStream.ReadULEB128 * Header64.minimum_instruction_length
          else
          begin
            // The DW_LNS_advance_pc opcode takes a single unsigned LEB128 operand
            // as the operation advance and modifies the address and op_index registers as
            // specified in Section 6.2.5.1 on page 160.
            RaiseNotImplemented(Header64.version);
          end;
        end;

        // The DW_LNS_advance_line opcode takes a single signed LEB128 operand and adds that
        // value to the line register of the state machine.

        DW_LNS_advance_line:
        begin
          SmRegisters.line := SmRegisters.line + UnitStream.ReadLEB128;
        end;

        // The DW_LNS_set_file opcode takes a single unsigned LEB128 operand and stores it in the
        // file register of the state machine.

        DW_LNS_set_file:
        begin
          SmRegisters.file_id := UnitStream.ReadULEB128;
        end;

        // The DW_LNS_set_column opcode takes a single unsigned LEB128 operand and stores it in
        // the column register of the state machine

        DW_LNS_set_column:
        begin
          SmRegisters.column := UnitStream.ReadULEB128;
        end;

        // The DW_LNS_negate_stmt opcode takes no operands. It sets the is_stmt register of the
        // state machine to the logical negation of its current value.

        DW_LNS_negate_stmt:
        begin
          SmRegisters.is_stmt := not SmRegisters.is_stmt;
        end;

        // The DW_LNS_set_basic_block opcode takes no operands. It sets the basic_block register
        // of the state machine to “true.”

        DW_LNS_set_basic_block:
        begin
          SmRegisters.basic_block := True;
        end;

        // The DW_LNS_const_add_pc opcode takes no operands. It multiplies the address increment
        // value corresponding to special opcode 255 by the minimum_instruction_length field of
        // the header, and adds the result to the address register of the state machine.

        // When the line number program needs to advance the address by a small amount, it can use a
        // single special opcode, which occupies a single byte. When it needs to advance the address by
        // up to twice the range of the last special opcode, it can use DW_LNS_const_add_pc followed
        // by a special opcode, for a total of two bytes. Only if it needs to advance the address by more
        // than twice that range will it need to use both DW_LNS_advance_pc and a special opcode,
        // requiring three or more bytes.

        DW_LNS_const_add_pc:
        begin
          if Header64.version < 5 then
          begin
            SmRegisters.address := SmRegisters.address + CalcAddPCValue(255, Header64);
          end
          else
          begin
            // The DW_LNS_const_add_pc opcode takes no operands. It advances the
            // address and op_index registers by the increments corresponding to special
            // opcode 255.
            RaiseNotImplemented(Header64.version);
          end;
        end;

        // The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded) operand and adds
        // it to the address register of the state machine. This is the only standard opcode whose
        // operand is not a variable length number. It also does not multiply the operand by the
        // minimum_instruction_length field of the header.

        // Existing assemblers cannot emit DW_LNS_advance_pc or special opcodes because they
        // cannot encode LEB128 numbers or judge when the computation of a special opcode
        // overflows and requires the use of DW_LNS_advance_pc. Such assemblers, however, can use
        // DW_LNS_fixed_advance_pc instead, sacrificing compression.

        DW_LNS_fixed_advance_pc:
        begin
          if Header64.version < 5 then
          begin
            SmRegisters.address := SmRegisters.address + UnitStream.ReadWord;
          end
          else
          begin
            // The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded)
            // operand and adds it to the address register of the state machine and sets the
            // op_index register to 0. This is the only standard opcode whose operand is not
            // a variable length number. It also does not multiply
            RaiseNotImplemented(Header64.version);
          end;
        end;

        // The DW_LNS_set_prologue_end opcode takes no operands. It sets the prologue_end
        // register to “true”.

        // When a breakpoint is set on entry to a function, it is generally desirable for execution to be
        // suspended, not on the very first instruction of the function, but rather at a point after the
        // function's frame has been set up, after any language defined local declaration processing has
        // been completed, and before execution of the first statement of the function begins. Debuggers
        // generally cannot properly determine where this point is. This command allows a compiler to
        // communicate the location(s) to use.

        // In the case of optimized code, there may be more than one such location; for example, the
        // code might test for a special case and make a fast exit prior to setting up the frame.

        // Note that the function to which the prologue end applies cannot be directly determined from
        // the line number information alone; it must be determined in combination with the subroutine
        // information entries of the compilation (including inlined subroutines).

        DW_LNS_set_prologue_end:
        begin
          SmRegisters.prolouge_end := True;
        end;

        // The DW_LNS_set_epilogue_begin opcode takes no operands. It sets the epilogue_begin
        // register to “true”.

        // When a breakpoint is set on the exit of a function or execution steps over the last executable
        // statement of a function, it is generally desirable to suspend execution after completion of the
        // last statement but prior to tearing down the frame (so that local variables can still be
        // examined). Debuggers generally cannot properly determine where this point is. This
        // command allows a compiler to communicate the location(s) to use.

        // Note that the function to which the epilogue end applies cannot be directly determined from
        // the line number information alone; it must be determined in combination with the subroutine
        // information entries of the compilation (including inlined subroutines).

        // In the case of a trivial function, both prologue end and epilogue begin may occur at the same
        // address.

        DW_LNS_set_epilogue_begin:
        begin
          SmRegisters.epilouge_begin := True;
        end;

        // The DW_LNS_set_isa opcode takes a single unsigned LEB128 operand and stores that value
        // in the isa register of the state machine.

        DW_LNS_set_isa:
        begin
          SmRegisters.isa := UnitStream.ReadULEB128;
        end;

      else

        // 6.2.5.1 Special Opcodes

        // Each ubyte special opcode has the following effect on the state machine:
        // 1. Add a signed integer to the line register.
        // 2. Multiply an unsigned integer by the minimum_instruction_length field of the line number
        // program header and add the result to the address register.

        // DWARF5
        // 2. Modify the operation pointer by incrementing the address and op_index
        // registers as described below

        // 3. Append a row to the matrix using the current values of the state machine registers.
        // 4. Set the basic_block register to “false.”
        // 5. Set the prologue_end register to “false.”
        // 6. Set the epilogue_begin register to “false.”
        // 7. Set the discriminator register to 0.

        // All of the special opcodes do those same six things; they differ from one another only in what
        // values they add to the line, address and op_index registers.

        if opcode < Header64.opcode_base then
        begin
          UnitStream.Seek(OpcodeLen[opcode], soFromCurrent);
        end
        else
        begin

          // To decode a special opcode, subtract the opcode_base from the opcode itself to give the
          // adjusted opcode. The amount to increment the address register is the result of the adjusted
          // opcode divided by the line_range multiplied by the minimum_instruction_length field
          // from the header. That is,
          //  address increment = (adjusted opcode / line_range) * minimim_instruction_length

          SmRegisters.address := SmRegisters.address + CalcAddPCValue(opcode, Header64);

          // The amount to increment the line register is the line_base plus the result of the adjusted
          // opcode modulo the line_range. That is,
          //  line increment = line_base + (adjusted opcode % line_range)

          SmRegisters.line := SmRegisters.line + Header64.line_base +
            ((opcode - Header64.opcode_base) mod Header64.line_range);
        end;

        SmRegisters.basic_block := False;
        SmRegisters.prolouge_end := False;
        SmRegisters.epilouge_begin := False;
        SmRegisters.discriminator := 0;
        AddToMatrix := True;

      end;

      if AddToMatrix then
      begin
        AddToMatrix := False;

        // если база не выставлена, (а это может быть когда код тупо не вкомпилен)
        // то смысла добавлять такую информацию в словарь нет
        // также не добавляется адрес из конца последовательности
        // он как правило означает конец функции, но для этого есть
        // .debug_info с более полной информацией
        if AddrVAInited and not SmRegisters.end_sequence then
          AddLine(ACtx, SmRegisters.address, SmRegisters.file_id,
            SmRegisters.line, SmRegisters.is_stmt);

        if SmRegisters.end_sequence then
        begin
          SmRegisters := InitStateMachineRegisters(Header64.default_is_stmt);
          AddrVAInited := False;
        end;

      end;

      if UnitStream.EOF then
        Break;

      opcode := UnitStream.ReadByte;
    end;
  finally
    UnitStream.Free;
  end;

end;

function TDwarfLinesUnit.ReadFileEntry(AStream: TDwarfStream): TFileEntry;
begin
  Result.FileName := AStream.ReadString;
  if Result.FileName <> '' then
  begin
    Result.DirectoryIndex := AStream.ReadLEB128;
    Result.FileTime := AStream.ReadULEB128;
    Result.FileLength := AStream.ReadULEB128;
  end;
end;

{ TDebugInformationEntry }

function TDebugInformationEntry.GetParam(Index: Integer): string;
begin
  Result := '';
end;

function TDebugInformationEntry.ParamCount: Integer;
begin
  Result := 0;
end;

{ TDebugInformationEntrySubProgramm }

procedure TDebugInformationEntrySubProgramm.AddParam(const Value: TParam);
begin
  FParamList.Add(Value);
end;

constructor TDebugInformationEntrySubProgramm.Create(AImage64: Boolean);
begin
  FIs64 := AImage64;
  FParamList := TList<TParam>.Create;
end;

destructor TDebugInformationEntrySubProgramm.Destroy;
begin
  FParamList.Free;
  inherited;
end;

function TDebugInformationEntrySubProgramm.GetParam(Index: Integer): string;

  function IntToStrEx(Value: Integer): string;
  begin
    if Value = 0 then
      Result := ''
    else
      if Value < 0 then
        Result := '-0x' + IntToHex(-Value, 1)
      else
        Result := '+0x' + IntToHex(Value, 1);
  end;

  function GetParamSize(const AParam: TParam): string;
  begin
    case AParam.ATypeSize of
      0: Result := '';
      1: Result := 'byte ptr';
      2: Result := 'word ptr';
      4: Result := 'dword ptr';
      8: Result := 'qword ptr';
      10: Result := 'tbyte ptr';
      128: Result := 'xmmword ptr';
      256: Result := 'ymmword ptr';
      512: Result := 'zmmword ptr';
    else
      Result := Format('(%d-byte) ptr', [AParam.ATypeSize]);
    end;
  end;

  function GetReg32Name(const AParam: TParam): string;
  begin
    if AParam.BpRegister < Length(Reg32Str) then
      Result := Reg32Str[AParam.BpRegister]
    else
      Result := '';
  end;

  function GetReg64Name(const AParam: TParam): string;
  begin
    if AParam.BpRegister < Length(Reg64Str) then
      Result := Reg64Str[AParam.BpRegister]
    else
      Result := '';
  end;

var
  AParam: TParam;
begin
  AParam := FParamList[Index];
  if FIs64 then
    Result := GetReg64Name(AParam)
  else
    Result := GetReg32Name(AParam);
  if Result = '' then
    Result := 'reg {?0x' + IntToHex(AParam.BpRegister, 1) + '}';
  Result := AParam.AName + AParam.AType + ' = ' + GetParamSize(AParam) +
    ' [' + Result + IntToStrEx(AParam.BpOffset) + ']';
end;

function TDebugInformationEntrySubProgramm.LongName: string;
var
  ParamList: string;
  I: Integer;

  procedure AddParamSeparator;
  begin
    if ParamList <> '' then
      ParamList := ParamList + '; ';
  end;

var
  AParam: TParam;
begin
  if True then
  begin
    if AType = '' then
      Result := 'procedure ' + AName
    else
      Result := 'function ' + AName;
    for I := 0 to ParamCount - 1 do
    begin
      AParam := FParamList.List[I];
      case AParam.AParamType of
        ptFormalParam:
        begin
          AddParamSeparator;
          if AParam.ByRef then
            ParamList := ParamList + 'var ';
          ParamList := ParamList + AParam.AName + AParam.AType;
        end;
      end;
    end;
    if ParamList <> '' then
      ParamList := '(' + ParamList + ')';
    Result := Result + ParamList + AType + ';';
  end;
end;

function TDebugInformationEntrySubProgramm.ParamCount: Integer;
begin
  Result := FParamList.Count;
end;

function TDebugInformationEntrySubProgramm.ShortName: string;
var
  I: Integer;
begin
  Result := AName;
  for I := 0 to ParamCount - 1 do
    if FParamList.List[I].AParamType = ptFormalParam then
    begin
      Result := Result + '(...)';
      Break;
    end;
  Result := Result + AType + ';'
end;

{ TDebugInformationEntryData }

function TDebugInformationEntryData.LongName: string;
begin
  Result := AName + AType;
end;

function TDebugInformationEntryData.ShortName: string;
begin
  Result := AName;
end;

{ TDie }

procedure TDie.CalcTypeParam(AOwner: TDwarfInfoUnit;
  ADieList: TDieList; AAbsoluteAddrDict, AAddrDict: TAddrDict);
var
  Index: Integer;
  Cursor: TDie;
begin
  if ATypeID = 0 then Exit;

  Index := 0;
  Cursor := Self;
  repeat
    if Cursor.ATypeIDIsAbsolute then
    begin
      if not AAbsoluteAddrDict.TryGetValue(Cursor.ATypeID, Index) then
        Break;
    end
    else
      if not AAddrDict.TryGetValue(Cursor.ATypeID, Index) then
        Break;
    Cursor := ADieList.List[Index];
    Include(ATypeSet, Cursor.Tag);
    if ATypeIndex = 0 then
      ATypeIndex := Index;
    case Cursor.Tag of
      DW_TAG_typedef:
      begin
        if (ATypeNameIndex = 0) and (Cursor.AName <> nil) then
          ATypeNameIndex := Index;
      end;
      DW_TAG_base_type, DW_TAG_structure_type:
        ATypeSize := Cursor.ATypeSize;
    end;
  until Cursor.ATypeID = 0;
  // все ссылочные типы равны размеру указателя
  if ByRef or (DW_TAG_pointer_type in ATypeSet) then
    ATypeSize := AOwner.Header64.address_size;
end;

function TDie.GetCaption(AOwner: TDwarfInfoUnit;
  ADieList: TDieList): string;
begin
  Result := string(AName);
end;

function TDie.GetType(AOwner: TDwarfInfoUnit;
  ADieList: TDieList): string;
begin
  if ATypeID = 0 then Exit('');

  if ATypeIndex = 0 then
    Result := '<???>'
  else
  begin
    if ATypeNameIndex = 0 then
      Result := '<???>'
    else
      Result := string(ADieList.List[ATypeNameIndex].AName);
    if DW_TAG_array_type = ADieList.List[ATypeIndex].Tag then
    begin
      if AOwner.Language = DW_LANG_Pascal83 then
        Result := ADieList.List[ATypeIndex].GetCaption(AOwner, ADieList) + Result
      else
        Result := Result + ADieList.List[ATypeIndex].GetCaption(AOwner, ADieList);
    end;
  end;

  if AOwner.Language = DW_LANG_Pascal83 then
    Result := ': ' + Result;
end;

{ TDieProgramm }

function TDieProgramm.GetCaption(AOwner: TDwarfInfoUnit;
  ADieList: TDieList): string;
const
  ClassDelim: array [Boolean] of string = ('::', '.');
var
  ParentDie: TDie;
begin
  Result := '';
  ParentDie := Parent;
  while Assigned(ParentDie) do
  begin
    case ParentDie.Tag of
      DW_TAG_class_type, DW_TAG_structure_type, DW_TAG_namespace:
      begin
        if ParentDie.AName <> nil then
          Result := string(ParentDie.AName) +
            ClassDelim[AOwner.Language = DW_LANG_Pascal83] + Result;
      end;
    end;
    ParentDie := ParentDie.Parent;
  end;
  Result := Result + string(AName);
end;


{ TDieArray }

function TDieArray.GetCaption(AOwner: TDwarfInfoUnit;
  ADieList: TDieList): string;

  function GetStartSubRange: Int64;
  var
    ADie: TDie;
  begin
    Result := 0;
    ADie := Child;
    while Assigned(ADie) and (ADie.Tag <> DW_TAG_subrange_type) do
      ADie := ADie.Sibling;
    if Assigned(ADie) then
      Result := ADie.LowerBound;
  end;

var
  AArrayLen, ALowerBound: Int64;
begin
  if (ATypeSize = 0) or (ByteStride = 0) then
  begin
    if AOwner.Language = DW_LANG_Pascal83 then
      Result := 'array of '
    else
      Result := '[]';
  end
  else
  begin
    AArrayLen := ATypeSize div ByteStride;
    if AOwner.Language = DW_LANG_Pascal83 then
    begin
      ALowerBound := GetStartSubRange;
      Result := Format('array [%d..%d] of ', [ALowerBound, AArrayLen - (1 - ALowerBound)]);
    end
    else
      Result := Format('[%d]', [AArrayLen]);
  end;
  Result := Result + string(AName);
end;

{ TDwarfInfoUnit }

procedure TDwarfInfoUnit.AddToList(ACurrent, ANew: TDie;
  List: TDieList);
begin
  List.Add(ANew);
  Inc(FLoadedCount);
  if ACurrent <> nil then
  begin
    {$ifdef debug_dump}
    ANew.DebugLevel := ACurrent.DebugLevel + 1;
    {$endif}
    ANew.Parent := ACurrent;
    if ACurrent.Child = nil then
      ACurrent.Child := ANew
    else
      ACurrent.LastChild.Sibling := ANew;
    ACurrent.LastChild := ANew;
  end;

  {$ifdef debug_dump}
  var s := format('0x%s: %s(%d) %s', [
    IntToHex(ANew.DebugOffset, 8).ToLower,
    StringOfChar(' ', ANew.DebugLevel * 2),
    ANew.DebugLevel,
    DbgTagToStr(ANew.ID)]);
  FCtx.Debug.Add(s);
  {$endif}

end;

constructor TDwarfInfoUnit.Create(AModuleIndex, AUnitIndex: Integer);
begin
  FModuleIndex := AModuleIndex;
  FUnitIndex := AUnitIndex;
  FAbbrevDescrList := TList<TAbbrevDescr>.Create;
  FAttributes := TList<TAttribute>.Create;
  FData := TDwarfDataList.Create;
  FLocationBuff := TMemoryStream.Create;
  FLocationBuff.Size := MAXBYTE;
  FLocationStream := TDwarfStream.Create(FLocationBuff, 0, 0);
end;

function TDwarfInfoUnit.CreateDie(
  AAbbrevDescr: TAbbrevDescr): TDie;
begin
  case AAbbrevDescr.Tag of
    DW_TAG_array_type:
      Result := TDieArray.Create;
    DW_TAG_subprogram:
      Result := TDieProgramm.Create;
  else
    Result := TDie.Create;
  end;
  Result.OffsetID := FDieOffsetInUnit;
  Result.AbsoluteOffset := FStream.AbsolutePosition;
  Result.Tag := AAbbrevDescr.Tag;

//  if Result.AbsoluteOffset = $5dd3a then
//    Beep;
end;

destructor TDwarfInfoUnit.Destroy;
begin
  FLocationStream.Free;
  FLocationBuff.Free;
  FAbbrevDescrList.Free;
  FAttributes.Free;
  FData.Free;
  inherited;
end;

procedure TDwarfInfoUnit.FillDwarfData(ADieList: TDieList;
  AAbsoluteDict: TAddrDict; AFromIndex: Integer);
var
  AddrDict: TAddrDict;
  I, Count: Integer;
  Die: TDie;
  OutSubProgramm: TDebugInformationEntrySubProgramm;
  OutVariable: TDebugInformationEntryData;
  SymbolData: TSymbolData;

  function FillParams(AEntry: TDebugInformationEntrySubProgramm;
    ADie: TDie): Integer;
  var
    Param: TDebugInformationEntrySubProgramm.TParam;
  begin
    Result := 0;
    ADie := ADie.Child;
    while ADie <> nil do
    begin
      Inc(Result);
      ADie.CalcTypeParam(Self, ADieList, AAbsoluteDict, AddrDict);
      case ADie.Tag of
        DW_TAG_formal_parameter:
        begin
          if ADie.Artificial then
            Param.AParamType := ptArtificialParam
          else
            Param.AParamType := ptFormalParam;
          Param.AName := ADie.GetCaption(Self, ADieList);
          Param.AType := ADie.GetType(Self, ADieList);
          Param.BpLocation := ADie.BpLocation;
          Param.BpOffset := ADie.BpOffset;
          Param.BpRegister := ADie.BpRegister;
          Param.ByRef := ADie.ByRef;
          Param.ATypeSize := ADie.ATypeSize;
          AEntry.AddParam(Param);
          // для открытых массивов следующим идет размер
          // он идет как скрытый параметр, но метки Artificial не имеет
          // поэтому делаем коррекцию
          if DW_TAG_array_type = ADieList.List[ADie.ATypeIndex].Tag then
          begin
            if Assigned(ADie.Sibling) and (ADie.Sibling.Tag = DW_TAG_formal_parameter) then
              ADie.Sibling.Artificial := True;
          end;
        end;
        DW_TAG_variable:
        begin
          Param.AParamType := ptLocalVariable;
          Param.AName := ADie.GetCaption(Self, ADieList);
          Param.AType := ADie.GetType(Self, ADieList);
          Param.BpLocation := ADie.BpLocation;
          Param.BpOffset := ADie.BpOffset;
          Param.BpRegister := ADie.BpRegister;
          Param.ByRef := False;
          Param.ATypeSize := ADie.ATypeSize;
          AEntry.AddParam(Param);
        end;
      end;
      ADie := ADie.Sibling;
    end;
  end;

var
  AUnitPfx: string;
  AppendUnitName: Boolean;
begin
  AddrDict := TAddrDict.Create;
  try
    // локальный словарь текущего модуля для быстрого поиска
    for I := AFromIndex to AFromIndex + FLoadedCount - 1 do
      AddrDict.Add(ADieList.List[I].OffsetID, I);

    if FAddrStart <> 0 then
    begin
      SymbolData := MakeItem(FCtx.Image.Rebase(FAddrStart), sdtDwarfUnit);
      SymbolData.Binary.ModuleIndex := FModuleIndex;
      SymbolData.Binary.ListIndex := FUnitIndex;
      SymbolStorage.Add(SymbolData);
    end;

    AUnitPfx := '';
    AppendUnitName := FCtx.AppendUnitName;
    if AppendUnitName then
    begin
      if IndexText(AnsiString(LowerCase(ExtractFileExt(UnitName))), ['.pas', '.lpr', '.dpr']) >= 0 then
      begin
        AUnitPfx := StringReplace(UnitName, '/', PathDelim, [rfReplaceAll]);
        AUnitPfx := StringReplace(AUnitPfx, '\', PathDelim, [rfReplaceAll]);
        AUnitPfx := ExtractFileName(AUnitPfx);
        AUnitPfx := ChangeFileExt(AUnitPfx, '') + '.';
      end
      else
        AppendUnitName := False;
    end;

    I := AFromIndex;
    Count := AFromIndex + FLoadedCount;
    while I < Count do
    begin
      Die := ADieList.List[I];
      Die.CalcTypeParam(Self, ADieList, AAbsoluteDict, AddrDict);
      case Die.Tag of
        DW_TAG_subprogram,
        DW_TAG_subroutine_type,
        DW_TAG_inlined_subroutine:
        begin
          if (Die.AddrVA <> 0) or FCtx.AppendNoAddrVADie then
          begin

            OutSubProgramm := TDebugInformationEntrySubProgramm.Create(FCtx.Image.GetIs64Image);
            OutSubProgramm.AddrVA := FCtx.Image.Rebase(Die.AddrVA);
            OutSubProgramm.EndOfCode := FCtx.Image.Rebase(Die.EndOfCode);
            OutSubProgramm.Executable := True;
            OutSubProgramm.AName := Die.GetCaption(Self, ADieList);
            if AppendUnitName and (Length(OutSubProgramm.AName) > 0) and not CharInSet(OutSubProgramm.AName[1], ['$', '_']) then
              OutSubProgramm.AName := AUnitPfx + OutSubProgramm.AName;
            OutSubProgramm.AType := Die.GetType(Self, ADieList);
            Inc(I, FillParams(OutSubProgramm, Die));

            // начало функции
            if Die.AddrVA <> 0 then
            begin
              SymbolData := MakeItem(OutSubProgramm.AddrVA, sdtDwarfProc);
              SymbolData.Binary.ModuleIndex := FModuleIndex;
              SymbolData.Binary.ListIndex := FUnitIndex;
              SymbolData.Binary.Param := FData.Count;
              SymbolStorage.Add(SymbolData);
            end;

            FData.Add(OutSubProgramm);

            // конец функции
            if Die.AddrVA <> 0 then
            begin
              SymbolData.AddrVA := OutSubProgramm.EndOfCode;
              SymbolData.DataType := sdtDwarfEndProc;
              SymbolStorage.Add(SymbolData);
            end;
          end;
        end;
        DW_TAG_variable:
        begin
          if (Die.AddrVA <> 0) or FCtx.AppendNoAddrVADie then
          begin
            OutVariable := TDebugInformationEntryData.Create;
            OutVariable.AddrVA := FCtx.Image.Rebase(Die.AddrVA);
            OutVariable.AName := Die.GetCaption(Self, ADieList);
            OutVariable.AType := Die.GetType(Self, ADieList);

            if Die.AddrVA <> 0 then
            begin
              SymbolData := MakeItem(OutVariable.AddrVA, sdtDwarfData);
              SymbolData.Binary.ModuleIndex := FModuleIndex;
              SymbolData.Binary.ListIndex := FUnitIndex;
              SymbolData.Binary.Param := FData.Count;
              SymbolStorage.Add(SymbolData);
            end;

            FData.Add(OutVariable);
          end;
        end;
      end;
      Inc(I);
    end;
  finally
    AddrDict.Free;
  end;
end;

function TDwarfInfoUnit.FixedFormByteSize(AForm: UInt64): Byte;

  // The size of a reference is determined by the DWARF 32/64-bit format.
  function DwarfOffsetByteSize: Byte;
  begin
    Result := IfThen(FHeader64.magic = 0, 4, 8);
  end;

begin
  case AForm of
    DW_FORM_addr: Result := FHeader64.address_size;

    // The definition of the size of form DW_FORM_ref_addr depends on the
    // version. In DWARF v2 it's the size of an address; after that, it's the
    // size of a reference.

    DW_FORM_ref_addr:
    begin
      if FHeader64.version <= 2 then
        Result := FHeader64.address_size
      else
        Result := DwarfOffsetByteSize;
    end;

    DW_FORM_flag,
    DW_FORM_data1,
    DW_FORM_ref1,
    DW_FORM_strx1,
    DW_FORM_addrx1:
      Result := 1;

    DW_FORM_data2,
    DW_FORM_ref2,
    DW_FORM_strx2,
    DW_FORM_addrx2:
      Result := 2;

    DW_FORM_strx3: Result := 3;

    DW_FORM_data4,
    DW_FORM_ref4,
    DW_FORM_ref_sup4,
    DW_FORM_strx4,
    DW_FORM_addrx4:
      Result := 4;

    DW_FORM_strp,
    DW_FORM_GNU_ref_alt,
    DW_FORM_GNU_strp_alt,
    DW_FORM_line_strp,
    DW_FORM_sec_offset,
    DW_FORM_strp_sup:
      Result := DwarfOffsetByteSize;

    DW_FORM_data8,
    DW_FORM_ref8,
    DW_FORM_ref_sig8,
    DW_FORM_ref_sup8:
      Result := 8;

    DW_FORM_data16: Result := 16;

  else
    // floating size
    Result := 0;
  end;
end;

function TDwarfInfoUnit.Load(Ctx: TDwarfContext; ADieList: TDieList): Boolean;
var
  Magic: DWORD;
  Header32: TDebugInfoProgramHeader32;
  HeaderLength: UInt64;
begin
  Result := True;
  FLoadedCount := 0;
  FCtx := Ctx;

  if Ctx.debug_info.Size - Ctx.debug_info.Position < SizeOf(TDebugInfoProgramHeader64)  then
  begin
    Ctx.debug_info.SeekToEnd;
    Result := False;
    Exit;
  end;

  FStream := TDwarfStream.Create(Ctx.debug_info, Ctx.debug_info.Position, 0);
  try

    // A 4-byte or 12-byte unsigned integer representing the length of the .debug_info
    // contribution for that compilation unit, not including the length field itself. In the 32-bit
    // DWARF format, this is a 4-byte unsigned integer (which must be less than 0xffffff00); in
    // the 64-bit DWARF format, this consists of the 4-byte value 0xffffffff followed by an 8-
    // byte unsigned integer that gives the actual length (see Section 7.4).

    Ctx.debug_info.ReadBuffer(Magic, SizeOf(Magic));
    if Magic = Header64Magic then
    begin
      FHeader64.magic := Header64Magic;
      Ctx.debug_info.ReadBuffer(FHeader64.unit_length, SizeOf(FHeader64) - SizeOf(Magic));
      if FHeader64.unit_length = 0 then
        Exit(False);
      Inc(FHeader64.unit_length, SizeOf(FHeader64.unit_length) + SizeOf(Magic));
      HeaderLength := SizeOf(FHeader64);
    end
    else
    begin
      Header32.unit_length := Magic;
      if Header32.unit_length = 0 then
        Exit(False);
      Ctx.debug_info.ReadBuffer(Header32.version, SizeOf(Header32) - SizeOf(Magic));
      FHeader64.Magic := 0;
      FHeader64.unit_length := Header32.unit_length + SizeOf(Header32.unit_length);
      FHeader64.version := Header32.version;
      FHeader64.debug_abbrev_offset := Header32.debug_abbrev_offset;
      FHeader64.address_size := Header32.address_size;
      HeaderLength := SizeOf(Header32);
    end;

    {$message 'подрубить как появится пятый заголовок'}
//    if not (FHeader64.address_size in [4, 8]) then
//      RaiseInternal(Format('Unexpected header address_size %d', [FHeader64.address_size]));

    FStream.ReNew(FHeader64.unit_length);

    if FHeader64.version < 5 then
    begin
      FStream.Position := HeaderLength;

      // информация о том что и в каком формате записано содержится
      // в секции debug_abbrev, поэтому сначала нужно прочесть её
      Ctx.debug_abbrev.Position := FHeader64.debug_abbrev_offset;
      LoadAbbrev(Ctx.debug_abbrev);

      if FAbbrevDescrList.Count = 0 then
        Exit(False);

      Result := LoadUnit(ADieList);
    end;

    if not FStream.EOF then
    begin
      FStream.SeekToEnd;
      if FHeader64.version < 5 then
        RaiseInternal(Format('Unexpected data position %d. Expected %d.',
          [FStream.PreviosPosition, FStream.Size]));
    end;

  finally
    FStream.Free;
  end;
end;

procedure TDwarfInfoUnit.LoadAbbrev(AAbbrevData: TDwarfStream);
var
  AbbrevDescr: TAbbrevDescr;
  Attr: TAttribute;
begin
  while not AAbbrevData.EOF and (AAbbrevData.ReadULEB128 <> 0) do
  begin
    AbbrevDescr.Tag := AAbbrevData.ReadULEB128;
    AbbrevDescr.Children := AAbbrevData.ReadByte;
    AbbrevDescr.AttrIndex := FAttributes.Count;
    AbbrevDescr.AttrCount := 0;
    repeat
      Attr.ID := AAbbrevData.ReadULEB128;
      Attr.Form := AAbbrevData.ReadULEB128;
      if Attr.ID <> 0 then
      begin
        FAttributes.Add(Attr);
        Inc(AbbrevDescr.AttrCount);
      end;
    until Attr.ID = 0;
    FAbbrevDescrList.Add(AbbrevDescr);
  end;
end;

procedure TDwarfInfoUnit.LoadCompileUnit(const AAbbrevDescr: TAbbrevDescr);
var
  I: Integer;
  Attribute: TAttribute;
  TmpStrAttr: PAnsiChar;
begin
  for I := 0 to AAbbrevDescr.AttrCount - 1 do
  begin
    Attribute := FAttributes.List[AAbbrevDescr.AttrIndex + I];
    case Attribute.ID of
      DW_AT_name:
      begin
        ReadAttribute(Attribute, @TmpStrAttr, SizeOf(TmpStrAttr));
        // для юнита сразу получаем финальные данные
        // поэтому указатель необходимо преобразовать в строку
        // иначе, по разрушению дварф контекста, указатели
        // станут мусором
        FUnitName := string(TmpStrAttr);
      end;
      DW_AT_producer:
      begin
        ReadAttribute(Attribute, @TmpStrAttr, SizeOf(TmpStrAttr));
        FProducer := string(TmpStrAttr);
      end;
      DW_AT_comp_dir:
      begin
        ReadAttribute(Attribute, @TmpStrAttr, SizeOf(TmpStrAttr));
        FSourceDir := string(TmpStrAttr);
      end;
      DW_AT_language: ReadAttribute(Attribute, @FLanguage, SizeOf(FLanguage));
      DW_AT_identifier_case: ReadAttribute(Attribute, @FIdentifierCase, SizeOf(FIdentifierCase));
      DW_AT_stmt_list: ReadAttribute(Attribute, @FStmtOffset, SizeOf(FStmtOffset));
      DW_AT_low_pc: ReadAttribute(Attribute, @FAddrStart, SizeOf(FAddrStart));
      DW_AT_high_pc: ReadAttribute(Attribute, @FAddrEnd, SizeOf(FAddrEnd));
    else
      SkipUnknownAttribute(Attribute.Form);
    end;
  end;
end;

procedure TDwarfInfoUnit.LoadDIE(const AAbbrevDescr: TAbbrevDescr;
  ADie: TDie);
var
  I: Integer;
  Attribute: TAttribute;
  Artificial: Byte;
  LocationData: TLocationData;
begin
  for I := 0 to AAbbrevDescr.AttrCount - 1 do
  begin
    Attribute := FAttributes.List[AAbbrevDescr.AttrIndex + I];
    case Attribute.ID of
      DW_AT_name:
        ReadAttribute(Attribute, @ADie.AName, SizeOf(ADie.AName));
      DW_AT_type:
      begin
        ReadAttribute(Attribute, @ADie.ATypeID, SizeOf(ADie.ATypeID));
        if Attribute.Form = DW_FORM_ref_addr then
          ADie.ATypeIDIsAbsolute := True;
      end;
      DW_AT_byte_size:
        ReadAttribute(Attribute, @ADie.ATypeSize, SizeOf(ADie.ATypeSize));
      DW_AT_artificial:
      begin
        ReadAttribute(Attribute, @Artificial, SizeOf(Artificial));
        ADie.Artificial := Artificial <> 0;
      end;
      DW_AT_location:
      begin
        LocationData := LoadLocation(Attribute);
        ADie.ByRef := DW_OP_deref in LocationData.OperandSet;
        ADie.BpOffset := LocationData.BpOffset;
        ADie.BpRegister := LocationData.BpRegister;
        if DW_OP_addr in LocationData.OperandSet then
          ADie.AddrVA := LocationData.AddrVA
        else
          ADie.BpLocation := True;
      end;
      DW_AT_low_pc:
        ReadAttribute(Attribute, @ADie.AddrVA, SizeOf(ADie.AddrVA));
      DW_AT_high_pc:
        ReadAttribute(Attribute, @ADie.EndOfCode, SizeOf(ADie.EndOfCode));
      DW_AT_byte_stride:
        ReadAttribute(Attribute, @ADie.ByteStride, SizeOf(ADie.ByteStride));
      DW_AT_lower_bound:
        if Attribute.Form = DW_FORM_block1 then
          SkipUnknownAttribute(Attribute.Form)
        else
          ReadAttribute(Attribute, @ADie.LowerBound, SizeOf(ADie.LowerBound));
    else
      SkipUnknownAttribute(Attribute.Form);
    end;
  end;
end;

function TDwarfInfoUnit.LoadLocation(const Attribute: TAttribute): TLocationData;
var
  ASize: Int64;
  Opcode: Byte;
begin
  ZeroMemory(@Result, SizeOf(Result));
  ASize := ReadAttribute(Attribute, FLocationBuff.Memory, MAXBYTE);

  if ASize = 0 then
    RaiseInternal('Unexpected location zero size');

  // такое пока не умеем читать
  if Assigned(FCtx.debug_loc) then
  begin
    // технически нужно прочитать 4 байта из FLocationStream
    // это будет оффсет, откуда нужно читать структуры из стрима debug_loc
    // которые выглядят примерно так
    {
    DWORD - оффсет от DW_TAG_compile_unit -> DW_AT_low_pc (начало переменной)
    DWORD - оффсет от DW_TAG_compile_unit -> DW_AT_low_pc (конец переменной)
    Word - размер самой Location
    а далее вычитывается локейшен алгоритмом ниже,
    после чего начинаем читать следующую структуру.
    Конец цепочки наступит когда первые два оффсета равны нулю.
    Куда это применять пока не понятно
    }
    Exit;
  end;

  FLocationStream.ReNew(ASize);
  repeat
    Opcode := FLocationStream.ReadByte;
    Include(Result.OperandSet, Opcode);
    case Opcode of

      // отсутствующие опкоды, если попали сюда - значит что-то пошло не так
      DW_OP_reserved0..DW_OP_reserved2,
      DW_OP_reserved4, DW_OP_reserved5, DW_OP_reserved7,
      DW_OP_reserved170..DW_OP_reserved255:
        RaiseInternal(Format('Unexpected DW_OP opcode %d', [Opcode]));

      // обрабатываемые опкоды
      DW_OP_addr:
      begin
        Result.AddrVA := 0;
        FLocationStream.ReadBuffer(Result.AddrVA, FHeader64.address_size);
      end;
      DW_OP_deref: ; // просто флаг что парамметр идет по ссылке
      DW_OP_breg0..DW_OP_breg31:
      begin
        Result.BpRegister := Opcode - DW_OP_breg0;
        Result.BpOffset := FLocationStream.ReadLEB128;
      end;
      DW_OP_regx:
        Result.BpRegister := FLocationStream.ReadULEB128;

      // пропускаемые опкоды

        // Opcodes with a single 1 byte arguments
      DW_OP_const1u,     // 0x08 1 1-byte constant
      DW_OP_const1s,     // 0x09 1 1-byte constant
      DW_OP_pick,        // 0x15 1 1-byte stack index
      DW_OP_deref_size,  // 0x94 1 1-byte size of data retrieved
      DW_OP_xderef_size: // 0x95 1 1-byte size of data retrieved
        FLocationStream.Seek(1, soFromCurrent);

      // Opcodes with a single 2 byte arguments
      DW_OP_const2u,     // 0x0a 1 2-byte constant
      DW_OP_const2s,     // 0x0b 1 2-byte constant
      DW_OP_skip,        // 0x2f 1 signed 2-byte constant
      DW_OP_bra,         // 0x28 1 signed 2-byte constant
      DW_OP_call2:       // 0x98 1 2-byte offset of DIE (DWARF3)
        FLocationStream.Seek(2, soFromCurrent);

      // Opcodes with a single 4 byte arguments
      DW_OP_const4u,     // 0x0c 1 4-byte constant
      DW_OP_const4s,     // 0x0d 1 4-byte constant
      DW_OP_call4:       // 0x99 1 4-byte offset of DIE (DWARF3)
        FLocationStream.Seek(4, soFromCurrent);

      // Opcodes with a single 8 byte arguments
      DW_OP_const8u,     // 0x0e 1 8-byte constant
      DW_OP_const8s:     // 0x0f 1 8-byte constant
        FLocationStream.Seek(8, soFromCurrent);

      // Opcodes that have a single ULEB (signed or unsigned) argument
      DW_OP_constu,      // 0x10 1 ULEB128 constant
      DW_OP_consts,      // 0x11 1 SLEB128 constant
      DW_OP_plus_uconst, // 0x23 1 ULEB128 addend
      DW_OP_fbreg,       // 0x91 1 SLEB128 offset
      DW_OP_piece,       // 0x93 1 ULEB128 size of piece addressed
      DW_OP_addrx,       // 0xa1 1 ULEB128 indirect address (DWARF5)
      DW_OP_constx,      // 0xa2 1 ULEB128 indirect constant (DWARF5)
      DW_OP_convert,     // 0xa8 1 ULEB128 type entry offset (DWARF5)
      DW_OP_reinterpret: // 0xa9 1 ULEB128 type entry offset (DWARF5)
        FLocationStream.ReadULEB128;

      // Opcodes that have a 2 ULEB (signed or unsigned) arguments
      DW_OP_bregx,       // 0x92 2 ULEB128 register followed by SLEB128 offset
      DW_OP_bit_piece,   // 0x9d 2 ULEB128 bit size, ULEB128 bit offset (DWARF3)
      DW_OP_regval_type: // 0xa5 2 ULEB128 register number, ULEB128 constant offset (DWARF5)
      begin
        FLocationStream.ReadULEB128;
        FLocationStream.ReadULEB128;
      end;

      DW_OP_implicit_value, // 0x9e ULEB128 size, block of that size (DWARF4)
      DW_OP_entry_value:    // 0xa3 ULEB128 size, block of that size (DWARF5)
        FLocationStream.Seek(FLocationStream.ReadULEB128, soFromCurrent);

      DW_OP_deref_type,  // 0xa6 2 1-byte size, ULEB128 type entry offset (DWARF5)
      DW_OP_xderef_type: // 0xa7 2 1-byte size, ULEB128 type entry offset (DWARF5)
      begin
        FLocationStream.Seek(1, soFromCurrent);
        FLocationStream.ReadULEB128;
      end;

      DW_OP_const_type:  // 0xa4 3 ULEB128 type entry offset, 1-byte size, constant value (DWARF5)
      begin
        FLocationStream.ReadULEB128;
        FLocationStream.Seek(FLocationStream.ReadByte, soFromCurrent);
      end;

      DW_OP_call_ref:   // 0x9a 1 4- or 8-byte offset of DIE (DWARF3)
        FLocationStream.Seek(IfThen(FHeader64.magic = 0, 4, 8), soFromCurrent);

      DW_OP_implicit_pointer: // 0xa0 2 4- or 8-byte offset of DIE, SLEB128 constant offset (DWARF5)
      begin
        FLocationStream.Seek(IfThen(FHeader64.magic = 0, 4, 8), soFromCurrent);
        FLocationStream.ReadULEB128;
      end;

    else
      // опкоды без параметров
    end;
  until FLocationStream.EOF;
end;

function TDwarfInfoUnit.LoadUnit(ADieList: TDieList): Boolean;
var
  AbbrevIndex: UInt64;
  AbbrevDescr: TAbbrevDescr;
  DieCurrent,
  DieNew: TDie;
begin
  Result := False;

  DieCurrent := nil;
  AbbrevIndex := FStream.ReadULEB128;
  while AbbrevIndex <> 0 do
  begin

    FDieOffsetInUnit := FStream.PreviosPosition;
    FDieOffsetInImage := FStream.PreviosNativePosition;

    if (AbbrevIndex = 0) or (AbbrevIndex > FAbbrevDescrList.Count) then
      RaiseInternal('Unexpected Tag Index ' + IntToStr(AbbrevIndex));

    AbbrevDescr := FAbbrevDescrList.List[AbbrevIndex - 1];
    DieNew := CreateDie(AbbrevDescr);

    try

      if AbbrevDescr.Tag = DW_TAG_compile_unit then
      begin
        // этот тэг должен идти самым первым и единственным
        // на всей последовательности
        if FUnitName <> '' then
          RaiseInternal('Unexpected DW_TAG_compile_unit');
        LoadCompileUnit(AbbrevDescr);
      end
      else
        LoadDIE(AbbrevDescr, DieNew);

    except
      DieNew.Free;
      FStream.SeekToEnd;
      Exit;
    end;

    AddToList(DieCurrent, DieNew, ADieList);
    if AbbrevDescr.Children > 0 then
      DieCurrent := DieNew;

    // проверка на пустой юнит представленый только именем модуля
    if FStream.EOF and (FAbbrevDescrList.Count = 1) then
    begin
      // на всякий случай проверим что DW_TAG_compile_unit был загружен
      if FUnitName = '' then
        RaiseInternal('Unexpected EOF');
      Break
    end
    else
      AbbrevIndex := FStream.ReadULEB128;

    while (AbbrevIndex = 0) and RevertToParent(DieCurrent) and not FStream.EOF do
      AbbrevIndex := FStream.ReadULEB128;

  end;

  Result := FLoadedCount > 0;
end;

procedure TDwarfInfoUnit.RaiseInternal(const AMessage: string);
begin
  raise Exception.CreateFmt('Internal error. %s at offset %d',
    [AMessage, FDieOffsetInImage]);
end;

function TDwarfInfoUnit.ReadAttribute(const Attribute: TAttribute;
  pBuff: Pointer; ASize: UInt64; AttributeStream: TDwarfStream): Int64;

  procedure CheckBuffSize(NeedSize: UInt64);
  begin
    if ASize < NeedSize then
      RaiseInternal(Format('Buff size too small %d. Expected %d', [ASize, NeedSize]))
    else
      Result := Int64(NeedSize);
  end;

  // данные могут сидеть в другой секции
  // пока что такая ситуация не обрабатывается
  // но чтобы не забыть - вынесено в отдельную процедуру
  procedure LoadRelocated(ASize: UInt64; ARelocStream: TDwarfStream = nil);
  var
    ULeb: UInt64;
  begin
    if ARelocStream = nil then
      FStream.ReadBuffer(pBuff^, ASize)
    else
    begin
      CheckBuffSize(SizeOf(Pointer));
      ULeb := 0;
      FStream.ReadBuffer(ULeb, ASize);
      ARelocStream.Position := ULeb;
      PPointer(pBuff)^ := ARelocStream.ReadPAnsiChar;
    end;
  end;

  procedure LoadBlock(ABlockSize: UInt64);
  begin
    CheckBuffSize(ABlockSize);
    FStream.ReadBuffer(pBuff^, ABlockSize);
  end;

var
  AForm, NeedSize, ULeb: UInt64;
  SLeb: Int64;
  Indirect: Boolean;
begin
  ZeroMemory(pBuff, ASize);
  AForm := Attribute.Form;
  repeat
    Indirect := False;

    // первичная проверка, вообще мы влезем или нет?
    NeedSize := FixedFormByteSize(AForm);
    CheckBuffSize(NeedSize);

    case AForm of
      DW_FORM_addr,
      DW_FORM_ref_addr,
      DW_FORM_data4,
      DW_FORM_ref4,
      DW_FORM_ref_sup4,
      DW_FORM_strx4,
      DW_FORM_addrx4,
      DW_FORM_GNU_ref_alt,
      DW_FORM_GNU_strp_alt,
      DW_FORM_sec_offset,
      DW_FORM_strp_sup:
        LoadRelocated(NeedSize, AttributeStream);

      DW_FORM_block2:
        LoadBlock(FStream.ReadWord);

      DW_FORM_block4:
        LoadBlock(FStream.ReadDWORD);

      DW_FORM_data2,
      DW_FORM_ref2,
      DW_FORM_strx2,
      DW_FORM_addrx2,
      DW_FORM_strx3,
      DW_FORM_data1,
      DW_FORM_ref1,
      DW_FORM_flag,
      DW_FORM_strx1,
      DW_FORM_addrx1,
      DW_FORM_data8,
      DW_FORM_ref8,
      DW_FORM_ref_sup8:
        FStream.ReadBuffer(pBuff^, NeedSize);

      DW_FORM_string:
      begin
        CheckBuffSize(SizeOf(Pointer));
        PPointer(pBuff)^ := FStream.ReadPAnsiChar;
      end;

      DW_FORM_sdata:
      begin
        if Abs(SLeb) > MAXDWORD then
          CheckBuffSize(8);
        if Abs(SLeb) > MAXWORD then
          CheckBuffSize(4);
        if Abs(SLeb) > MAXBYTE then
          CheckBuffSize(2);
        SLeb := FStream.ReadLEB128;
        Move(SLeb, pBuff^, ASize);
      end;

      DW_FORM_strp:
        LoadRelocated(NeedSize, FCtx.debug_str);

      DW_FORM_line_strp:
        LoadRelocated(NeedSize, FCtx.debug_line_str);

      DW_FORM_block,
      DW_FORM_exprloc:
        LoadBlock(FStream.ReadULEB128);

      DW_FORM_block1:
        LoadBlock(FStream.ReadByte);

      DW_FORM_udata,
      DW_FORM_ref_udata,
      DW_FORM_strx,
      DW_FORM_rnglistx,
      DW_FORM_GNU_addr_index,
      DW_FORM_GNU_str_index:
      begin
        ULeb := FStream.ReadULEB128;
        if ULeb > MAXDWORD then
          CheckBuffSize(8);
        if ULeb > MAXWORD then
          CheckBuffSize(4);
        if ULeb > MAXBYTE then
          CheckBuffSize(2);
        Move(ULeb, pBuff^, ASize);
      end;

      DW_FORM_indirect:
      begin
        AForm := FStream.ReadULEB128;
        Indirect := True;
      end;

      DW_FORM_flag_present:
        PByte(pBuff)^ := 1;

      DW_FORM_data16:
        LoadBlock(NeedSize);

    else
      RaiseInternal(Format('Unknown Form %d', [AForm]));
    end;

  until not Indirect;
end;

function TDwarfInfoUnit.RevertToParent(var ACurrent: TDie): Boolean;
begin
  if Assigned(ACurrent) then
    ACurrent := ACurrent.Parent
  else
    // это пока для проверки что дерево построилось правильно
    // в противном случае выход на nil произойдет ДО завершения
    // чтения всех данных
    RaiseInternal('Unexpected zero tag index');
  Result := Assigned(ACurrent);
end;

procedure TDwarfInfoUnit.SkipUnknownAttribute(AForm: UInt64);
var
  Indirect: Boolean;
begin
  repeat
    Indirect := False;
    case AForm of
      DW_FORM_addr,
      DW_FORM_ref_addr,
      DW_FORM_flag_present,
      DW_FORM_data1,
      DW_FORM_data2,
      DW_FORM_data4,
      DW_FORM_data8,
      DW_FORM_data16,
      DW_FORM_flag,
      DW_FORM_ref1,
      DW_FORM_ref2,
      DW_FORM_ref4,
      DW_FORM_ref8,
      DW_FORM_ref_sig8,
      DW_FORM_ref_sup4,
      DW_FORM_ref_sup8,
      DW_FORM_strx1,
      DW_FORM_strx2,
      DW_FORM_strx4,
      DW_FORM_addrx1,
      DW_FORM_addrx2,
      DW_FORM_addrx4,
      DW_FORM_sec_offset,
      DW_FORM_strp,
      DW_FORM_strp_sup,
      DW_FORM_line_strp,
      DW_FORM_GNU_ref_alt,
      DW_FORM_GNU_strp_alt:
        FStream.Seek(FixedFormByteSize(AForm), soCurrent);

      DW_FORM_block2:
        FStream.Seek(FStream.ReadWord, soCurrent);

      DW_FORM_block4:
        FStream.Seek(FStream.ReadDWORD, soCurrent);

      DW_FORM_string:
        FStream.ReadPAnsiChar;

      DW_FORM_block, DW_FORM_exprloc:
        FStream.Seek(FStream.ReadULEB128, soCurrent);

      DW_FORM_block1:
        FStream.Seek(FStream.ReadByte, soCurrent);

      DW_FORM_sdata:
        FStream.ReadLEB128;

      DW_FORM_udata,
      DW_FORM_ref_udata,
      DW_FORM_strx,
      DW_FORM_addrx,
      DW_FORM_loclistx,
      DW_FORM_rnglistx,
      DW_FORM_GNU_addr_index,
      DW_FORM_GNU_str_index:
        FStream.ReadULEB128;

      DW_FORM_indirect:
      begin
        Indirect := True;
        AForm := FStream.ReadULEB128;
      end;

    else
      RaiseInternal(Format('Unknown Form %d', [AForm]));
    end;
  until not Indirect;

end;

function TDwarfInfoUnit.UnitName: string;
begin
  Result := FUnitName;
end;

{ TDwarfDebugInfo }

constructor TDwarfDebugInfo.Create(AImage: TAbstractImageGate);
begin
  FImage := AImage;
  FMappedUnit := -1;
  FMappedUnitLines := TList<TDwarfLinesUnit>.Create;
  FUnitLines := TUnitLinesList.Create;
  FUnitInfos := TUnitInfosList.Create;
end;

destructor TDwarfDebugInfo.Destroy;
begin
  FUnitLines.Free;
  FUnitInfos.Free;
  FMappedUnitLines.Free;
  inherited;
end;

procedure TDwarfDebugInfo.DoBeforeLoadCallback;
begin
  if Assigned(BeforeLoadCallback) then
    BeforeLoadCallback(Self);
end;

procedure TDwarfDebugInfo.DoCallback(AStep: TLoadCallbackStep; ACurrent,
  AMax: Int64);
begin
  if Assigned(LoadCallback) then
    LoadCallback(AStep, ACurrent, AMax);
end;

function TDwarfDebugInfo.GetUnitAtStmt(StmtOffset: DWORD): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to FUnitInfos.Count - 1 do
    if FUnitInfos[I].StmtOffset = StmtOffset then
    begin
      Result := I;
      Break;
    end;
end;

function TDwarfDebugInfo.Load(AStream: TStream): TDebugInfoTypes;
var
  Ctx: TDwarfContext;
begin
  Result := [];
  Ctx := TDwarfContext.Create(FImage, AStream);
  try
    DoBeforeLoadCallback;
    Ctx.AppendUnitName := AppendUnitName;
    Ctx.AppendNoAddrVADie := AppendNoAddrVADie;
    if LoadInfo(Ctx) then
      Include(Result, ditDwarfDie);
    if LoadLines(Ctx) then
      Include(Result, ditDwarfLines);
    if LoadStub(Ctx) then
      Include(Result, ditStab);
  finally
    Ctx.Free;
  end;
  LoadCallback := nil;
end;

function TDwarfDebugInfo.LoadInfo(Ctx: TDwarfContext): Boolean;
var
  AUnit: TDwarfInfoUnit;
  DieList: TDieList;
  AAbsoluteDict: TAddrDict;
  I, LoadIndex: Integer;
  {$IFDEF USE_PROFILING}
  sw: TStopwatch;
  {$ENDIF}
begin
  Result := (Ctx.debug_info <> nil) and (Ctx.debug_abbrev <> nil);
  if not Result then Exit;
  DoCallback(lcsLoadInfo, 0, Ctx.debug_info.Size);
  DieList := TDieList.Create;
  try
    // загружаем все данные в общий список без их обработки
    while not Ctx.debug_info.EOF do
    begin
      AUnit := TDwarfInfoUnit.Create(FImage.ModuleIndex, FUnitInfos.Count);
      try
        {$IFDEF USE_PROFILING}
        sw := TStopwatch.StartNew;
        {$ENDIF}
        if not AUnit.Load(Ctx, DieList) then
          FreeAndNil(AUnit)
        else
          FUnitInfos.Add(AUnit);
        {$IFDEF USE_PROFILING}
        AUnit.Elapsed := sw.ElapsedMilliseconds;
        {$ENDIF}
        DoCallback(lcsLoadInfo, Ctx.debug_info.Position, Ctx.debug_info.Size);
      except
        AUnit.Free;
        Result := False;
        Break;
      end;
    end;
    DoCallback(lcsLoadInfo, Ctx.debug_info.Size, Ctx.debug_info.Size);

    // теперь переносим найденые процедуры в модули
    // с обработкой типов через словарь абсолютных смещений
    // который можно построить только после полной загрузки данных

    DoCallback(lcsProcessInfo, 0, DieList.Count);
    AAbsoluteDict := TAddrDict.Create;
    try
      for I := 0 to DieList.Count - 1 do
        AAbsoluteDict.Add(DieList.List[I].AbsoluteOffset, I);
      LoadIndex := 0;
      for AUnit in FUnitInfos do
      begin
        {$IFDEF USE_PROFILING}
        sw := TStopwatch.StartNew;
        {$ENDIF}
        AUnit.FillDwarfData(DieList, AAbsoluteDict, LoadIndex);
        {$IFDEF USE_PROFILING}
        AUnit.Elapsed := AUnit.Elapsed + sw.ElapsedMilliseconds;
        {$ENDIF}
        Inc(LoadIndex, AUnit.LoadedCount);
        DoCallback(lcsProcessInfo, LoadIndex, DieList.Count);
      end;
    finally
      AAbsoluteDict.Free;
    end;
    DoCallback(lcsProcessInfo, DieList.Count, DieList.Count);

  finally
    DieList.Free;
  end;
end;

function TDwarfDebugInfo.LoadLines(Ctx: TDwarfContext): Boolean;
var
  AUnit: TDwarfLinesUnit;
  {$IFDEF USE_PROFILING}
  sw: TStopwatch;
  {$ENDIF}
begin
  Result := Ctx.debug_line <> nil;
  if not Result then Exit;
  DoCallback(lcsLoadLines, 0, Ctx.debug_line.Size);
  while not Ctx.debug_line.EOF do
  begin
    AUnit := TDwarfLinesUnit.Create(FImage.ModuleIndex, FUnitLines.Count,
      GetUnitAtStmt(Ctx.debug_line.Position));
    try
      {$IFDEF USE_PROFILING}
      sw := TStopwatch.StartNew;
      {$ENDIF}
      if not AUnit.Load(Ctx) then
      begin
        FreeAndNil(AUnit);
        Break;
      end;
      {$IFDEF USE_PROFILING}
      AUnit.Elapsed := sw.ElapsedMilliseconds;
      {$ENDIF}
      FUnitLines.Add(AUnit);
      DoCallback(lcsLoadLines, Ctx.debug_line.Position, Ctx.debug_line.Size);
    except
      AUnit.Free;
      Result := False;
      Break;
    end;
  end;
  DoCallback(lcsLoadLines, Ctx.debug_line.Size, Ctx.debug_line.Size);
end;

function TDwarfDebugInfo.LoadStub(Ctx: TDwarfContext): Boolean;
var
  Loader: TStabLoader;
begin
  // стабы присутствуют только у 32 битных программ со вторым дварфом
  if (Ctx.stab = nil) or (Ctx.stabstr = nil) then
    Exit(False);

  Loader := TStabLoader.Create(Self, Ctx);
  try
    Result := Loader.Load;
  finally
    Loader.Free;
  end;
end;

function TDwarfDebugInfo.MappedUnitLines(
  AUnitInfoIndex: Integer): TList<TDwarfLinesUnit>;
var
  I: Integer;
begin
  Result := FMappedUnitLines;
  if FMappedUnit <> AUnitInfoIndex then
  begin
    FMappedUnitLines.Clear;
    FMappedUnit := AUnitInfoIndex;
    if FMappedUnit < 0 then Exit;
    for I := 0 to UnitLines.Count - 1 do
      if UnitLines[I].MappedUnitIndex = FMappedUnit then
        FMappedUnitLines.Add(UnitLines[I]);
  end;
end;

{ TStabSubProgramm }

function TStabSubProgramm.LongName: string;
begin
  Result := Format('[%s] %s', [AUnitName, ShortName]);
end;

{ TStabLoader }

constructor TStabLoader.Create(ADwarf: TDwarfDebugInfo; ACtx: TDwarfContext);
begin
  FCtx := ACtx;
  FDwarf := ADwarf;
  FDirAndFilesDict := TDictionary<string, Integer>.Create;
end;

destructor TStabLoader.Destroy;
begin
  FDirAndFilesDict.Free;
  inherited;
end;

function TStabLoader.Load: Boolean;
var
  ALineUnit: TDwarfLinesUnit;
  AInfoUnit: TDwarfInfoUnit;
  AStubs: array of TStab;
  I, Count: Integer;
  OutSubProgramm: TStabSubProgramm;
  OutVariable: TDebugInformationEntryData;
  AUnitName, AUnitDir: string;
  Param: TDebugInformationEntrySubProgramm.TParam;
  SymbolData: TSymbolData;
  AModuleIndex, AUnitListIndex, ALineListIndex: Integer;

  procedure PushSubProgramm;
  begin
    OutSubProgramm.AUnitName := AUnitName;

    SymbolData := MakeItem(OutSubProgramm.AddrVA, sdtDwarfProc);
    SymbolData.Binary.ModuleIndex := AModuleIndex;
    SymbolData.Binary.ListIndex := AUnitListIndex;
    SymbolData.Binary.Param := AInfoUnit.Data.Count;
    SymbolStorage.Add(SymbolData);

    AInfoUnit.Data.Add(OutSubProgramm);

    if OutSubProgramm.EndOfCode <> 0 then
    begin
      SymbolData.AddrVA := OutSubProgramm.EndOfCode;
      SymbolData.DataType := sdtDwarfEndProc;
      SymbolStorage.Add(SymbolData);
    end;

    OutSubProgramm := nil;
  end;

  procedure PushLine(AddrVA: ULONG_PTR64; LineNumber: Integer);
  var
    DirIndex, FileIndex: Integer;
    FileEntry: TFileEntry;
  begin
    // пакуем строковые данные по директориям и файлам
    // причем учитываем особенность что индексы идут от единицы и нулевой
    // означает что индекса нет
    DirIndex := 0;
    if AUnitDir <> '' then
    begin
      if not FDirAndFilesDict.TryGetValue(AUnitDir, DirIndex) then
      begin
        DirIndex := ALineUnit.DirList.Add(AUnitDir) + 1;
        FDirAndFilesDict.Add(AUnitDir, DirIndex);
      end;
    end;

    if not FDirAndFilesDict.TryGetValue(AUnitName, FileIndex) then
    begin
      FileEntry.FileName := AUnitName;
      FileEntry.DirectoryIndex := DirIndex;
      FileEntry.FileTime := 0;
      FileEntry.FileLength := 0;
      FileIndex := ALineUnit.Files.Add(FileEntry) + 1;
      FDirAndFilesDict.Add(AUnitName, FileIndex);
    end;

    ALineUnit.AddLine(FCtx, AddrVA, FileIndex, LineNumber, True);
  end;

begin
  Count := FCtx.stab.Size div SizeOf(TStab);
  if Count = 0 then Exit(False);
  FDwarf.DoCallback(lcsLoadLines, 0, Count);
  SetLength(AStubs, Count);
  FCtx.stab.ReadBuffer(AStubs[0], FCtx.stab.Size);

  OutSubProgramm := nil;
  AModuleIndex := FCtx.Image.ModuleIndex;
  AUnitListIndex := FDwarf.UnitInfos.Count;
  ALineListIndex := FDwarf.UnitLines.Count;

  // стабы не самостоятельны и будут добавлены отдельной записью в общий пул
  AInfoUnit := TDwarfInfoUnit.Create(AModuleIndex, AUnitListIndex);
  ALineUnit := TDwarfLinesUnit.Create(AModuleIndex, ALineListIndex,
    FDwarf.UnitInfos.Add(AInfoUnit));
  FDwarf.UnitLines.Add(ALineUnit);

  for I := 0 to Count - 1 do
    case AStubs[I].n_type of
      N_FNAME, N_FUN:
      begin
        if AStubs[I].n_value <> 0 then
        begin
          if Assigned(OutSubProgramm) then
            PushSubProgramm; // такого по идее быть не должно!
          AUnitName := '';
          AUnitDir := '';
          OutSubProgramm := TStabSubProgramm.Create(FCtx.Image.GetIs64Image);
          OutSubProgramm.Executable := True;
          OutSubProgramm.AName := ReadString(AStubs[I].n_strx);
          OutSubProgramm.AddrVA := FCtx.Image.Rebase(AStubs[I].n_value);
        end;
      end;
      N_SO, N_SOL:
      begin
        AUnitName := ReadString(AStubs[I].n_strx);
        Split(AUnitName, AUnitDir);
      end;
      N_SLINE:
      begin
        if OutSubProgramm = nil then
          Continue;
        OutSubProgramm.EndOfCode := OutSubProgramm.AddrVA + AStubs[I].n_value;
        PushLine(OutSubProgramm.EndOfCode, AStubs[I].n_desc);
      end;
      N_RBRAC:
      begin
        if Assigned(OutSubProgramm) then
        begin
          OutSubProgramm.EndOfCode := OutSubProgramm.AddrVA + AStubs[I].n_value;
          PushSubProgramm;
        end;
      end;
      N_PSYM:
      begin
        if OutSubProgramm = nil then
          Continue;
        Param.AParamType := ptLocalVariable;
        Param.AName := ReadString(AStubs[I].n_strx);
        Param.AType := '';
        Param.BpLocation := True;
        Param.BpOffset := Integer(AStubs[I].n_value);
        Param.BpRegister := IfThen(FCtx.Image.GetIs64Image, 6, 5);
        Param.ByRef := False;
        Param.ATypeSize := 0;
        OutSubProgramm.AddParam(Param);
      end;
      N_STSYM, N_LCSYM:
      begin
        OutVariable := TDebugInformationEntryData.Create;
        OutVariable.AName := ReadString(AStubs[I].n_strx);
        OutVariable.AddrVA := FCtx.Image.Rebase(AStubs[I].n_value);

        SymbolData := MakeItem(OutVariable.AddrVA, sdtDwarfData);
        SymbolData.Binary.ModuleIndex := AModuleIndex;
        SymbolData.Binary.ListIndex := AUnitListIndex;
        SymbolData.Binary.Param := AInfoUnit.Data.Count;
        SymbolStorage.Add(SymbolData);

        AInfoUnit.Data.Add(OutVariable);
      end;
    end;

  Result := AInfoUnit.Data.Count > 0;
end;

function TStabLoader.ReadString(strx: LongInt): string;
var
  Index: Integer;
begin
  FCtx.stabstr.Position := strx;
  Result := string(FCtx.stabstr.ReadPAnsiChar);
  Index := Pos(':', Result);
  if Index > 0 then
    SetLength(Result, Index - 1);
end;

procedure TStabLoader.Split(var AUnitName: string; out AUnitPath: string);
var
  TmpName: string;
  I: Integer;
begin
  AUnitName := StringReplace(AUnitName, '/', PathDelim, [rfReplaceAll]);
  TmpName := ExtractFileName(AUnitName);
  if TmpName = AUnitName then
    AUnitPath := ''
  else
  begin
    I := 1;
    while CharInSet(AUnitName[I], ['.', PathDelim]) do
      Inc(I);
    AUnitPath := Copy(AUnitName, I, Length(AUnitName) - I - Length(TmpName));
    AUnitName := TmpName;
  end;
end;

end.
