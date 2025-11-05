// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ECOFF_H
#define ECOFF_H

#include <rz_util.h>
#include <rz_bin.h>

// ECoff machine/magic types
#define ECOFF_MACHINE_MIPS1     0x0180 // MIPS I
#define ECOFF_MACHINE_MIPS1_EL  0x0162 // MIPS I
#define ECOFF_MACHINE_MIPS1_BE  0x0160 // MIPS I
#define ECOFF_MACHINE_MIPS2_EL  0x0166 // MIPS II
#define ECOFF_MACHINE_MIPS2_BE  0x0163 // MIPS II
#define ECOFF_MACHINE_MIPS3_EL  0x0142 // MIPS III
#define ECOFF_MACHINE_MIPS3_BE  0x0140 // MIPS III
#define ECOFF_MACHINE_ALPHA     0x0185
#define ECOFF_MACHINE_ALPHA_BSD 0x0183

// ECoff header flags
#define ECOFF_F_FLAGS_RELFLG         0x0001 // File does not contain relocation information. This flag applies to actual relocations only, not compact relocations.
#define ECOFF_F_FLAGS_EXEC           0x0002 // File is executable (has no unresolved external references).
#define ECOFF_F_FLAGS_LNNO           0x0004 // Line numbers are stripped from file.
#define ECOFF_F_FLAGS_LSYMS          0x0008 // Local symbols are stripped from file.
#define ECOFF_F_FLAGS_NO_SHARED      0x0010 // Non-sharable object
#define ECOFF_F_FLAGS_NO_CALL_SHARED 0x0020 // Object file cannot be used to create a -call_shared (dynamic) executable file.
#define ECOFF_F_FLAGS_LOMAP          0x0040 // Allows a static executable file to be loaded at an address less than VM_MIN_ADDRESS (0x10000). This flag cannot be used by dynamic executables.
#define ECOFF_F_FLAGS_NO_REORG       0x4000 // Tells object consumer not to reorder sections.
#define ECOFF_F_FLAGS_NO_REMOVE      0x8000 // Tells object consumer not to remove NOPs.

#define ECOFF_F_FLAGS_ALPHA_OBJ_MASK    0x3000 // Mask for the value below.
#define ECOFF_F_FLAGS_ALPHA_NO_SHARED   0x1000 // Non-sharable object
#define ECOFF_F_FLAGS_ALPHA_SHARABLE    0x2000 // Shared library.
#define ECOFF_F_FLAGS_ALPHA_CALL_SHARED 0x3000 // Dynamic executable file.

#define ECOFF_F_FLAGS_IS_STRIPPED (ECOFF_F_FLAGS_RELFLG | ECOFF_F_FLAGS_LNNO | ECOFF_F_FLAGS_LSYMS)

// ECoff aouthdr magic
#define ECOFF_AOUTHDR_OMAGIC   0x0107 // .text segment is read-write but not shareable
#define ECOFF_AOUTHDR_NMAGIC   0x0108 // .text segment is read-write & shareable
#define ECOFF_AOUTHDR_SMAGIC   0x0109 // used by the kernel when converting mips ELF to ECoff
#define ECOFF_AOUTHDR_ZMAGIC   0x010b // .text and .data are splitted and .text is readonly and shareable
#define ECOFF_AOUTHDR_LIBMAGIC 0x0123 // used by the kernel when converting mips ELF to ECoff

// ECoff section types
#define ECOFF_SECTION_TYPE_REG          0x00000000 // Regular section: allocated, relocated, loaded. User section flags have this setting.
#define ECOFF_SECTION_TYPE_TEXT         0x00000020 // Text section
#define ECOFF_SECTION_TYPE_DATA         0x00000040 // Data section
#define ECOFF_SECTION_TYPE_BSS          0x00000080 // Bss section
#define ECOFF_SECTION_TYPE_RDATA        0x00000100 // Read-only data section
#define ECOFF_SECTION_TYPE_SDATA        0x00000200 // Small data
#define ECOFF_SECTION_TYPE_SBSS         0x00000400 // Small bss
#define ECOFF_SECTION_TYPE_UCODE        0x00000800 // U-Code
#define ECOFF_SECTION_TYPE_GOT1         0x00001000 // Global offset table
#define ECOFF_SECTION_TYPE_DYNAMIC1     0x00002000 // Dynamic linking information
#define ECOFF_SECTION_TYPE_DYNSYM1      0x00004000 // Dynamic linking symbol table
#define ECOFF_SECTION_TYPE_REL_DYN1     0x00008000 // Dynamic relocation information
#define ECOFF_SECTION_TYPE_DYNSTR1      0x00010000 // Dynamic linking symbol table
#define ECOFF_SECTION_TYPE_HASH1        0x00020000 // Dynamic symbol hash table
#define ECOFF_SECTION_TYPE_DSOLIST1     0x00040000 // Shared library dependency list
#define ECOFF_SECTION_TYPE_MSYM1        0x00080000 // Additional dynamic linking symbol table
#define ECOFF_SECTION_TYPE_LIT4         0x10000000 // 4-byte literals
#define ECOFF_SECTION_TYPE_NRELOC_OVFL2 0x20000000 // Indicates that section header field s_nreloc overflowed
#define ECOFF_SECTION_TYPE_LIB          0x40000000 // Shared Library
#define ECOFF_SECTION_TYPE_INIT         0x80000000 // Initialization text

// ECoff extended section types
#define ECOFF_SECTION_EXT_TYPE_MASK 0x0ff00000

#define ECOFF_SECTION_EXT_TYPE_CONFLICT1 0x00100000 // Additional dynamic linking information
#define ECOFF_SECTION_EXT_TYPE_RESOURCE  0x00200000 // Resource
#define ECOFF_SECTION_EXT_TYPE_FINI      0x01000000 // Termination text
#define ECOFF_SECTION_EXT_TYPE_COMMENT1  0x02000000 // Comment section
#define ECOFF_SECTION_EXT_TYPE_COMMENT2  0x02100000 // Comment section
#define ECOFF_SECTION_EXT_TYPE_RCONST    0x02200000 // Read-only constants
#define ECOFF_SECTION_EXT_TYPE_XDATA     0x02400000 // Exception scope table
#define ECOFF_SECTION_EXT_TYPE_TLSDATA   0x02500000 // Initialized TLS data
#define ECOFF_SECTION_EXT_TYPE_TLSBSS    0x02600000 // Uninitialized TLS data
#define ECOFF_SECTION_EXT_TYPE_TLSINIT   0x02700000 // Initialization for TLS data
#define ECOFF_SECTION_EXT_TYPE_PDATA     0x02800000 // Exception procedure table
#define ECOFF_SECTION_EXT_TYPE_LITA      0x04000000 // Address literals
#define ECOFF_SECTION_EXT_TYPE_LIT8      0x08000000 // 8-byte literals

// ECoff Symbols Special Section Number
// Normally these must be between 0x0001-0x7fff (077777o) and defines
// which is the section number where symbol is defined.
#define ECOFF_SYMBOL_SECT_NUM_DEBUG -2 // Special symbolic debugging symbol
#define ECOFF_SYMBOL_SECT_NUM_ABS   -1 // Absolute symbol
#define ECOFF_SYMBOL_SECT_NUM_UNDEF 0 // Undefined external symbol

// ECoff Symbols Storage Class
#define ECOFF_SYMBOL_SCLASS_EFCN    -1 // physical end of a function
#define ECOFF_SYMBOL_SCLASS_NULL    0 // -
#define ECOFF_SYMBOL_SCLASS_AUTO    1 // automatic variable
#define ECOFF_SYMBOL_SCLASS_EXT     2 // external symbol
#define ECOFF_SYMBOL_SCLASS_STAT    3 // static
#define ECOFF_SYMBOL_SCLASS_REG     4 // register variable
#define ECOFF_SYMBOL_SCLASS_EXTDEF  5 // external definition
#define ECOFF_SYMBOL_SCLASS_LABEL   6 // label
#define ECOFF_SYMBOL_SCLASS_ULABEL  7 // undefined label
#define ECOFF_SYMBOL_SCLASS_MOS     8 // member of structure
#define ECOFF_SYMBOL_SCLASS_ARG     9 // function argument
#define ECOFF_SYMBOL_SCLASS_STRTAG  10 // structure tag
#define ECOFF_SYMBOL_SCLASS_MOU     11 // member of union
#define ECOFF_SYMBOL_SCLASS_UNTAG   12 // union tag
#define ECOFF_SYMBOL_SCLASS_TPDEF   13 // type definition
#define ECOFF_SYMBOL_SCLASS_USTATIC 14 // uninitialized static
#define ECOFF_SYMBOL_SCLASS_ENTAG   15 // enumeration ~
#define ECOFF_SYMBOL_SCLASS_MOE     16 // member of enumeration
#define ECOFF_SYMBOL_SCLASS_REGPARM 17 // register parameter
#define ECOFF_SYMBOL_SCLASS_FIELD   18 // bit field
#define ECOFF_SYMBOL_SCLASS_BLOCK   100 // beginning and end of block
#define ECOFF_SYMBOL_SCLASS_FCN     101 // beginning and end of function
#define ECOFF_SYMBOL_SCLASS_EOS     102 // end of structure
#define ECOFF_SYMBOL_SCLASS_FILE    103 // filename
#define ECOFF_SYMBOL_SCLASS_LINE    104 // used only by utility programs
#define ECOFF_SYMBOL_SCLASS_ALIAS   105 // duplicated tag
#define ECOFF_SYMBOL_SCLASS_HIDDEN  106 // like static, used to avoid name conflicts

// ECoff Symbol Type (basic type Bits 0-3 of the type)
#define ECOFF_SYMBOL_BASE_TYPE_MASK   0x000F
#define ECOFF_SYMBOL_BASE_TYPE_NULL   0 // Type not assigned
#define ECOFF_SYMBOL_BASE_TYPE_CHAR   2 // Character
#define ECOFF_SYMBOL_BASE_TYPE_SHORT  3 // Short integer
#define ECOFF_SYMBOL_BASE_TYPE_INT    4 // Integer
#define ECOFF_SYMBOL_BASE_TYPE_LONG   5 // Long integer
#define ECOFF_SYMBOL_BASE_TYPE_FLOAT  6 // Floating point
#define ECOFF_SYMBOL_BASE_TYPE_DOUBLE 7 // Double word
#define ECOFF_SYMBOL_BASE_TYPE_STRUCT 8 // Structure
#define ECOFF_SYMBOL_BASE_TYPE_UNION  9 // Union
#define ECOFF_SYMBOL_BASE_TYPE_ENUM   10 // Enumeration
#define ECOFF_SYMBOL_BASE_TYPE_MOE    11 // Member of an enumeration
#define ECOFF_SYMBOL_BASE_TYPE_UCHAR  12 // Unsigned character
#define ECOFF_SYMBOL_BASE_TYPE_USHORT 13 // Unsigned short integer
#define ECOFF_SYMBOL_BASE_TYPE_UINT   14 // Unsigned integer
#define ECOFF_SYMBOL_BASE_TYPE_ULONG  15 // Unsigned long integer

// ECoff Symbol Type (derived type Bits 4-15)
#define ECOFF_SYMBOL_DERIVED_TYPE_MASK 0xFFF0
#define ECOFF_SYMBOL_DERIVED_TYPE_NON  0 // No derived type
#define ECOFF_SYMBOL_DERIVED_TYPE_PTR  1 // Pointer
#define ECOFF_SYMBOL_DERIVED_TYPE_FCN  2 // Function
#define ECOFF_SYMBOL_DERIVED_TYPE_ARY  3 // Array

// ECoff relocations
#define ECOFF_RELOC_NONE   0
#define ECOFF_RELOC_TEXT   1
#define ECOFF_RELOC_RDATA  2
#define ECOFF_RELOC_DATA   3
#define ECOFF_RELOC_SDATA  4
#define ECOFF_RELOC_SBSS   5
#define ECOFF_RELOC_BSS    6
#define ECOFF_RELOC_INIT   7
#define ECOFF_RELOC_LIT8   8
#define ECOFF_RELOC_LIT4   9
#define ECOFF_RELOC_XDATA  10
#define ECOFF_RELOC_PDATA  11
#define ECOFF_RELOC_FINI   12
#define ECOFF_RELOC_LITA   13
#define ECOFF_RELOC_ABS    14
#define ECOFF_RELOC_RCONST 15

// ECoff max number of relocs types.
#define ECOFF_NUM_RELOCS 16

// ECoff file descriptor table entry fields.
#define ECOFF_FDE_LANG_C         0
#define ECOFF_FDE_LANG_PASCAL    1
#define ECOFF_FDE_LANG_FORTRAN   2
#define ECOFF_FDE_LANG_ASSEMBLER 3
#define ECOFF_FDE_LANG_MACHINE   4
#define ECOFF_FDE_LANG_NIL       5
#define ECOFF_FDE_LANG_ADA       6
#define ECOFF_FDE_LANG_PL1       7
#define ECOFF_FDE_LANG_COBOL     8
#define ECOFF_FDE_LANG_STDC      9
#define ECOFF_FDE_LANG_MIPS_CXX  10
#define ECOFF_FDE_LANG_DEC_CXX   11
#define ECOFF_FDE_LANG_CXX       12
#define ECOFF_FDE_LANG_FORTRAN90 13
#define ECOFF_FDE_LANG_BLISS     14
#define ECOFF_FDE_LANG_PTAL      15
#define ECOFF_FDE_LANG_CXX_V1    16
#define ECOFF_FDE_LANG_CXX_V2    17

#define ECOFF_FDE_GLEVEL_0 2
#define ECOFF_FDE_GLEVEL_1 1
#define ECOFF_FDE_GLEVEL_2 0
#define ECOFF_FDE_GLEVEL_3 3

// ECoff local symbol type.
#define ECOFF_LOCAL_SYM_ST_NIL        0 // Dummy entry
#define ECOFF_LOCAL_SYM_ST_GLOBAL     1 // Global variable
#define ECOFF_LOCAL_SYM_ST_STATIC     2 //  Static variable
#define ECOFF_LOCAL_SYM_ST_PARAM      3 //  Procedure argument
#define ECOFF_LOCAL_SYM_ST_LOCAL      4 //  Local variable
#define ECOFF_LOCAL_SYM_ST_LABEL      5 //  Label
#define ECOFF_LOCAL_SYM_ST_PROC       6 //  Global procedure
#define ECOFF_LOCAL_SYM_ST_BLOCK      7 //  Start of block
#define ECOFF_LOCAL_SYM_ST_END        8 //  End of block, file, or procedure
#define ECOFF_LOCAL_SYM_ST_MEMBER     9 //  Member of class, structure, union, or enumeration
#define ECOFF_LOCAL_SYM_ST_TYPEDEF    10 //  User-defined type definition
#define ECOFF_LOCAL_SYM_ST_FILE       11 //  Source file name
#define ECOFF_LOCAL_SYM_ST_STATICPROC 14 //  Static procedure
#define ECOFF_LOCAL_SYM_ST_CONSTANT   15 //  Constant data
#define ECOFF_LOCAL_SYM_ST_BASE       17 //  Base class (for example, C++)
#define ECOFF_LOCAL_SYM_ST_VIRTBASE   18 //  Virtual base class (for example, C++)
#define ECOFF_LOCAL_SYM_ST_TAG        19 //  Data structure tag value (for example, C++ class or struct)
#define ECOFF_LOCAL_SYM_ST_INTER      20 //  Interlude (for example, C++)
#define ECOFF_LOCAL_SYM_ST_MODULE     22 // Fortran90 module definition
#define ECOFF_LOCAL_SYM_ST_NAMESPACE  22 //  Namespace definition (for example, C++)
#define ECOFF_LOCAL_SYM_ST_MODVIEW    23 // Modifiers for current view of given module;
#define ECOFF_LOCAL_SYM_ST_USING      23 // Namespace use (for example, C++ "using").
#define ECOFF_LOCAL_SYM_ST_ALIAS      24 // Defines an alias for another symbols. Currently, only used for namespace aliases.

// ECoff local symbol storage class.
#define ECOFF_LOCAL_SYM_SC_NIL          0 // Dummy entry
#define ECOFF_LOCAL_SYM_SC_TEXT         1 // Symbol allocated in the .text section
#define ECOFF_LOCAL_SYM_SC_DATA         2 // Symbol allocated in the .data section
#define ECOFF_LOCAL_SYM_SC_BSS          3 // Symbol allocated in the .bss section
#define ECOFF_LOCAL_SYM_SC_REGISTER     4 // Symbol allocated in a register
#define ECOFF_LOCAL_SYM_SC_ABS          5 // Symbol value is absolute
#define ECOFF_LOCAL_SYM_SC_UNDEFINED    6 // Symbol referenced but not defined in the current module
#define ECOFF_LOCAL_SYM_SC_UNALLOCATED  7 // Storage not allocated for this symbol
#define ECOFF_LOCAL_SYM_SC_TLSUNDEFINED 9 // Undefined TLS symbol
#define ECOFF_LOCAL_SYM_SC_INFO         11 // Symbol contains debugger information
#define ECOFF_LOCAL_SYM_SC_SDATA        13 // Symbol allocated in the .sdata section
#define ECOFF_LOCAL_SYM_SC_SBSS         14 // Symbol allocated in the .sbss section
#define ECOFF_LOCAL_SYM_SC_RDATA        15 // Symbol allocated in the .rdata section
#define ECOFF_LOCAL_SYM_SC_VAR          16 // Parameter passed by reference (for example, Fortran or Pascal)
#define ECOFF_LOCAL_SYM_SC_COMMON       17 // Common symbol
#define ECOFF_LOCAL_SYM_SC_SCOMMON      18 // Small common symbol
#define ECOFF_LOCAL_SYM_SC_VARREGISTER  19 // Parameter passed by reference in a register
#define ECOFF_LOCAL_SYM_SC_VARIANT      20 // Variant record (for example, Pascal or Ada)
#define ECOFF_LOCAL_SYM_SC_FILEDESC     20 // File descriptor (for example, COBOL) - conflicts with variant
#define ECOFF_LOCAL_SYM_SC_SUNDEFINED   21 // Small undefined symbol
#define ECOFF_LOCAL_SYM_SC_INIT         22 // Symbol allocated in the .init section
#define ECOFF_LOCAL_SYM_SC_REPORTDESC   23 // Report descriptor (for example, COBOL)
#define ECOFF_LOCAL_SYM_SC_XDATA        24 // Symbol allocated in the .xdata section
#define ECOFF_LOCAL_SYM_SC_PDATA        25 // Symbol allocated in the .pdata section
#define ECOFF_LOCAL_SYM_SC_FINI         26 // Symbol allocated in the .fini section
#define ECOFF_LOCAL_SYM_SC_RCONST       27 // Symbol allocated in the .rconst section
#define ECOFF_LOCAL_SYM_SC_TLS_COMMON   29 // TLS unallocated data
#define ECOFF_LOCAL_SYM_SC_TLS_DATA     30 // Symbol allocated in the .tlsdata section
#define ECOFF_LOCAL_SYM_SC_TLS_BSS      31 // Symbol allocated in the .tlsbss section
#define ECOFF_LOCAL_SYM_SC_MAX          32 // Maximum number of storage classes

// ECoff external symbol entry fields.

typedef struct ecoff_header_t {
	ut16 f_magic; /* magic/machine number */
	ut16 f_nscns; /* number of sections */
	st32 f_timedate; /* time & date stamp */
	union {
		st32 ptr32;
		st64 ptr64;
	} f_sym; /* file pointer to symtab */
	st32 f_nsyms; /* number of symtab entries */
	ut16 f_opthdr; /* size of ECoff_Optional */
	ut16 f_flags; /* flags */
} ECoff_Header;

typedef struct ecoff_aouthdr_alpha_t {
	ut16 magic; /* type of file */
	ut8 vstamp[2]; /* version stamp */
	ut16 bldrev; /* build revision */
	ut16 padding; /* padding 2 byte */
	ut64 tsize; /* text size in bytes */
	ut64 dsize; /* initialized data */
	ut64 bsize; /* uninitialized data */
	ut64 entry; /* virtual address of program entry point */
	ut64 text_start; /* base address of text */
	ut64 data_start; /* base address of data */
	ut64 bss_start; /* base address of bss */
	ut32 gpr_mask; /* general registers bitmask */
	ut32 fpr_mask; /* floating point registers bitmask */
	ut64 gp_value; /* value for gp register */
} ECoff_AOutHdr_Alpha;

typedef struct ecoff_aouthdr_mips_t {
	ut16 magic; /* type of file */
	ut8 vstamp[2]; /* version stamp */
	ut32 tsize; /* text size in bytes */
	ut32 dsize; /* initialized data */
	ut32 bsize; /* uninitialized data */
	ut32 entry; /* entry point */
	ut32 text_start; /* base of text used for this file */
	ut32 data_start; /* base of data used for this file */
	ut32 bss_start; /* base of bss used for this file */
	ut32 gpr_mask; /* general purpose registers bitmask */
	ut32 cpr_mask[4]; /* co-processor register bitmask */
	ut32 gp_value; /* value for gp register */
} ECoff_AOutHdr_Mips;

typedef struct ecoff_section_alpha_t {
	char s_name[8]; /* section entry name or an index to a name */
	ut64 s_paddr; /* physical address */
	ut64 s_vaddr; /* virtual address */
	ut64 s_size; /* section size */
	ut64 s_scnptr; /* file ptr to raw data for section */
	ut64 s_relptr; /* file ptr to relocation */
	ut64 s_lnnoptr; /* file ptr to line numbers */
	ut16 s_nreloc; /* number of relocation entries */
	ut16 s_nlnno; /* number of line number entries */
	ut32 s_flags; /* flags */
	/* not part of the actual section object */
	char *resolved_name;
} ECoff_Section_Alpha;

typedef struct ecoff_section_mips_t {
	char s_name[8]; /* section entry name or an index to a name */
	ut32 s_paddr; /* physical address */
	ut32 s_vaddr; /* virtual address */
	ut32 s_size; /* section size */
	ut32 s_scnptr; /* file ptr to raw data for section */
	ut32 s_relptr; /* file ptr to relocation */
	ut32 s_lnnoptr; /* file ptr to line numbers */
	ut16 s_nreloc; /* number of relocation entries */
	ut16 s_nlnno; /* number of line number entries */
	ut32 s_flags; /* flags */
	/* not part of the actual section object */
	char *resolved_name;
} ECoff_Section_Mips;

typedef struct ecoff_symbolic_header_alpha_t {
	st16 magic; /* Symbol table magic must be 0x1992 */
	ut8 vstamp[2]; /* Symbol table version stamp (major.minor) */
	st32 iline_max; /* Number of line number entries */
	st32 idn_max; /* unused ? documentation mentions only "obsolete" */
	st32 ipd_max; /* Number of procedure descriptors. */
	st32 isym_max; /* Number of local symbols. */
	st32 iopt_max; /* Size of optimization symbol table. */
	st32 iaux_max; /* Number of auxiliary symbols. */
	st32 iss_max; /* Size of local string table. */
	st32 iss_ext_max; /* Size of external string table. */
	st32 ifd_max; /* Number of file descriptors. */
	st32 crfd; /* Number of relative file descriptors. */
	st32 iext_max; /* Number of external symbols. */
	st64 cb_line; /* Size of (packed) line number entries. */
	ut64 cb_line_offset; /* Offset to start of (packed) line numbers. */
	ut64 cb_dn_offset; /* unused ? documentation mentions only "obsolete" */
	ut64 cb_pd_offset; /* Offset to start of procedure descriptors */
	ut64 cb_sym_offset; /* Offset to start of local symbols */
	ut64 cb_opt_offset; /* Offset to start of optimization entries */
	ut64 cb_aux_offset; /* Offset to start of auxiliary symbols */
	ut64 cb_ss_offset; /* Offset to start of local strings */
	ut64 cb_ss_ext_offset; /* Offset to start of external strings. */
	ut64 cb_fd_offset; /* Offset to start of file descriptors. */
	ut64 cb_rfd_offset; /* Offset to start of relative file descriptors. */
	ut64 cb_ext_offset; /* Offset to start of external symbols. */
} ECoff_SymHdr_Alpha;

typedef struct ecoff_file_descriptor_entry_alpha_t {
	ut64 adr; /* Address of first instruction */
	st64 cb_line_offset; /* Offset from start of packed line numbers to start of entries for this file */
	st64 cb_line; /* Size of packed line numbers for this file. */
	st64 cb_ss; /* Size of local string table entries for this file. */
	st32 rss; /* Offset from start of file's local string table entries to source file name (-1 if unknown). */
	st32 iss_base; /* Start of local strings for this file. */
	st32 isym_base; /* Starting index of local symbol entries for this file */
	st32 csym; /* Count of local symbol entries for this file. */
	st32 iline_base; /* Starting index of line number entries (if expanded) for this file. */
	st32 cline; /* Count of line number entries (if expanded) for this file. */
	st32 iopt_base; /* Offset from start of optimization symbol table to optimization symbol entries for this file. */
	st32 copt; /* Size of optimization symbol entries for this file. */
	st32 ipd_first; /* Starting index of procedure descriptors for this file. */
	st32 cpd; /* Count of procedure descriptors for this file. */
	st32 iaux_base; /* Starting index of auxiliary symbol entries for this file. */
	st32 caux; /* Count of auxiliary symbol entries for this file. */
	st32 rfd_base; /* Starting index of relative file descriptors for this file. */
	st32 crfd; /* Count of relative file descriptors for this file. */
	ut16 lang; /* : 5 | Source language for this file */
	ut16 f_merge; /* : 1 | Informs linker whether this file can be merged. */
	ut16 f_readin; /* : 1 | True if file was read in (as opposed to just created). */
	ut16 f_bigendian; /* : 1 | Unused. */
	ut16 glevel; /* : 2 | Symbolic information level with which this file was compiled. */
	ut16 f_trim; /* : 1 | Unused. */
	ut16 reserved; /* : 5 | reserved bits */
	ut8 vstamp[2]; /* Symbol table version stamp from the .o files. */
	ut32 reserved2; /* reserved bytes */
} ECoff_FileDescEntry_Alpha;

typedef struct ecoff_procedure_descriptor_entry_alpha_t {
	ut64 adr; /* The start address of this procedure. (-1 if no .text) */
	st64 cb_line_offset; /* Offset to the start of this procedure's line numbers from the start of the file descriptor entry */
	st32 isym; /* Start of local symbols for this procedure. */
	st32 iline; /* Start of line number entries (if expanded) for this procedure (-1 if unknown). */
	ut32 regmask; /* Saved general register mask */
	st32 regoffset; /* Offset from the virtual frame pointer to the general register save area in the stack frame. */
	st32 iopt; /* Start of procedure's optimization symbol entries. */
	ut32 fregmask; /* Saved floating-point register mask. */
	st32 fregoffset; /* Offset from the virtual frame pointer to the floating-point register save area in the stack frame. */
	st32 frameoffset; /* Size of the fixed part of the stack frame. */
	st32 ln_low; /* Lowest source line number within this file for the procedure */
	st32 ln_high; /* Highest source line number within this file for the procedure */
	ut32 gp_prologue; /* : 8 | Size of gp prologue. */
	ut32 gp_used; /* : 1 | Flag set if the procedure uses gp. */
	ut32 reg_frame; /* : 1 | True if the procedure is a light-weight or null-weight procedure. */
	ut32 prof; /* : 1 | True if the procedure has been compiled with –pg for gprof profiling. */
	ut32 reserved; /* : 13 | Must be zero. */
	ut32 localoff; /* : 8 | Bias value for accessing local symbols on the stack at run time. */
	st16 framereg; /* Frame pointer register number. */
	st16 pcreg; /* PC (Program Counter) register number. */
} ECoff_ProcDescrEntry_Alpha;

typedef struct ecoff_local_symbol_alpha_t {
	st64 value; /* A field that can contain an address, size, offset, or index. */
	st32 iss; /* Offset from the iss_base field of a file descriptor table entry to the name of the symbol (-1 if no name). */
	ut32 st; /* : 6 | Symbol type */
	ut32 sc; /* : 5 | Storage class */
	ut32 reserved; /* : 1 | Must be zero. */
	ut32 index; /* : 20 | An index into either the local symbol table or auxiliary symbol table. */
} ECoff_LocalSymbol_Alpha;

typedef struct ecoff_external_symbol_alpha_t {
	ECoff_LocalSymbol_Alpha asym; /* External symbol table entry */
	ut32 jmptbl; /* : 1 | Unused. */
	ut32 cobol_main; /* : 1 | Flag set to indicate that the symbol is a COBOL main procedure. */
	ut32 weakext; /* : 1 | Flag set to identify the symbol as a weak external. */
	ut32 alignment; /* : 4 | Power of two byte alignment for common storage class symbols biased by 2^3 (8) */
	ut32 xport; /* : 1 | Flag set to indicate the symbol is to be exported from a shared library. */
	ut32 multiext; /* : 1 | Flag set to indicate that multiple definitions of the symbol are allowed. */
	ut32 reserved; /* : 23 | Must be zero. */
	st32 ifd; /* Index of the file descriptor where the symbol is defined. (-1 for undefined) */
} ECoff_ExternSymbol_Alpha;

typedef struct ecoff_symbol_mips_t {
	char e_name[8]; /* symbol entry name or an index to a name */
	ut32 e_value; /* symbol value, storage class dependent */
	st16 e_scnum; /* section number of the symbol */
	ut16 e_type; /* basic and derived type specification  */
	st8 e_sclass; /* storage class of the symbol */
	ut8 e_numaux; /* number of auxiliary entries */
	/* not part of the actual symbol object */
	char *resolved_name;
} ECoff_Symbol_Mips;

#define COFF_SYMBOL_SIZE 18

typedef struct ecoff_reloc_t {
	union {
		ut64 r_vaddr64; // alpha
		ut32 r_vaddr32; // mips
	};
	ut32 r_symndx; // Alpha only
	ut32 r_bits;
} ECoff_Reloc;

typedef struct ecoff_mips_t {
	ECoff_AOutHdr_Mips aouthdr;
	RzVector /*<ECoff_Section_Mips>*/ *sections;
	RzVector /*<ECoff_Symbol_Mips>*/ *symbols;
} ECoff_Mips;

typedef struct ecoff_alpha_t {
	ECoff_AOutHdr_Alpha aouthdr;
	ECoff_SymHdr_Alpha symhdr;
	RzVector /*<ECoff_Section_Alpha>*/ *sections;
	RzVector /*<ECoff_FileDescEntry_Alpha>*/ *file_descs;
	RzVector /*<ECoff_ProcDescrEntry_Alpha>*/ *proc_descs;
	RzVector /*<ECoff_LocalSymbol_Alpha>*/ *local_symbols;
	RzVector /*<ECoff_ExternSymbol_Alpha>*/ *extern_symbols;
} ECoff_Alpha;

typedef struct ecoff_t {
	bool big_endian;
	ECoff_Header header;
	union {
		ECoff_Mips mips;
		ECoff_Alpha alpha;
	};
} ECoff;

void ecoff_free(ECoff *ecoff);
bool ecoff_is_valid_buffer(RzBuffer *buffer, bool *big_endian);
ECoff *ecoff_parse_from_buffer(RzBuffer *buffer);
RzPVector /*<RzBinAddr *>*/ *ecoff_get_entries(const ECoff *ecoff);
RzPVector /*<RzBinSection *>*/ *ecoff_get_sections(const ECoff *ecoff);
RzPVector /*<RzBinSymbol *>*/ *ecoff_get_symbols(const ECoff *ecoff);
RzBinInfo *ecoff_get_info(const ECoff *ecoff);
bool ecoff_new_structure(const ECoff *ecoff, RzStructuredData *parent);
RzList /*<char *>*/ *ecoff_resolve_section_flags(ut64 s_flags);

#endif /* ECOFF_H */
