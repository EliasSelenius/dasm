

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <Windows.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef signed char i8;
typedef signed short i16;
typedef signed int i32;
typedef signed long long i64;

typedef float f32;
typedef double f64;

typedef char bool;

#define true 1
#define false 0
#define null 0

// TODO: maybe extract string library to seperate repo, and make it single-header
#include "../plang/src/essh-string.h"
#include "../plang/src/essh-string.c"

#define kB (1024)
#define MB (kB*kB)
#define GB (MB*kB)
#define TB (GB*kB)

#define page_size (4*kB)

u8* alloc_exec_buffer() {
    u8* buffer = VirtualAlloc(null, 1*MB, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return buffer;
}


#define not_immplemented(msg) do { printf("[ERROR]: Not immplemented \""msg"\" at %s:%d\n", __FILE__, __LINE__); /*exit(1);*/ } while(0)

#define array_len(array) (sizeof(array)/sizeof(array[0]))

/*

Instruction layout:
    prefixes:
        Instruction prefix      (0 or 1 bytes)
        Address-size prefix     (0 or 1 bytes)
        Operand-size prefix     (0 or 1 bytes)
        Segment override        (0 or 1 bytes)
    OpCode                      (1 or 2 bytes)
    MOD-REG-R/M                 (0 or 1 byte)
        Mod                         (2 bits)
        Reg/OpCode                  (3 bits)
        R/M                         (3 bits)
    SIB                         (0 or 1 byte)
        SS                          (2 bits)
        Index                       (3 bits)
        Base                        (3 bits)
    displacement                (0, 1, 2 or 4 bytes)
    immediate                   (0, 1, 2 or 4 bytes)



in 64 bit mode the default operand size is 32 and the default address size is 64
REX prefixes allow for 64 bit operands

see Volume 2A Chapter 2 for instruction format

REX.W prefix to make 64bit operands
0x66  prefix to make 16bit operands
when both prefixes are used REX.W takes precedence

REX.W Prefix               |  0   |  0   |  0   |  0   |  1   |  1   |  1   |  1   |
Operand-Size Prefix 66H    |  N   |  N   |  Y   |  Y   |  N   |  N   |  Y   |  Y   |
Address-Size Prefix 67H    |  N   |  Y   |  N   |  Y   |  N   |  Y   |  N   |  Y   |
Effective Operand Size     |  32  |  32  |  16  |  16  |  64  |  64  |  64  |  64  |
Effective Address Size     |  64  |  32  |  64  |  32  |  64  |  32  |  64  |  32  |
Y: Yes - this instruction prefix is present.
N: No - this instruction prefix is not present.


Volume 1 Chapter 3.7.5      to get explanation on SIB
    - Table 2-3 at Volume 2 Chapter 2.1.5
Volume 1 Chapter 4.2.2      floating-point and NaN encodings
Volume 1 Chapter 4.8        floating-point format
Volume 2 Chapter 2.2.1.5    64bit Immediates
Volume 2 Chapter 2.2.1.6    RIP-Relative Addressing


addressing-form specifier (ModR/M byte)


REX prefix format:  0100WRXB
REX.W: set operand size to 64bits
REX.R: extension of ModRM.reg field, (becomes the fourth bit)
REX.X: extension of SIB.index field, (becomes the fourth bit)
REX.B: extension of ModRM.r/m, SIB.base or opcode.reg field, (becomes the fourth bit)

*/

typedef union Value {
    void* pointer;
    u64   uint64;
    u32   uint32;
    u16   uint16;
    u8    uint8;
    i64   int64;
    i32   int32;
    i16   int16;
    i8    int8;
} Value;


typedef u8 RegisterIndex;

typedef enum InstructionEncoding {
    // encoding:    example:
    IE_NoOperands,  // ret
    IE_Imm,         // ret 1
    IE_RegReg,      // mov eax, ecx
    IE_RegMem,      // mov eax, [ecx]
    IE_MemReg,      // mov [eax], ecx
    IE_RegImm,      // mov eax, 1
    IE_MemImm,      // mov [eax], 1
} InstructionEncoding;

typedef struct Instruction {
    char* mnemonic;
    InstructionEncoding encoding;
    u8 operand_bytesize;
    u8 address_bytesize;

    // memory operand general form: ptr [base + index*scale + disp]
    u8 scale; // 0, 1, 2, 4, 8
    RegisterIndex reg, mem, index; // mem is either ModRM.r/m or SIB.base field
    Value displacement;
    Value immediate;
} Instruction;


char* get_register_name(RegisterIndex reg, u32 byte_size) {
    static char* reg8[]  = {"al",  "cl",  "dl",  "bl",  "ah",  "ch",  "dh",  "bh",  "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
    static char* reg16[] = {"ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",  "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
    static char* reg32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    static char* reg64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8",  "r9",  "r10",  "r11",  "r12",  "r13",  "r14",  "r15" };

    switch (byte_size) {
        case 1: return reg8[reg];
        case 2: return reg16[reg];
        case 4: return reg32[reg];
        case 8: return reg64[reg];

        default: assert(false);
    }

    return null;
}


void print_inst_memoperand(Instruction inst, StringBuilder* sb) {
    static const char* ptr[] = {null, "byte", "word", null, "dword", null, null, null, "qword"};

    // ptr [mem]
    // ptr [mem + disp]
    // ptr [index*scale]
    // ptr [index*scale + disp]
    // ptr [mem + index*scale]
    // ptr [mem + index*scale + disp]

    sb_append_format(sb, "%s ptr [", ptr[inst.operand_bytesize]);

    // TODO: this must be put under some kind of condition (when using displacement only or rip relative addressing)
    sb_append_format(sb, "%s", get_register_name(inst.mem, inst.address_bytesize));

    if (inst.scale) {
        sb_append_format(sb, " + %s*%d", get_register_name(inst.index, inst.address_bytesize), (int)inst.scale);
    }

    if (inst.displacement.int64) {
        sb_append_format(sb, " + 0x%x", inst.displacement.int64); // TODO: displacement size?
    }
    sb_append_format(sb, "]");
}

char* print_inst(Instruction inst, StringBuilder* sb) {
    sb_append_format(sb, "%s", inst.mnemonic);

    switch (inst.encoding) {
        case IE_NoOperands: break;
        case IE_Imm:    sb_append_format(sb, " 0x%x", inst.immediate.int64); break;
        case IE_RegReg: sb_append_format(sb, " %s, %s", get_register_name(inst.reg, inst.operand_bytesize), get_register_name(inst.mem, inst.operand_bytesize)); break;
        case IE_RegMem: {
            sb_append_format(sb, " %s, ", get_register_name(inst.reg, inst.operand_bytesize));
            print_inst_memoperand(inst, sb);
        } break;
        case IE_MemReg: {
            sbAppend(sb, " ");
            print_inst_memoperand(inst, sb);
            sb_append_format(sb, ", %s", get_register_name(inst.reg, inst.operand_bytesize));
        } break;
        case IE_RegImm: sb_append_format(sb, " %s, 0x%x", get_register_name(inst.mem, inst.operand_bytesize), inst.immediate.uint64); break;
        case IE_MemImm: {
            sbAppend(sb, " ");
            print_inst_memoperand(inst, sb);
            sb_append_format(sb, ", 0x%x", inst.immediate.int64);
        } break;
    }

    return sb->content;
}

typedef struct Disassembler {
    u8* buffer;
    u32 index;
} Disassembler;

u8 get_byte(Disassembler* dasm) { return dasm->buffer[dasm->index++]; }
u32 get_dword(Disassembler* dasm) {
    u32 res = 0;
    res |= (get_byte(dasm) << 0);
    res |= (get_byte(dasm) << 8);
    res |= (get_byte(dasm) << 16);
    res |= (get_byte(dasm) << 24);

    return res;
}
u64 get_bytes(Disassembler* dasm, u8 num_bytes) {
    assert(num_bytes <= 8);
    u64 res = 0;
    for (u32 i = 0; i < num_bytes; i++) {
        res |= (get_byte(dasm) << (i*8));
    }
    return res;
}

static int opcode_visits[0x100] = {0};
static int opcode_ext_visits[18][0b1000] = {0};

u8 get_opcode(Disassembler* dasm) {
    u8 opcode = get_byte(dasm);
    opcode_visits[opcode]++;
    return opcode;
}

void modrm_sib_disp(Disassembler* dasm, Instruction* inst) {
    u8 MOD_REG_RM = get_byte(dasm);
    u8 MOD = (MOD_REG_RM & 0b11000000) >> 6;
    u8 REG = (MOD_REG_RM & 0b00111000) >> 3;
    u8 RM  = (MOD_REG_RM & 0b00000111) >> 0;

    inst->reg |= (RegisterIndex)REG; // TODO: unless REG is an opcode extension
    inst->mem |= (RegisterIndex)RM;

    if (MOD == 0b11) { // rm is a register not an address
        if (inst->encoding == IE_MemImm) {
            inst->encoding = IE_RegImm;
            inst->reg = inst->mem;
            return;
        } else if (inst->encoding == IE_MemReg) {
            RegisterIndex temp = inst->mem;
            inst->mem = inst->reg;
            inst->reg = temp;
        }
        inst->encoding = IE_RegReg;
        return;
    }

    if (RM == 0b100) {
        u8 SIB = get_byte(dasm);
        u8 SS    = (SIB & 0b11000000) >> 6;
        u8 Index = (SIB & 0b00111000) >> 3;
        u8 Base  = (SIB & 0b00000111) >> 0;

        inst->mem = (RegisterIndex)Base;
        inst->index = (RegisterIndex)Index;

        switch (SS) {
            case 0b00: inst->scale = 1; break;
            case 0b01: inst->scale = 2; break;
            case 0b10: inst->scale = 4; break;
            case 0b11: inst->scale = 8; break;
        }

        if (Index == 0b100) inst->scale = 0;
    }

    switch (MOD) {
        case 0b00: { // no displacement
            if (RM == 0b101) {
                // special case: four byte signed displacement only (or RIP relative addressing in 64bit mode)
                not_immplemented("displacement only (or RIP relative addressing)");
                return;
            }
        } break;
        case 0b01: { // one byte signed displacement
            inst->displacement.uint64 = get_byte(dasm);
            inst->displacement.int64 = (i64)inst->displacement.int8;
        } break;
        case 0b10: { // four byte signed displacement
            inst->displacement.uint64 = get_bytes(dasm, 4);
            inst->displacement.int64 = (i64)inst->displacement.int32; // TODO: i think this sign extends our value to 64 bits
        } break;
    }
}

typedef enum OpcodeExtGroup {
    Grp_None = 0,
    Grp_1, Grp_1A,
    Grp_2,  Grp_3,  Grp_4,  Grp_5,  Grp_6,  Grp_7,  Grp_8,  Grp_9,
    Grp_10, Grp_11, Grp_12, Grp_13, Grp_14, Grp_15, Grp_16, Grp_17,
} OpcodeExtGroup;

static void opcode_extension(Disassembler* dasm, Instruction* inst, u8 opcode, OpcodeExtGroup group) {
    if (group == Grp_None) return;

    u8 ext = (dasm->buffer[dasm->index] & 0b00111000) >> 3;
    opcode_ext_visits[group - 1][ext]++;

    #define switch_ext(prfx, c0, c1, c2, c3, c4, c5, c6, c7) switch (ext) {\
        case 0b000: prfx c0; break; case 0b001: prfx c1; break; case 0b010: prfx c2; break; case 0b011: prfx c3; break;\
        case 0b100: prfx c4; break; case 0b101: prfx c5; break; case 0b110: prfx c6; break; case 0b111: prfx c7; break;}\

    switch (group) {
        case Grp_1:  switch_ext(inst->mnemonic =, "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp") break;
        case Grp_1A: break;
        case Grp_2:  break;
        case Grp_3:  break;
        case Grp_4:  break;
        case Grp_5:  break;
        case Grp_6:  break;
        case Grp_7:  break;
        case Grp_8:  break;
        case Grp_9:  break;
        case Grp_10: break;
        case Grp_11: break;
        case Grp_12: break;
        case Grp_13: break;
        case Grp_14: break;
        case Grp_15: break;
        case Grp_16: break;
        case Grp_17: break;
    }

    #undef switch_ext
}

/*
    operation & operand encoding
    prefix
    invalid
    2 byte opcode
    opcode extension group
*/
/*
prefix and opcode information:
    - operation add/sub/mov etc...
    - operand encoding. (Presence of ModRM byte and direction of operands)
    - operand-size
    - address-size
    - num immediate bytes
    - register
    - expectation of opcode extension in ModRM byte
*/


static Instruction disassemb(Disassembler* dasm) {
    static char* opcode_mnemonics[] = { // TODO: make "prefix" more descriptive
    //         0x00      0x01      0x02      0x03      0x04      0x05      0x06      0x07      0x08      0x09      0x0A      0x0B      0x0C      0x0D      0x0E      0x0F
    /*00*/    "add",    "add",    "add",    "add",    "add",    "add",     null,     null,     "or",     "or",     "or",     "or",     "or",     "or",     null,     null,
    /*10*/    "adc",    "adc",    "adc",    "adc",    "adc",    "adc",     null,     null,    "sbb",    "sbb",    "sbb",    "sbb",    "sbb",    "sbb",     null,     null,
    /*20*/    "and",    "and",    "and",    "and",    "and",    "and", "prefix",     null,    "sub",    "sub",    "sub",    "sub",    "sub",    "sub", "prefix",     null,
    /*30*/    "xor",    "xor",    "xor",    "xor",    "xor",    "xor", "prefix",     null,    "cmp",    "cmp",    "cmp",    "cmp",    "cmp",    "cmp", "prefix",     null,
    /*40*/    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",    "rex",
    /*50*/   "push",   "push",   "push",   "push",   "push",   "push",   "push",   "push",    "pop",    "pop",    "pop",    "pop",    "pop",    "pop",    "pop",    "pop",
    /*60*/     null,     null,     null, "movsxd", "prefix", "prefix", "prefix", "prefix",   "push",   "imul",   "push",   "imul",     null,     null,     null,     null,
    /*70*/ "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb", "Jcc_Jb",
    /*80*/     null,     null,     null,     null,   "test",   "test",   "xchg",   "xchg",    "mov",    "mov",    "mov",    "mov",    "mov",    "lea",    "mov",     null,
    /*90*/   "xchg",   "xchg",   "xchg",   "xchg",   "xchg",   "xchg",   "xchg",   "xchg",     null,     null,     null,     null,     null,     null,   "shaf",   "lahf",
    /*A0*/    "mov",    "mov",    "mov",    "mov",     null,     null,     null,     null,   "test",   "test",     null,     null,     null,     null,     null,     null,
    /*B0*/    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",    "mov",
    /*C0*/     null,     null,    "ret",    "ret",     null,     null,    "mov",    "mov",  "enter",  "leave",    "ret",    "ret",   "int3",    "int",     null,     null,
    /*D0*/     null,     null,     null,     null,     null,     null,     null,     null,    "esc",    "esc",    "esc",    "esc",    "esc",    "esc",    "esc",    "esc",
    /*E0*/     null,     null,   "loop",     null,     "in",     "in",    "out",    "out",   "call",    "jmp",    "jmp",    "jmp",     "in",     "in",    "out",    "out",
    /*F0*/ "prefix",   "int1", "prefix", "prefix",    "hlt",    "cmc",     null,     null,    "clc",    "stc",    "cli",    "sti",    "cld",    "std",     null,     null,
    };


    Instruction inst = {0};
    u8 imm_bytes = 0;

    // deafults for 64bit mode
    inst.operand_bytesize = 4;
    inst.address_bytesize = 8;

    u8 opcode = get_opcode(dasm);

    switch (opcode) { // TODO: check for other prefixes...
        case 0x64: break;
        case 0x65: break;
        case 0x66: inst.operand_bytesize = 2; break;
        case 0x67: inst.address_bytesize = 4; break;
        default: goto opcode_not_used;
    }

    opcode = get_opcode(dasm);
    opcode_not_used:

    if ((opcode & 0xF0) == 0x40) { // REX
        if (opcode & 0b1000) inst.operand_bytesize = 8;
        inst.reg   |= (opcode & 0b0100) << 1;
        inst.index |= (opcode & 0b0010) << 2;
        inst.mem   |= (opcode & 0b0001) << 3;

        opcode = get_opcode(dasm);
    }

    inst.mnemonic = opcode_mnemonics[opcode];

    #define EbGb   { inst.encoding = IE_MemReg; inst.operand_bytesize = 1; }
    #define EvGv   { inst.encoding = IE_MemReg; }
    #define GbEb   { inst.encoding = IE_RegMem; inst.operand_bytesize = 1; }
    #define GvEv   { inst.encoding = IE_RegMem; }
    #define AL_Ib  { inst.encoding = IE_RegImm; inst.operand_bytesize = 1; inst.reg = 0; imm_bytes = 1; }
    #define rAX_Iz { inst.encoding = IE_RegImm;                            inst.reg = 0; imm_bytes = inst.operand_bytesize == 8 ? 4 : inst.operand_bytesize; }
    #define Ib     { inst.encoding = IE_Imm;    inst.operand_bytesize = 1; imm_bytes = 1; }
    #define Jb     { inst.encoding = IE_Imm;    inst.operand_bytesize = 1; imm_bytes = 1; }
    #define Jz     { inst.encoding = IE_Imm;    imm_bytes = inst.operand_bytesize == 8 ? 4 : inst.operand_bytesize;}

    #define EbIb { inst.encoding = IE_MemImm; inst.operand_bytesize = 1; imm_bytes = 1; }
    #define EvIz { inst.encoding = IE_MemImm; imm_bytes = inst.operand_bytesize == 8 ? 4 : inst.operand_bytesize; }
    #define EvIb { inst.encoding = IE_MemImm; imm_bytes = 1; }

    #define col_Ib { inst.encoding = IE_RegImm; inst.operand_bytesize = 1; inst.mem |= opcode&0b00000111; imm_bytes = 1; }
    #define col_Iv { inst.encoding = IE_RegImm; inst.mem |= opcode&0b00000111; imm_bytes = inst.operand_bytesize; }
    #define col_rAX { inst.encoding = IE_RegReg; inst.mem |= opcode&0b00000111; }

    #define X(num, code) case (num): code; break;
    #define row(sn, aa, ab, ac, ad, ba, bb, bc, bd, ca, cb, cc, cd, da, db, dc, dd)\
        X(sn+0x00, aa) X(sn+0x01, ab) X(sn+0x02, ac) X(sn+0x03, ad)\
        X(sn+0x04, ba) X(sn+0x05, bb) X(sn+0x06, bc) X(sn+0x07, bd)\
        X(sn+0x08, ca) X(sn+0x09, cb) X(sn+0x0A, cc) X(sn+0x0B, cd)\
        X(sn+0x0C, da) X(sn+0x0D, db) X(sn+0x0E, dc) X(sn+0x0F, dd)

    switch (opcode) {
        /* legend:
            Eb,Gb    Ev,Gv    Gb,Eb    Gv,Ev    AL,Ib    rAX,Iz

            E       = ModRM.rm field
            G       = ModRM.reg field
            AL      = the AL register
            I       = Immediate value
            rAX     = either AX, EAX or RAX depending on operand-size
            S       = the ModRM.reg field selects a segment register

            b       = a byte
            w       = a word
            d       = a doubleword
            q       = a quadword
            dq      = a double quadword
            qq      = a quad quadword

            v       = either word, doubleword or quadword depending on operand-size
            z       = either word (when 16bit operand-size) or doubleword (when 32/64bit operand-size)
        */

        //            0x00      0x01      0x02      0x03      0x04      0x05      0x06      0x07      0x08      0x09      0x0A      0x0B      0x0C      0x0D      0x0E      0x0F
        row(0x00,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         ,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         )
        row(0x10,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         ,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         )
        row(0x20,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         ,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         )
        row(0x30,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         ,     EbGb,     EvGv,     GbEb,     GvEv,    AL_Ib,   rAX_Iz,         ,         )
        row(0x40,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         )
        row(0x50,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         )
        row(0x60,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         )
        row(0x70,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         )
        row(0x80,     EbIb,     EvIz,     EbIb,     EvIb,         ,         ,     EbGb,     EvGv,     EbGb,     EvGv,     GbEb,     GvEv,         ,         ,         ,         )
        row(0x90,  col_rAX,  col_rAX,  col_rAX,  col_rAX,  col_rAX,  col_rAX,  col_rAX,  col_rAX,         ,         ,         ,         ,         ,         ,         ,         )
        row(0xA0,         ,         ,         ,         ,         ,         ,         ,         ,    AL_Ib,   rAX_Iz,         ,         ,         ,         ,         ,         )
        row(0xB0,   col_Ib,   col_Ib,   col_Ib,   col_Ib,   col_Ib,   col_Ib,   col_Ib,   col_Ib,   col_Iv,   col_Iv,   col_Iv,   col_Iv,   col_Iv,   col_Iv,   col_Iv,   col_Iv)
        row(0xC0,         ,         ,         ,         ,         ,         ,     EbIb,     EvIz,         ,         ,         ,         ,         ,       Ib,         ,         )
        row(0xD0,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         )
        row(0xE0,         ,         ,         ,         ,         ,         ,         ,         ,         ,       Jz,         ,       Jb,         ,         ,         ,         )
        row(0xF0,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         ,         )
    }

    static const OpcodeExtGroup ext_group[0x100] = {
        [0x80] = Grp_1, [0x81] = Grp_1, [0x82] = Grp_1, [0x83] = Grp_1,
        [0x8f] = Grp_1A,
        [0xc0] = Grp_2, [0xc1] = Grp_2, [0xd0] = Grp_2, [0xd1] = Grp_2, [0xd2] = Grp_2, [0xd3] = Grp_2,
        [0xf6] = Grp_3, [0xf7] = Grp_3,
        [0xfe] = Grp_4,
        [0xff] = Grp_5,
        [0xc6] = Grp_11, [0xc7] = Grp_11,
    };

    opcode_extension(dasm, &inst, opcode, ext_group[opcode]);

    #undef row
    #undef X



    switch (inst.encoding) {
        case IE_NoOperands: break;
        case IE_RegReg:     break;
        case IE_Imm:        break;
        case IE_RegImm:     break;
        case IE_MemImm:     modrm_sib_disp(dasm, &inst); break;
        case IE_RegMem:     modrm_sib_disp(dasm, &inst); break;
        case IE_MemReg:     modrm_sib_disp(dasm, &inst); break;
    }

    if (imm_bytes != 0) inst.immediate.uint64 = get_bytes(dasm, imm_bytes);

    return inst;
}
