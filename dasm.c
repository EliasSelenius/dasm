

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
    u8* buffer = VirtualAlloc(null, 1*GB, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return buffer;
}

typedef int func();

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
    sb_append_format(sb, "%s ", inst.mnemonic);
    switch (inst.encoding) {
        case IE_NoOperands: break;
        case IE_Imm: {
            sb_append_format(sb, "0x%x", inst.immediate.int64);
        } break;
        case IE_RegReg: {
            sb_append_format(sb, "%s, ", get_register_name(inst.reg, inst.operand_bytesize));
            sb_append_format(sb, "%s",   get_register_name(inst.mem, inst.operand_bytesize));
        } break;
        case IE_RegMem: {
            sb_append_format(sb, "%s, ", get_register_name(inst.reg, inst.operand_bytesize));
            print_inst_memoperand(inst, sb);
        } break;
        case IE_MemReg: {
            print_inst_memoperand(inst, sb);
            sb_append_format(sb, ", %s", get_register_name(inst.reg, inst.operand_bytesize));
        } break;
        case IE_RegImm: {
            sb_append_format(sb, "%s", get_register_name(inst.reg, inst.operand_bytesize));
            sb_append_format(sb, ", 0x%x", inst.immediate.int64);
        } break;
        case IE_MemImm: {
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

/*
    ADD, ADC, AND, XOR, OR, SBB, SUB, CMP
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


static int opcode_visits[0x100] = {0};
static int opcode_ext_visits[18][0b1000] = {0};


void opcodemap_lookup(Disassembler* dasm, Instruction* inst) {

    #define entry(num, code) case (num): opcode_visits[num]++; code break;
    #define row(sn, aa, ab, ac, ad, ba, bb, bc, bd, ca, cb, cc, cd, da, db, dc, dd)\
        entry(sn+0x00, aa) entry(sn+0x01, ab) entry(sn+0x02, ac) entry(sn+0x03, ad)\
        entry(sn+0x04, ba) entry(sn+0x05, bb) entry(sn+0x06, bc) entry(sn+0x07, bd)\
        entry(sn+0x08, ca) entry(sn+0x09, cb) entry(sn+0x0A, cc) entry(sn+0x0B, cd)\
        entry(sn+0x0C, da) entry(sn+0x0D, db) entry(sn+0x0E, dc) entry(sn+0x0F, dd)

    #define empty { inst->mnemonic = "<not_immplemented>"; inst->encoding = IE_NoOperands; }
    #define invalid { inst->mnemonic = "<invalid>"; inst->encoding = IE_NoOperands; }

    // operand encoding is specified by the three least significant bits
    #define lt(operation_mnemonic) {\
        inst->mnemonic = #operation_mnemonic;\
        switch (byte & 0b111) {\
            case 0b000: inst->encoding = IE_MemReg;\
                        inst->operand_bytesize = 1;\
                        break;\
            case 0b001: inst->encoding = IE_MemReg;\
                        break;\
            case 0b010: inst->encoding = IE_RegMem;\
                        inst->operand_bytesize = 1;\
                        break;\
            case 0b011: inst->encoding = IE_RegMem;\
                        break;\
            case 0b100: inst->encoding = IE_RegImm;\
                        inst->operand_bytesize = 1;\
                        break;/*TODO: make these refer to A register*/\
            case 0b101: inst->encoding = IE_RegImm; break;\
        }\
    }

    // legacy prefixes
    #define op_size { inst->operand_bytesize = 2; }
    #define ad_size { inst->address_bytesize = 4; }

    #define REX {\
        if (byte & 0b1000) inst->operand_bytesize = 8;\
        inst->reg   |= (byte & 0b0100) << 1;\
        inst->index |= (byte & 0b0010) << 2;\
        inst->mem   |= (byte & 0b0001) << 3;\
    }

    // TODO: note that operand size appears to be 1 byte for all opcodes where the lower 4bits of the opcode is an even number. Use this fact to consolidate the code

    // immediate group 1
    #define group1\
        opcode_ext_visits[0][opcode_ex]++;\
        inst->encoding = IE_MemImm;\
        if (1 & byte); else inst->operand_bytesize = 1;\
        switch (opcode_ex) {\
            case 0b000: inst->mnemonic = "add"; break;\
            case 0b001: inst->mnemonic = "or";  break;\
            case 0b010: inst->mnemonic = "adc"; break;\
            case 0b011: inst->mnemonic = "sbb"; break;\
            case 0b100: inst->mnemonic = "and"; break;\
            case 0b101: inst->mnemonic = "sub"; break;\
            case 0b110: inst->mnemonic = "xor"; break;\
            case 0b111: inst->mnemonic = "cmp"; break;\
        }

    #define group11\
        opcode_ext_visits[11][opcode_ex]++;\
        if (1 & byte); else inst->operand_bytesize = 1;\
        switch (opcode_ex) {\
            case 0b000: inst->mnemonic = "mov"; inst->encoding = IE_MemImm; break;\
            case 0b001: break;\
            case 0b010: break;\
            case 0b011: break;\
            case 0b100: break;\
            case 0b101: break;\
            case 0b110: break;\
            case 0b111: break;\
        }

    u8 byte = get_byte(dasm);
    // TODO: fix possible overflow here:
    u8 opcode_ex = (dasm->buffer[dasm->index] & 0b00111000) >> 3; // this opcode extension might be applicable in some cases

    switch (byte) { // Opcode Map (see: Volume 2 Appendix A.3)
        //          0x00     0x01     0x02     0x03     0x04     0x05     0x06     0x07     0x08     0x09     0x0A     0x0B     0x0C     0x0D     0x0E     0x0F
        row(0x00, lt(add), lt(add), lt(add), lt(add), lt(add), lt(add),   empty,   empty, lt (or), lt (or), lt (or), lt (or), lt (or), lt (or),   empty,   empty)
        row(0x10, lt(adc), lt(adc), lt(adc), lt(adc), lt(adc), lt(adc),   empty,   empty, lt(sbb), lt(sbb), lt(sbb), lt(sbb), lt(sbb), lt(sbb),   empty,   empty)
        row(0x20, lt(and), lt(and), lt(and), lt(and), lt(and), lt(and),   empty,   empty, lt(sub), lt(sub), lt(sub), lt(sub), lt(sub), lt(sub),   empty,   empty)
        row(0x30, lt(xor), lt(xor), lt(xor), lt(xor), lt(xor), lt(xor),   empty,   empty, lt(cmp), lt(cmp), lt(cmp), lt(cmp), lt(cmp), lt(cmp),   empty,   empty)
        row(0x40,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX)
        row(0x50,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0x60,   empty,   empty,   empty,   empty,   empty,   empty, op_size, ad_size,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0x70,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0x80,  group1,  group1,  group1,  group1,   empty,   empty,   empty,   empty, lt(mov), lt(mov), lt(mov), lt(mov),   empty,   empty,   empty,   empty)
        row(0x90,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xA0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xB0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xC0,   empty,   empty,   empty,   empty,   empty,   empty, group11, group11,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xD0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xE0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xF0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
    }

    #undef row
    #undef entry
}

// OpCodeInfo get_opcode(Disassembler* dasm) {

//     static const OpCodeInfo opcode_lookup[0xFF] = {
//         /*0x00*/ [0b00000000] = {"add", true, false,  1, 0},
//         /*0x01*/ [0b00000001] = {"add", true, false,  4, 0},
//         /*0x02*/ [0b00000010] = {"add", true, true,   1, 0},
//         /*0x03*/ [0b00000011] = {"add", true, true,   4, 0},
//         /*0x80*/ [0b10000000] = {"add", true, false,  1, 1},
//         /*0x81*/ [0b10000001] = {"add", true, false,  4, 4},
//         /*0x83*/ [0b10000011] = {"add", true, false,  4, 1},

//         /*0x88*/ [0b10001000] = {"mov", true, false,  1, 0},
//         /*0x89*/ [0b10001001] = {"mov", true, false,  4, 0},
//         /*0x8A*/ [0b10001010] = {"mov", true, true,   1, 0},
//         /*0x8B*/ [0b10001011] = {"mov", true, true,   4, 0},

//         /*0xC2*/ [0b11000010] = {"ret", false, false, 0, 2}, // near returns
//         /*0xC3*/ [0b11000011] = {"ret", false, false, 0, 0},
//         /*0xCA*/ [0b11001010] = {"ret", false, false, 0, 2}, // far returns
//         /*0xCB*/ [0b11001011] = {"ret", false, false, 0, 0},
//     };

//     // TODO: 2 byte opcodes...
//     u8 opcode = get_byte(dasm);
//     OpCodeInfo info = opcode_lookup[opcode];
//     if (info.mnemonic) return info;

//     not_immplemented();
// }

/*
mov eax, [ecx]    ->     8b 01  in x86
mov eax, [ecx]    ->  67 8b 01  in x64
mov rax, [rcx]    ->  48 8b 01  in x64
*/


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

Instruction disassemb(Disassembler* dasm) {
    Instruction inst = {0};

    // deafults for 64bit mode
    inst.operand_bytesize = 4;
    inst.address_bytesize = 8;

    do {
        opcodemap_lookup(dasm, &inst);
    } while (inst.mnemonic == null);

    switch (inst.encoding) {
        case IE_NoOperands: break;
        case IE_Imm:        inst.immediate.uint64 = get_bytes(dasm, inst.operand_bytesize); break;
        case IE_RegReg:     break;
        case IE_RegMem:     modrm_sib_disp(dasm, &inst); break;
        case IE_MemReg:     modrm_sib_disp(dasm, &inst); break;
        case IE_RegImm:     inst.immediate.uint64 = get_bytes(dasm, inst.operand_bytesize); break;
        case IE_MemImm:     modrm_sib_disp(dasm, &inst); inst.immediate.uint64 = get_bytes(dasm, inst.operand_bytesize); break;
    }

    return inst;
}

typedef struct Testcase {
    u8* machine_code;
    char* disassembly;
} Testcase;

static const Testcase tests[] = {
    {(u8*)"\x03\x07",                         "add eax, dword ptr [rdi]"},
    {(u8*)"\x67\x48\x01\x38",                 "add qword ptr [eax], rdi"},

    // Grp11 - MOV 0xC7
    {(u8*)"\xc7\x00\x10\x00\x00\x00",         "mov dword ptr [rax], 0x10"},
    {(u8*)"\xc7\x40\x01\x10\x00\x00\x00",     "mov dword ptr [rax + 0x1], 0x10"},
    {(u8*)"\xc7\x04\x18\x10\x00\x00\x00",     "mov dword ptr [rax + rbx*1], 0x10"},
    {(u8*)"\xc7\x44\x18\x01\x10\x00\x00\x00", "mov dword ptr [rax + rbx*1 + 0x1], 0x10"},
    {(u8*)"\xc7\x44\x58\x01\x10\x00\x00\x00", "mov dword ptr [rax + rbx*2 + 0x1], 0x10"},
    // Grp11 - MOV 0xC6
    {(u8*)"\xc6\x00\x10",                     "mov byte ptr [rax], 0x10"},
    {(u8*)"\xc6\x40\x01\x10",                 "mov byte ptr [rax + 0x1], 0x10"},
    {(u8*)"\xc6\x04\x18\x10",                 "mov byte ptr [rax + rbx*1], 0x10"},
    {(u8*)"\xc6\x44\x18\x01\x10",             "mov byte ptr [rax + rbx*1 + 0x1], 0x10"},
    {(u8*)"\xc6\x44\x58\x01\x10",             "mov byte ptr [rax + rbx*2 + 0x1], 0x10"},

    // 
    {(u8*)"\x00\xd8",                         "add al, bl"},
    {(u8*)"\x48\x01\xe0",                     "add rax, rsp"},
    {(u8*)"\x01\xe0",                         "add eax, esp"},
    {(u8*)"\x02\x00",                         "add al, byte ptr [rax]"},
    {(u8*)"\x03\x00",                         "add eax, dword ptr [rax]"},
    {(u8*)"\x04\x10",                         "add al, 0x10"},
    {(u8*)"\x66\x05\x00\x10",                 "add ax, 0x1000"},
    {(u8*)"\x05\x00\x10\x00\x00",             "add eax, 0x1000"},
    {(u8*)"\x10\xd8",                         "adc al, bl"},
    {(u8*)"\x48\x11\xe0",                     "adc rax, rsp"},
    {(u8*)"\x11\xe0",                         "adc eax, esp"},
    {(u8*)"\x12\x00",                         "adc al, byte ptr [rax]"},
    {(u8*)"\x13\x00",                         "adc eax, dword ptr [rax]"},
    {(u8*)"\x14\x10",                         "adc al, 0x10"},
    {(u8*)"\x66\x15\x00\x10",                 "adc ax, 0x1000"},
    {(u8*)"\x15\x00\x10\x00\x00",             "adc eax, 0x1000"},
    {(u8*)"\x20\xd8",                         "and al, bl"},
    {(u8*)"\x48\x21\xe0",                     "and rax, rsp"},
    {(u8*)"\x21\xe0",                         "and eax, esp"},
    {(u8*)"\x22\x00",                         "and al, byte ptr [rax]"},
    {(u8*)"\x23\x00",                         "and eax, dword ptr [rax]"},
    {(u8*)"\x24\x10",                         "and al, 0x10"},
    {(u8*)"\x66\x25\x00\x10",                 "and ax, 0x1000"},
    {(u8*)"\x25\x00\x10\x00\x00",             "and eax, 0x1000"},
    {(u8*)"\x30\xd8",                         "xor al, bl"},
    {(u8*)"\x48\x31\xe0",                     "xor rax, rsp"},
    {(u8*)"\x31\xe0",                         "xor eax, esp"},
    {(u8*)"\x32\x00",                         "xor al, byte ptr [rax]"},
    {(u8*)"\x33\x00",                         "xor eax, dword ptr [rax]"},
    {(u8*)"\x34\x10",                         "xor al, 0x10"},
    {(u8*)"\x66\x35\x00\x10",                 "xor ax, 0x1000"},
    {(u8*)"\x35\x00\x10\x00\x00",             "xor eax, 0x1000"},
    {(u8*)"\x08\xd8",                         "or al, bl"},
    {(u8*)"\x48\x09\xe0",                     "or rax, rsp"},
    {(u8*)"\x09\xe0",                         "or eax, esp"},
    {(u8*)"\x0a\x00",                         "or al, byte ptr [rax]"},
    {(u8*)"\x0b\x00",                         "or eax, dword ptr [rax]"},
    {(u8*)"\x0c\x10",                         "or al, 0x10"},
    {(u8*)"\x66\x0d\x00\x10",                 "or ax, 0x1000"},
    {(u8*)"\x0d\x00\x10\x00\x00",             "or eax, 0x1000"},
    {(u8*)"\x18\xd8",                         "sbb al, bl"},
    {(u8*)"\x48\x19\xe0",                     "sbb rax, rsp"},
    {(u8*)"\x19\xe0",                         "sbb eax, esp"},
    {(u8*)"\x1a\x00",                         "sbb al, byte ptr [rax]"},
    {(u8*)"\x1b\x00",                         "sbb eax, dword ptr [rax]"},
    {(u8*)"\x1c\x10",                         "sbb al, 0x10"},
    {(u8*)"\x66\x1d\x00\x10",                 "sbb ax, 0x1000"},
    {(u8*)"\x1d\x00\x10\x00\x00",             "sbb eax, 0x1000"},
    {(u8*)"\x28\xd8",                         "sub al, bl"},
    {(u8*)"\x48\x29\xe0",                     "sub rax, rsp"},
    {(u8*)"\x29\xe0",                         "sub eax, esp"},
    {(u8*)"\x2a\x00",                         "sub al, byte ptr [rax]"},
    {(u8*)"\x2b\x00",                         "sub eax, dword ptr [rax]"},
    {(u8*)"\x2c\x10",                         "sub al, 0x10"},
    {(u8*)"\x66\x2d\x00\x10",                 "sub ax, 0x1000"},
    {(u8*)"\x2d\x00\x10\x00\x00",             "sub eax, 0x1000"},
    {(u8*)"\x38\xd8",                         "cmp al, bl"},
    {(u8*)"\x48\x39\xe0",                     "cmp rax, rsp"},
    {(u8*)"\x39\xe0",                         "cmp eax, esp"},
    {(u8*)"\x3a\x00",                         "cmp al, byte ptr [rax]"},
    {(u8*)"\x3b\x00",                         "cmp eax, dword ptr [rax]"},
    {(u8*)"\x3c\x10",                         "cmp al, 0x10"},
    {(u8*)"\x66\x3d\x00\x10",                 "cmp ax, 0x1000"},
    {(u8*)"\x3d\x00\x10\x00\x00",             "cmp eax, 0x1000"},

    // Grp1 - Immediates
    {(u8*)"\x80\xc1\xff",                     "add cl, 0xff"},
    {(u8*)"\x81\xc2\x00\x10\x00\x10",         "add edx, 0x10001000"},
    {(u8*)"\x83\xc3\x01",                     "add ebx, 0x1"},
    {(u8*)"\x80\xc9\xff",                     "or cl, 0xff"},
    {(u8*)"\x81\xca\x00\x10\x00\x10",         "or edx, 0x10001000"},
    {(u8*)"\x83\xcb\x01",                     "or ebx, 0x1"},
    {(u8*)"\x80\xd1\xff",                     "adc cl, 0xff"},
    {(u8*)"\x81\xd2\x00\x10\x00\x10",         "adc edx, 0x10001000"},
    {(u8*)"\x83\xd3\x01",                     "adc ebx, 0x1"},
    {(u8*)"\x80\xd9\xff",                     "sbb cl, 0xff"},
    {(u8*)"\x81\xda\x00\x10\x00\x10",         "sbb edx, 0x10001000"},
    {(u8*)"\x83\xdb\x01",                     "sbb ebx, 0x1"},
    {(u8*)"\x80\xe1\xff",                     "and cl, 0xff"},
    {(u8*)"\x81\xe2\x00\x10\x00\x10",         "and edx, 0x10001000"},
    {(u8*)"\x83\xe3\x01",                     "and ebx, 0x1"},
    {(u8*)"\x80\xe9\xff",                     "sub cl, 0xff"},
    {(u8*)"\x81\xea\x00\x10\x00\x10",         "sub edx, 0x10001000"},
    {(u8*)"\x83\xeb\x01",                     "sub ebx, 0x1"},
    {(u8*)"\x80\xf1\xff",                     "xor cl, 0xff"},
    {(u8*)"\x81\xf2\x00\x10\x00\x10",         "xor edx, 0x10001000"},
    {(u8*)"\x83\xf3\x01",                     "xor ebx, 0x1"},
    {(u8*)"\x80\xf9\xff",                     "cmp cl, 0xff"},
    {(u8*)"\x81\xfa\x00\x10\x00\x10",         "cmp edx, 0x10001000"},
    {(u8*)"\x83\xfb\x01",                     "cmp ebx, 0x1"},

};

static void run_tests() {
    printf("Running Tests:\n");
    int test_count = array_len(tests);
    int failed_tests = 0;
    for (int i = 0; i < test_count; i++) {
        Testcase test = tests[i];
        Disassembler dasm = {test.machine_code, 0};
        Instruction inst = disassemb(&dasm);
        char* disasm = print_inst(inst, temp_builder());

        // u32 lev = lev_dist(make_string(test.disassembly), make_string(disasm));
        u32 lev = strcmp(disasm, test.disassembly);

        if (lev) {printf("\033[1;31m"); failed_tests++;}
        else     printf("\033[1;32m");

        printf("%3d %-50s %-50s (lev: %u)\n", i, test.disassembly, disasm, lev);

        printf("\033[0m");
    }

    printf("%d failed of %d tests\n\n", failed_tests, test_count);
}

int main(int argc, char* argv[]) {
/*
81 c0 ff 00 00 00
80 c0 ff
01 c1
03 c1

03 1d 0f 00 00 00
03 3b
03 46 0f

83 c0 01
83 c0 7f
*/

/*
add ecx, 2
add eax, ecx
mov edi, eax
ret
ret 23
mov eax, [ecx]

mov r8, 0x11223344
mov r8, 0x1122334455


mov dword ptr [rax], 16
mov dword ptr [rax + 1], 16
mov dword ptr [rax + rbx], 16
mov dword ptr [rax + rbx + 1], 16
mov dword ptr [rax + rbx*2 + 1], 16

*/

    run_tests();

    printf("OpCode Map usage:\n  ");
    for (int i = 0; i <= 0xF; i++) printf(" %02x", i);
    printf("\n");
    for (int i = 0; i <= 0xF; i++) {
        printf("%x0:", i);
        for (int j = 0; j <= 0xF; j++) {
            int visits = opcode_visits[i*0x10 + j];
            if (visits) printf("%2d|", visits);
            else        printf("..|");
        }
        printf("\n");
    }

    printf("OpCode Extension usage:\n        ");
    for (int i = 0; i < array_len(opcode_ext_visits[0]); i++) printf("%d  ", i);
    printf("\n");
    for (int i = 0; i < array_len(opcode_ext_visits); i++) {
        if (i == 0) printf("group1 :");
        else if (i == 1) printf("group1A:");
        else printf("group%-2d:", i);
        for (int j = 0; j < array_len(opcode_ext_visits[i]); j++) {
            int visits = opcode_ext_visits[i][j];
            if (visits) printf("%2d|", visits);
            else        printf("..|");
        }
        printf("\n");
    }

    return 0;
}
