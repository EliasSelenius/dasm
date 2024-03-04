

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

#define MB (1024*1024)
#define GB (MB*1024)

#define page_size (1024*4)

u8* alloc_exec_buffer() {
    u8* buffer = VirtualAlloc(null, 1*GB, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    return buffer;
}

typedef int func();

#define not_immplemented(msg) do { printf("[ERROR]: Not immplemented \""msg"\" at %s:%d\n", __FILE__, __LINE__); exit(1); } while(0)

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


void print_inst_memoperand(Instruction inst) {
    static const char* ptr[] = {null, "byte", "word", null, "dword", null, null, null, "qword"};

    // ptr [mem]
    // ptr [mem + disp]
    // ptr [index*scale]
    // ptr [index*scale + disp]
    // ptr [mem + index*scale]
    // ptr [mem + index*scale + disp]

    printf("%s ptr [", ptr[inst.operand_bytesize]);

    printf("%s", get_register_name(inst.mem, inst.address_bytesize)); // TODO: this must be put under some kind of condition

    if (inst.scale) {
        printf(" + %s*%d", get_register_name(inst.index, inst.address_bytesize), (int)inst.scale);
    }

    if (inst.displacement.int64) {
        printf(" + %lld", inst.displacement.int64); // TODO: displacement size?
    }
    printf("]");
}

void print_inst(Instruction inst) {
    printf("%s ", inst.mnemonic);
    switch (inst.encoding) {
        case IE_NoOperands: break;
        case IE_Imm: {
            printf("%lld", inst.immediate.int64);
        } break;
        case IE_RegReg: {
            printf("%s, ", get_register_name(inst.reg, inst.operand_bytesize));
            printf("%s",   get_register_name(inst.mem, inst.operand_bytesize));
        } break;
        case IE_RegMem: {
            printf("%s, ", get_register_name(inst.reg, inst.operand_bytesize));
            print_inst_memoperand(inst);
        } break;
        case IE_MemReg: {
            print_inst_memoperand(inst);
            printf(", %s", get_register_name(inst.reg, inst.operand_bytesize));
        } break;
        case IE_RegImm: {
            printf("%s", get_register_name(inst.reg, inst.operand_bytesize));
            printf(", %lld", inst.immediate.int64);
        } break;
        case IE_MemImm: {
            print_inst_memoperand(inst);
            printf(", %lld", inst.immediate.int64);
        } break;
    }
    printf("\n");
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

typedef struct OpCodeInfo {
    char* mnemonic;
    InstructionEncoding encoding;
    u8 operand_bytesize;
    u8 imm_operand_bytesize;
} OpCodeInfo;

void opcodemap_lookup(u8 byte, Instruction* inst) {

    #define entry(num, code) case (num): code break;
    #define row(sn, aa, ab, ac, ad, ba, bb, bc, bd, ca, cb, cc, cd, da, db, dc, dd)\
        entry(sn+0x00, aa) entry(sn+0x01, ab) entry(sn+0x02, ac) entry(sn+0x03, ad)\
        entry(sn+0x04, ba) entry(sn+0x05, bb) entry(sn+0x06, bc) entry(sn+0x07, bd)\
        entry(sn+0x08, ca) entry(sn+0x09, cb) entry(sn+0x0A, cc) entry(sn+0x0B, cd)\
        entry(sn+0x0C, da) entry(sn+0x0D, db) entry(sn+0x0E, dc) entry(sn+0x0F, dd)

    #define empty { not_immplemented(); }

    // operand encoding is specified by the three least significant bits
    #define last_three_bits(operation_mnemonic) {\
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

    #define add_3 last_three_bits(add)
    #define adc_3 last_three_bits(adc)
    #define and_3 last_three_bits(and)
    #define xor_3 last_three_bits(xor)
    #define or_3  last_three_bits(or)
    #define sbb_3 last_three_bits(sbb)
    #define sub_3 last_three_bits(sub)
    #define cmp_3 last_three_bits(cmp)
    #define mov_3 last_three_bits(mov)

    #define op_size { inst->operand_bytesize = 2; }
    #define ad_size { inst->address_bytesize = 4; }


    // REX prefix format:  0100WRXB
    // REX.W: set operand size to 64bits
    // REX.R: extension of ModRM.reg field, (becomes the fourth bit)
    // REX.X: extension of SIB.index field, (becomes the fourth bit)
    // REX.B: extension of ModRM.r/m, SIB.base or opcode.reg field, (becomes the fourth bit)

    #define REX {\
        if (byte & 0b1000) inst->operand_bytesize = 8;\
        inst->reg   |= (byte & 0b0100) << 1;\
        inst->index |= (byte & 0b0010) << 2;\
        inst->mem   |= (byte & 0b0001) << 3;\
    }

    switch (byte) { // Opcode Map (see: Volume 2 Appendix A.3)
        //          0x00     0x01     0x02     0x03     0x04     0x05     0x06     0x07     0x08     0x09     0x0A     0x0B     0x0C     0x0D     0x0E     0x0F
        row(0x00,   add_3,   add_3,   add_3,   add_3,   add_3,   add_3,   empty,   empty,    or_3,    or_3,    or_3,    or_3,    or_3,    or_3,   empty,   empty)
        row(0x10,   adc_3,   adc_3,   adc_3,   adc_3,   adc_3,   adc_3,   empty,   empty,   sbb_3,   sbb_3,   sbb_3,   sbb_3,   sbb_3,   sbb_3,   empty,   empty)
        row(0x20,   and_3,   and_3,   and_3,   and_3,   and_3,   and_3,   empty,   empty,   sub_3,   sub_3,   sub_3,   sub_3,   sub_3,   sub_3,   empty,   empty)
        row(0x30,   xor_3,   xor_3,   xor_3,   xor_3,   xor_3,   xor_3,   empty,   empty,   cmp_3,   cmp_3,   cmp_3,   cmp_3,   cmp_3,   cmp_3,   empty,   empty)
        row(0x40,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX,     REX)
        row(0x50,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0x60,   empty,   empty,   empty,   empty,   empty,   empty, op_size, ad_size,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0x70,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0x80,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   mov_3,   mov_3,   mov_3,   mov_3,   empty,   empty,   empty,   empty)
        row(0x90,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xA0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xB0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
        row(0xC0,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty,   empty)
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
        u8 byte = get_byte(dasm);
        opcodemap_lookup(byte, &inst);
    } while (inst.mnemonic == null);

    switch (inst.encoding) {
        case IE_NoOperands: break;
        case IE_Imm:        inst.immediate.uint64 = get_bytes(dasm, inst.operand_bytesize); break;
        case IE_RegReg:     break;
        case IE_RegMem:     modrm_sib_disp(dasm, &inst); break;
        case IE_MemReg:     modrm_sib_disp(dasm, &inst); break;
        case IE_RegImm:     inst.immediate.uint64 = get_bytes(dasm, inst.operand_bytesize); break;
        case IE_MemImm:     inst.immediate.uint64 = get_bytes(dasm, inst.operand_bytesize); break;
    }

    return inst;
}


int main(int argc, char* argv[]) {
    u8* buffer = alloc_exec_buffer();

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

    // char prog[] = "\xB8\x55\xA4\x00\x00\xC3";
    char prog[] = "\x03\x07\x67\x48\x01\x38";


    memcpy(buffer, prog, sizeof(prog));
    // func* f = (func*)buffer;
    // int i = f();
    // printf("Returned: %d\n", i);

    Disassembler dasm = {buffer, 0};
    for (u32 i = 0; i < 5; i++) {
        Instruction inst = disassemb(&dasm);
        print_inst(inst);
    }

    return 0;
}
