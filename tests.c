
#include "dasm.h"

static u32 run_test(u32 test_index, u32 code_count, u8* code, char* expected_result) {
    Disassembler dasm = {code, 0};
    Instruction inst = disassemb(&dasm);
    char* result = print_inst(inst, temp_builder());

    u32 failed = strcmp(result, expected_result);

    if (failed) printf("\033[1;31m");
    else        printf("\033[1;32m");

    printf("%3d    ", test_index);

    { // print machine code
        u32 hex_count = 0;
        for (hex_count = 0; hex_count < code_count; hex_count++) printf(" %02x", code[hex_count]);
        for (; hex_count < 15; hex_count++) printf("   ");
    }

    printf(" %-50s %-50s %s\n", expected_result, result, failed ? "Failed" : "Passed");

    printf("\033[0m");

    return failed ? 0 : 1;
}

static void run_tests() {

    u32 test_index = 0;
    u32 passed = 0;

    #define test(code, dasm) passed += run_test(test_index++, sizeof(code) - 1, (u8*)code, dasm);
    #define test_header(msg) printf("%s\n", msg);

    printf("Running Tests:\n      %-45s  %-50s %-50s %s\n", "Machine Code:", "Expected:", "Got:", "Status:");

    test("\x03\x07", "add eax, dword ptr [rdi]")
    test("\x67\x48\x01\x38", "add qword ptr [eax], rdi")
    test("\xC7\x84\x24\xD4\x00\x00\x00\x00\x00\x00\x00", "mov dword ptr [rsp + 0xd4], 0x0")

    test_header("Grp11 - MOV 0xC7")
    test("\xc7\x00\x10\x00\x00\x00", "mov dword ptr [rax], 0x10")
    test("\xc7\x40\x01\x10\x00\x00\x00", "mov dword ptr [rax + 0x1], 0x10")
    test("\xc7\x04\x18\x10\x00\x00\x00", "mov dword ptr [rax + rbx*1], 0x10")
    test("\xc7\x44\x18\x01\x10\x00\x00\x00", "mov dword ptr [rax + rbx*1 + 0x1], 0x10")
    test("\xc7\x44\x58\x01\x10\x00\x00\x00", "mov dword ptr [rax + rbx*2 + 0x1], 0x10")
    test_header("Grp11 - MOV 0xC6")
    test("\xc6\x00\x10", "mov byte ptr [rax], 0x10")
    test("\xc6\x40\x01\x10", "mov byte ptr [rax + 0x1], 0x10")
    test("\xc6\x04\x18\x10", "mov byte ptr [rax + rbx*1], 0x10")
    test("\xc6\x44\x18\x01\x10", "mov byte ptr [rax + rbx*1 + 0x1], 0x10")
    test("\xc6\x44\x58\x01\x10", "mov byte ptr [rax + rbx*2 + 0x1], 0x10")

    test_header("")
    test("\x00\xd8", "add al, bl")
    test("\x48\x01\xe0", "add rax, rsp")
    test("\x01\xe0", "add eax, esp")
    test("\x02\x00", "add al, byte ptr [rax]")
    test("\x03\x00", "add eax, dword ptr [rax]")
    test("\x04\x10", "add al, 0x10")
    test("\x66\x05\x00\x10", "add ax, 0x1000")
    test("\x05\x00\x10\x00\x00", "add eax, 0x1000")
    test("\x10\xd8", "adc al, bl")
    test("\x48\x11\xe0", "adc rax, rsp")
    test("\x11\xe0", "adc eax, esp")
    test("\x12\x00", "adc al, byte ptr [rax]")
    test("\x13\x00", "adc eax, dword ptr [rax]")
    test("\x14\x10", "adc al, 0x10")
    test("\x66\x15\x00\x10", "adc ax, 0x1000")
    test("\x15\x00\x10\x00\x00", "adc eax, 0x1000")
    test("\x20\xd8", "and al, bl")
    test("\x48\x21\xe0", "and rax, rsp")
    test("\x21\xe0", "and eax, esp")
    test("\x22\x00", "and al, byte ptr [rax]")
    test("\x23\x00", "and eax, dword ptr [rax]")
    test("\x24\x10", "and al, 0x10")
    test("\x66\x25\x00\x10", "and ax, 0x1000")
    test("\x25\x00\x10\x00\x00", "and eax, 0x1000")
    test("\x30\xd8", "xor al, bl")
    test("\x48\x31\xe0", "xor rax, rsp")
    test("\x31\xe0", "xor eax, esp")
    test("\x32\x00", "xor al, byte ptr [rax]")
    test("\x33\x00", "xor eax, dword ptr [rax]")
    test("\x34\x10", "xor al, 0x10")
    test("\x66\x35\x00\x10", "xor ax, 0x1000")
    test("\x35\x00\x10\x00\x00", "xor eax, 0x1000")
    test("\x08\xd8", "or al, bl")
    test("\x48\x09\xe0", "or rax, rsp")
    test("\x09\xe0", "or eax, esp")
    test("\x0a\x00", "or al, byte ptr [rax]")
    test("\x0b\x00", "or eax, dword ptr [rax]")
    test("\x0c\x10", "or al, 0x10")
    test("\x66\x0d\x00\x10", "or ax, 0x1000")
    test("\x0d\x00\x10\x00\x00", "or eax, 0x1000")
    test("\x18\xd8", "sbb al, bl")
    test("\x48\x19\xe0", "sbb rax, rsp")
    test("\x19\xe0", "sbb eax, esp")
    test("\x1a\x00", "sbb al, byte ptr [rax]")
    test("\x1b\x00", "sbb eax, dword ptr [rax]")
    test("\x1c\x10", "sbb al, 0x10")
    test("\x66\x1d\x00\x10", "sbb ax, 0x1000")
    test("\x1d\x00\x10\x00\x00", "sbb eax, 0x1000")
    test("\x28\xd8", "sub al, bl")
    test("\x48\x29\xe0", "sub rax, rsp")
    test("\x29\xe0", "sub eax, esp")
    test("\x2a\x00", "sub al, byte ptr [rax]")
    test("\x2b\x00", "sub eax, dword ptr [rax]")
    test("\x2c\x10", "sub al, 0x10")
    test("\x66\x2d\x00\x10", "sub ax, 0x1000")
    test("\x2d\x00\x10\x00\x00", "sub eax, 0x1000")
    test("\x38\xd8", "cmp al, bl")
    test("\x48\x39\xe0", "cmp rax, rsp")
    test("\x39\xe0", "cmp eax, esp")
    test("\x3a\x00", "cmp al, byte ptr [rax]")
    test("\x3b\x00", "cmp eax, dword ptr [rax]")
    test("\x3c\x10", "cmp al, 0x10")
    test("\x66\x3d\x00\x10", "cmp ax, 0x1000")
    test("\x3d\x00\x10\x00\x00", "cmp eax, 0x1000")

    test_header("Grp1 - Immediates")
    test("\x80\xc1\xff", "add cl, 0xff")
    test("\x81\xc2\x00\x10\x00\x10", "add edx, 0x10001000")
    test("\x83\xc3\x01", "add ebx, 0x1")
    test("\x80\xc9\xff", "or cl, 0xff")
    test("\x81\xca\x00\x10\x00\x10", "or edx, 0x10001000")
    test("\x83\xcb\x01", "or ebx, 0x1")
    test("\x80\xd1\xff", "adc cl, 0xff")
    test("\x81\xd2\x00\x10\x00\x10", "adc edx, 0x10001000")
    test("\x83\xd3\x01", "adc ebx, 0x1")
    test("\x80\xd9\xff", "sbb cl, 0xff")
    test("\x81\xda\x00\x10\x00\x10", "sbb edx, 0x10001000")
    test("\x83\xdb\x01", "sbb ebx, 0x1")
    test("\x80\xe1\xff", "and cl, 0xff")
    test("\x81\xe2\x00\x10\x00\x10", "and edx, 0x10001000")
    test("\x83\xe3\x01", "and ebx, 0x1")
    test("\x80\xe9\xff", "sub cl, 0xff")
    test("\x81\xea\x00\x10\x00\x10", "sub edx, 0x10001000")
    test("\x83\xeb\x01", "sub ebx, 0x1")
    test("\x80\xf1\xff", "xor cl, 0xff")
    test("\x81\xf2\x00\x10\x00\x10", "xor edx, 0x10001000")
    test("\x83\xf3\x01", "xor ebx, 0x1")
    test("\x80\xf9\xff", "cmp cl, 0xff")
    test("\x81\xfa\x00\x10\x00\x10", "cmp edx, 0x10001000")
    test("\x83\xfb\x01", "cmp ebx, 0x1")

    test_header("Interupts")
    test("\xcc", "int3")
    test("\xcd\x01", "int 0x1")

    test_header("test instruction")
    test("\xa8\x12", "test al, 0x12")
    test("\x66\xa9\x00\x10", "test ax, 0x1000")
    test("\xa9\x00\x10\x00\x00", "test eax, 0x1000")
    test("\x48\xa9\x00\x10\x00\x00", "test rax, 0x1000")

    test_header("MOV immediate byte into byte register - 0xB0 to 0xB7")
    test("\xb0\x0a", "mov al, 0xa")
    test("\xb1\x0b", "mov cl, 0xb")
    test("\xb2\x0c", "mov dl, 0xc")
    test("\xb3\x0d", "mov bl, 0xd")
    test("\xb4\x0e", "mov ah, 0xe")
    test("\xb5\x0f", "mov ch, 0xf")
    test("\xb6\xab", "mov dh, 0xab")
    test("\xb7\xcd", "mov bh, 0xcd")

    test("\x41\xb0\x0a", "mov r8b, 0xa")
    test("\x41\xb1\x0b", "mov r9b, 0xb")
    test("\x41\xb2\x0c", "mov r10b, 0xc")
    test("\x41\xb3\x0d", "mov r11b, 0xd")
    test("\x41\xb4\x0e", "mov r12b, 0xe")
    test("\x41\xb5\x0f", "mov r13b, 0xf")
    test("\x41\xb6\xab", "mov r14b, 0xab")
    test("\x41\xb7\xcd", "mov r15b, 0xcd")

    test_header("MOV immediate into register - 0xB8 to 0xBF")
    test("\xb8\x0a\x00\x00\x00", "mov eax, 0xa")
    test("\xb9\x0b\x00\x00\x00", "mov ecx, 0xb")
    test("\xba\x0c\x00\x00\x00", "mov edx, 0xc")
    test("\xbb\x0d\x00\x00\x00", "mov ebx, 0xd")
    test("\xbc\x0e\x00\x00\x00", "mov esp, 0xe")
    test("\xbd\x0f\x00\x00\x00", "mov ebp, 0xf")
    test("\xbe\xab\x00\x00\x00", "mov esi, 0xab")
    test("\xbf\xcd\x00\x00\x00", "mov edi, 0xcd")

    test("\x41\xb8\x0a\x00\x00\x00", "mov r8d, 0xa")
    test("\x41\xb9\x0b\x00\x00\x00", "mov r9d, 0xb")
    test("\x41\xba\x0c\x00\x00\x00", "mov r10d, 0xc")
    test("\x41\xbb\x0d\x00\x00\x00", "mov r11d, 0xd")
    test("\x41\xbc\x0e\x00\x00\x00", "mov r12d, 0xe")
    test("\x41\xbd\x0f\x00\x00\x00", "mov r13d, 0xf")
    test("\x41\xbe\xab\x00\x00\x00", "mov r14d, 0xab")
    test("\x41\xbf\xcd\x00\x00\x00", "mov r15d, 0xcd")

    test("\x49\xb8\x00\x0a\x00\x00\x00\x00\x00\x00", "mov r8, 0xa00")
    test("\x49\xb9\x00\x0b\x00\x00\x00\x00\x00\x00", "mov r9, 0xb00")
    test("\x49\xba\x00\x0c\x00\x00\x00\x00\x00\x00", "mov r10, 0xc00")
    test("\x49\xbb\x00\x0d\x00\x00\x00\x00\x00\x00", "mov r11, 0xd00")
    test("\x49\xbc\x00\x0e\x00\x00\x00\x00\x00\x00", "mov r12, 0xe00")
    test("\x49\xbd\x00\x0f\x00\x00\x00\x00\x00\x00", "mov r13, 0xf00")
    test("\x49\xbe\x00\xab\x00\x00\x00\x00\x00\x00", "mov r14, 0xab00")
    test("\x49\xbf\x00\xcd\x00\x00\x00\x00\x00\x00", "mov r15, 0xcd00")


    test_header("XCHG - 0x86, 0x87")
    test("\x86\xE9", "xchg cl, ch");
    test("\x86\x63\x01", "xchg byte ptr [rbx + 0x1], ah");
    test("\x4D\x87\xC8", "xchg r8, r9");
    test("\x87\x08", "xchg dword ptr [rax], ecx");
    test("\x67\x87\x4C\xD0\x0F", "xchg dword ptr [eax + edx*8 + 0xf], ecx");

    test_header("XCHG eax - 0x91 to 0x97")
    test("\x91",     "xchg eax, ecx")
    test("\x92",     "xchg eax, edx")
    test("\x93",     "xchg eax, ebx")
    test("\x94",     "xchg eax, esp")
    test("\x95",     "xchg eax, ebp")
    test("\x96",     "xchg eax, esi")
    test("\x97",     "xchg eax, edi")
    test("\x41\x90", "xchg eax, r8d")
    test("\x41\x91", "xchg eax, r9d")
    test("\x41\x92", "xchg eax, r10d")
    test("\x41\x93", "xchg eax, r11d")
    test("\x41\x94", "xchg eax, r12d")
    test("\x41\x95", "xchg eax, r13d")
    test("\x41\x96", "xchg eax, r14d")
    test("\x41\x97", "xchg eax, r15d")

    test_header("XCHG rax - 0x91 to 0x97")
    test("\x48\x91", "xchg rax, rcx")
    test("\x48\x92", "xchg rax, rdx")
    test("\x48\x93", "xchg rax, rbx")
    test("\x48\x94", "xchg rax, rsp")
    test("\x48\x95", "xchg rax, rbp")
    test("\x48\x96", "xchg rax, rsi")
    test("\x48\x97", "xchg rax, rdi")
    test("\x49\x90", "xchg rax, r8")
    test("\x49\x91", "xchg rax, r9")
    test("\x49\x92", "xchg rax, r10")
    test("\x49\x93", "xchg rax, r11")
    test("\x49\x94", "xchg rax, r12")
    test("\x49\x95", "xchg rax, r13")
    test("\x49\x96", "xchg rax, r14")
    test("\x49\x97", "xchg rax, r15")

    test_header("XCHG ax - 0x91 to 0x97")
    test("\x66\x90",     "xchg ax, ax")
    test("\x66\x91",     "xchg ax, cx")
    test("\x66\x92",     "xchg ax, dx")
    test("\x66\x93",     "xchg ax, bx")
    test("\x66\x94",     "xchg ax, sp")
    test("\x66\x95",     "xchg ax, bp")
    test("\x66\x96",     "xchg ax, si")
    test("\x66\x97",     "xchg ax, di")
    test("\x66\x41\x90", "xchg ax, r8w")
    test("\x66\x41\x91", "xchg ax, r9w")
    test("\x66\x41\x92", "xchg ax, r10w")
    test("\x66\x41\x93", "xchg ax, r11w")
    test("\x66\x41\x94", "xchg ax, r12w")
    test("\x66\x41\x95", "xchg ax, r13w")
    test("\x66\x41\x96", "xchg ax, r14w")
    test("\x66\x41\x97", "xchg ax, r15w")

    test_header("call");
    test("\xe8\x10\x00\x00\x00", "call 0x10")
    // test("\x66\xe8\xff\x10", "call 0x10ff") // e8 ignores operand size prefix

    printf("Summary: ran %d tests. %d failed. %d passed.\n\n", test_index, test_index - passed, passed);


    //  reg8[] = {"al",  "cl",  "dl",  "bl",  "ah",  "ch",  "dh",  "bh",  "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
    // reg16[] = {"ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",  "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
    // reg32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    // reg64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8",  "r9",  "r10",  "r11",  "r12",  "r13",  "r14",  "r15" };

    #undef test
    #undef test_header
};

static void print_opcode_usage() {
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
}



int main(int argc, char* argv[]) {

    run_tests();
    print_opcode_usage();

    printf("\n\n\n");

    void* code = (void*)main;
    Disassembler dasm = { code, 0 };
    u32 i = 0;
    while (true && i++ < 10) {

        printf("%p ", dasm.buffer + dasm.index);

        u32 begin = dasm.index;
        Instruction inst = disassemb(&dasm);
        u32 inst_length = dasm.index - begin;

        { // print machine code
            u32 hex_count = 0;
            for (hex_count = 0; hex_count < inst_length; hex_count++) printf(" %02x", dasm.buffer[dasm.index - inst_length + hex_count]);
            for (; hex_count < 15; hex_count++) printf("   ");
        }

        char* asmb = print_inst(inst, temp_builder());
        printf("%s\n", asmb);

        if (inst.mnemonic == "ret") break;
        else if (inst.mnemonic == "jmp") {
            u64 a = (u64)dasm.buffer + dasm.index;
            a += inst.immediate.int32;
            dasm.buffer = (u8*)a;
            dasm.index = 0;
            printf("JUMPED TO %p\n", dasm.buffer);
        }
    }

    return 0;
}
