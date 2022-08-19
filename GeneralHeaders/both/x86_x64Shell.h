//#pragma once
//#ifndef BOTH_x86_x64Shell_HEADER_INCLUDED
//#define BOTH_x86_x64Shell_HEADER_INCLUDED

#include "BasicUtilities.h"

#pragma region UTILITIES
#ifdef SHELL_RELATIVITY

#define R_CP(rv, ...) INSERT_INLINECODE_8_BIT_ARRAY(rv = SHELL_RELATIVITY, __VA_ARGS__) // Sets a relativity checkpoint
#define D_C_S(tp, sn, sz, ...) unsigned char INVALID1337##sn[] = { __VA_ARGS__ }; SHELL_RELATIVITY -= sizeof(INVALID1337##sn); tp char sn[sz] = { __VA_ARGS__ } // Double contructs the shellcode to create valid checkpoints

#endif
#pragma endregion

#pragma region TYPES

#define BYTECAST(byte) ((unsigned char)(byte)) // byte [Size: 0x1]
#define WORDCAST(word) ((unsigned short)(word)) // word [Size: 0x2]
#define DWORDCAST(dword) ((unsigned long)(dword)) // dword [Size: 0x4]
#define QWORDCAST(qword) ((unsigned long long)(qword)) // qword [Size: 0x8]

#ifndef SHELL_RELATIVITY

#define BYTEPTR(byte) (BYTECAST(byte) & 0xFF) // byte ptr [Size: 0x1]
#define WORDPTR(word) (WORDCAST(word) & 0xFF), ((WORDCAST(word) >> 8) & 0xFF) // word ptr [Size: 0x2]
#define DWORDPTR(dword) (DWORDCAST(dword) & 0xFF), ((DWORDCAST(dword) >> 8) & 0xFF), ((DWORDCAST(dword) >> 16) & 0xFF), ((DWORDCAST(dword) >> 24) & 0xFF) // dword ptr [Size: 0x4]
#define QWORDPTR(qword) (QWORDCAST(qword) & 0xFF), ((QWORDCAST(qword) >> 8) & 0xFF), ((QWORDCAST(qword) >> 16) & 0xFF), ((QWORDCAST(qword) >> 24) & 0xFF), ((QWORDCAST(qword) >> 32) & 0xFF), ((QWORDCAST(qword) >> 40) & 0xFF), ((QWORDCAST(qword) >> 48) & 0xFF), ((QWORDCAST(qword) >> 56) & 0xFF) // qword ptr [Size: 0x8]

#else

#define BYTEPTR(byte) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (BYTECAST(byte) & 0xFF)) // byte ptr [Size: 0x1]
#define WORDPTR(word) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (WORDCAST(word) & 0xFF), ((WORDCAST(word) >> 8) & 0xFF)) // word ptr [Size: 0x2]
#define DWORDPTR(dword) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x04, (DWORDCAST(dword) & 0xFF), ((DWORDCAST(dword) >> 8) & 0xFF), ((DWORDCAST(dword) >> 16) & 0xFF), ((DWORDCAST(dword) >> 24) & 0xFF)) // dword ptr [Size: 0x4]
#define QWORDPTR(qword) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x08, (QWORDCAST(qword) & 0xFF), ((QWORDCAST(qword) >> 8) & 0xFF), ((QWORDCAST(qword) >> 16) & 0xFF), ((QWORDCAST(qword) >> 24) & 0xFF), ((QWORDCAST(qword) >> 32) & 0xFF), ((QWORDCAST(qword) >> 40) & 0xFF), ((QWORDCAST(qword) >> 48) & 0xFF), ((QWORDCAST(qword) >> 56) & 0xFF)) // qword ptr [Size: 0x8]

#endif
#pragma endregion

#pragma region REGISTERS

#define RAX 0x00 // rax REX extention
#define RCX 0x01 // rcx REX extention
#define RDX 0x02 // rdx REX extention
#define RBX 0x03 // rbx REX extention
#define RSP 0x04 // rsp REX extention
#define RBP 0x05 // rbp REX extention
#define RSI 0x06 // rsi REX extention
#define RDI 0x07 // rdi REX extention

#define EAX 0x00 // eax
#define ECX 0x01 // ecx
#define EDX 0x02 // edx
#define EBX 0x03 // ebx
#define ESP 0x04 // esp
#define EBP 0x05 // ebp
#define ESI 0x06 // esi
#define EDI 0x07 // edi

#define AX 0x00 // ax WORD extention
#define CX 0x01 // cx WORD extention
#define DX 0x02 // dx WORD extention
#define BX 0x03 // bx WORD extention
#define SP 0x04 // sp WORD extention
#define BP 0x05 // bp WORD extention
#define SI 0x06 // si WORD extention
#define DI 0x07 // di WORD extention

#define AL 0x00 // al
#define CL 0x01 // cl
#define DL 0x02 // dl
#define BL 0x03 // bl
#define AH 0x04 // ah
#define CH 0x05 // ch
#define DH 0x06 // dh
#define BH 0x07 // bh

#define SPL 0x04 // spl REX extention
#define BPL 0x05 // bpl REX extention
#define SIL 0x06 // sil REX extention
#define DIL 0x07 // dil REX extention

#define R8 0x00 // r8 REX extention
#define R9 0x01 // r9 REX extention
#define R10 0x02 // r10 REX extention
#define R11 0x03 // r11 REX extention
#define R12 0x04 // r12 REX extention
#define R13 0x05 // r13 REX extention
#define R14 0x06 // r14 REX extention
#define R15 0x07 // r15 REX extention

#define R8D 0x00 // r8d REX extention
#define R9D 0x01 // r9d REX extention
#define R10D 0x02 // r10d REX extention
#define R11D 0x03 // r11d REX extention
#define R12D 0x04 // r12d REX extention
#define R13D 0x05 // r13d REX extention
#define R14D 0x06 // r14d REX extention
#define R15D 0x07 // r15d REX extention

#define R8W 0x00 // r8w REX extention
#define R9W 0x01 // r9w REX extention
#define R10W 0x02 // r10w REX extention
#define R11W 0x03 // r11w REX extention
#define R12W 0x04 // r12w REX extention
#define R13W 0x05 // r13w REX extention
#define R14W 0x06 // r14w REX extention
#define R15W 0x07 // r15w REX extention

#define R8B 0x00 // r8b REX extention
#define R9B 0x01 // r9b REX extention
#define R10B 0x02 // r10b REX extention
#define R11B 0x03 // r11b REX extention
#define R12B 0x04 // r12b REX extention
#define R13B 0x05 // r13b REX extention
#define R14B 0x06 // r14b REX extention
#define R15B 0x07 // r15b REX extention

#define XMM0 0x00 // xmm0
#define XMM1 0x01 // xmm1
#define XMM2 0x02 // xmm2
#define XMM3 0x03 // xmm3
#define XMM4 0x04 // xmm4
#define XMM5 0x05 // xmm5
#define XMM6 0x06 // xmm6
#define XMM7 0x07 // xmm7

#define XMM8 0x00 // xmm8 REX extention
#define XMM9 0x01 // xmm9 REX extention
#define XMM10 0x02 // xmm10 REX extention
#define XMM11 0x03 // xmm11 REX extention
#define XMM12 0x04 // xmm12 REX extention
#define XMM13 0x05 // xmm13 REX extention
#define XMM14 0x06 // xmm14 REX extention
#define XMM15 0x07 // xmm15 REX extention

#define CR0 0x00 // cr0
#define CR1 0x01 // cr1
#define CR2 0x02 // cr2
#define CR3 0x03 // cr3
#define CR4 0x04 // cr4
#define CR5 0x05 // cr5
#define CR6 0x06 // cr6
#define CR7 0x07 // cr7

#define CR8 0x00 // cr8 REX extention
#define CR9 0x01 // cr9 REX extention
#define CR10 0x02 // cr10 REX extention
#define CR11 0x03 // cr11 REX extention
#define CR12 0x04 // cr12 REX extention
#define CR13 0x05 // cr13 REX extention
#define CR14 0x06 // cr14 REX extention
#define CR15 0x07 // cr15 REX extention

#define DR0 0x00 // dr0
#define DR1 0x01 // dr1
#define DR2 0x02 // dr2
#define DR3 0x03 // dr3
#define DR4 0x04 // dr4
#define DR5 0x05 // dr5
#define DR6 0x06 // dr6
#define DR7 0x07 // dr7

#define DR8 0x00 // dr8 REX extention
#define DR9 0x01 // dr9 REX extention
#define DR10 0x02 // dr10 REX extention
#define DR11 0x03 // dr11 REX extention
#define DR12 0x04 // dr12 REX extention
#define DR13 0x05 // dr13 REX extention
#define DR14 0x06 // dr14 REX extention
#define DR15 0x07 // dr15 REX extention

#pragma endregion

#pragma region REGISTER_MEMORY_ARGUMENTS
#ifndef SHELL_RELATIVITY

#define R_MR(r0, r1) (((r0) << 3) | (r1)) // r0, [r1] [Size: 0x1] [r1 - cannot be (rbp/rsp) (ebp/esp)]
#define R_MR_BO(r0, r1, bo) (((r0) << 3) | (r1) | 0x40), BYTEPTR(bo) // r0, [r1 + bo] [Size: 0x2]  [r1 - cannot be (rsp) (esp)]
#define R_MR_DO(r0, r1, do) (((r0) << 3) | (r1) | 0x80), DWORDPTR(do) // r0, [r1 + do] [Size: 0x5]  [r1 - cannot be (rsp) (esp)]
#define R_LR(r0, r1) (((r0) << 3) | (r1) | 0xC0) // r0, r1 [Size: 0x1]

#define R_REL_DO(r0, do) (((r0) << 3) | 0x5), DWORDPTR(do) // r0, [rip + do] [Size: 0x5]

#define R_MRPR(r0, r1, r2) (((r0) << 3) | 0x4), (((r2) << 3) | (r1)) // r0, [r1 + r2] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR_BO(r0, r1, r2, bo) (((r0) << 3) | 0x44), (((r2) << 3) | (r1)), BYTEPTR(bo) // r0, [r1 + r2 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR_DO(r0, r1, r2, do) (((r0) << 3) | 0x84), (((r2) << 3) | (r1)), DWORDPTR(do) // r0, [r1 + r2 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRPR2(r0, r1, r2) (((r0) << 3) | 0x4), (((r2) << 3) | (r1) | 0x40) // r0, [r1 + r2 * 2] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR2_BO(r0, r1, r2, bo) (((r0) << 3) | 0x44), (((r2) << 3) | (r1) | 0x40), BYTEPTR(bo) // r0, [r1 + r2 * 2 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR2_DO(r0, r1, r2, do) (((r0) << 3) | 0x84), (((r2) << 3) | (r1) | 0x40), DWORDPTR(do) // r0, [r1 + r2 * 2 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRPR4(r0, r1, r2) (((r0) << 3) | 0x4), (((r2) << 3) | (r1) | 0x80) // r0, [r1 + r2 * 4] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR4_BO(r0, r1, r2, bo) (((r0) << 3) | 0x44), (((r2) << 3) | (r1) | 0x80), BYTEPTR(bo) // r0, [r1 + r2 * 4 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR4_DO(r0, r1, r2, do) (((r0) << 3) | 0x84), (((r2) << 3) | (r1) | 0x80), DWORDPTR(do) // r0, [r1 + r2 * 4 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRPR8(r0, r1, r2) (((r0) << 3) | 0x4), (((r2) << 3) | (r1) | 0xC0) // r0, [r1 + r2 * 8] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR8_BO(r0, r1, r2, bo) (((r0) << 3) | 0x44), (((r2) << 3) | (r1) | 0xC0), BYTEPTR(bo) // r0, [r1 + r2 * 8 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR8_DO(r0, r1, r2, do) (((r0) << 3) | 0x84), (((r2) << 3) | (r1) | 0xC0), DWORDPTR(do) // r0, [r1 + r2 * 8 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRSP(r0) (((r0) << 3) | 0x4), 0x24 // r0, [rsp] [Size: 0x2]
#define R_MRSP_BO(r0, bo) (((r0) << 3) | 0x44), 0x24, BYTEPTR(bo) // r0, [rsp + bo] [Size: 0x3]
#define R_MRSP_DO(r0, do) (((r0) << 3) | 0x84), 0x24, DWORDPTR(do) // r0, [rsp + do] [Size: 0x6]

#define R_M32(r0, m32) (((r0) << 3) | 0x4), 0x25, DWORDPTR(m32) // r0, [m32] [Size: 0x6]

#define MR_R(r0, r1) R_MR(r1, r0) // [r0], r1 [Size: 0x1] [r0 - cannot be (rbp/rsp) (ebp/esp)]
#define MR_BO_R(r0, r1, bo) R_MR_BO(r1, r0, bo) // [r0 + bo], r1 [Size: 0x2] [r0 - cannot be (rsp) (esp)]
#define MR_DO_R(r0, r1, do) R_MR_DO(r1, r0, do) // [r0 + do], r1 [Size: 0x5] [r0 - cannot be (rsp) (esp)]
#define LR_R(r0, r1) R_LR(r1, r0) // r0, r1 [Size: 0x1]

#define REL_DO_R(r0, do) R_REL_DO(r0, do) // [rip + do], r0 [Size: 0x5]

#define MRPR_R(r0, r1, r2) R_MRPR(r2, r0, r1) // [r0 + r1] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR_BO_R(r0, r1, r2, bo) R_MRPR_BO(r2, r0, r1, bo) // [r0 + r1 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR_DO_R(r0, r1, r2, do) R_MRPR_DO(r2, r0, r1, do) // [r0 + r1 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR2_R(r0, r1, r2) R_MRPR2(r2, r0, r1) // [r0 + r1 * 2] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR2_BO_R(r0, r1, r2, bo) R_MRPR2_BO(r2, r0, r1, bo) // [r0 + r1 * 2 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR2_DO_R(r0, r1, r2, do) R_MRPR2_DO(r2, r0, r1, do) // [r0 + r1 * 2 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR4_R(r0, r1, r2) R_MRPR4(r2, r0, r1) // [r0 + r1 * 4] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR4_BO_R(r0, r1, r2, bo) R_MRPR4_BO(r2, r0, r1, bo) // [r0 + r1 * 4 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR4_DO_R(r0, r1, r2, do) R_MRPR4_DO(r2, r0, r1, do) // [r0 + r1 * 4 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR8_R(r0, r1, r2) R_MRPR8(r2, r0, r1) // [r0 + r1 * 8] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR8_BO_R(r0, r1, r2, bo) R_MRPR8_BO(r2, r0, r1, bo) // [r0 + r1 * 8 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR8_DO_R(r0, r1, r2, do) R_MRPR8_DO(r2, r0, r1, do) // [r0 + r1 * 8 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRSP_R(r0) R_MRSP(r0) // [rsp], r0 [Size: 0x2]
#define MRSP_BO_R(r0, bo) R_MRSP_BO(r0, bo) // [rsp + bo], r0 [Size: 0x3]
#define MRSP_DO_R(r0, do) R_MRSP_DO(r0, do) // [rsp + do], r0 [Size: 0x6]

#define M32_R(r0, m32) R_M32(r0, m32) // [m32], r0 [Size: 0x6]

#define MR(r0) (r0) // [r0] [Size: 0x1] [r0 - cannot be (rbp/rsp) (ebp/esp)]
#define MR_BO(r0, bo) ((r0) | 0x40), BYTEPTR(bo) // [r0 + bo] [Size: 0x2] [r0 - cannot be (rsp) (esp)]
#define MR_DO(r0, do) ((r0) | 0x80), DWORDPTR(do) // [r0 + do] [Size: 0x5] [r0 - cannot be (rsp) (esp)]
#define LR(r0) ((r0) | 0xC0) // r0 [Size: 0x1] [r0 - cannot be (rsp) (esp)]

#define REL_DO(do) 0x5, DWORDPTR(do) // [rip + do] [Size: 0x5]

#define MRPR(r0, r1) 0x4, (((r1) << 3) | (r0)) // [r0 + r1] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR_BO(r0, r1, bo) 0x44, (((r1) << 3) | (r0)), BYTEPTR(bo) // [r0 + r1 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR_DO(r0, r1, do) 0x84, (((r1) << 3) | (r0)), DWORDPTR(do) // [r0 + r1 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR2(r0, r1) 0x4, (((r1) << 3) | (r0) | 0x40) // [r0 + r1 * 2] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR2_BO(r0, r1, bo) 0x44, (((r1) << 3) | (r0) | 0x40), BYTEPTR(bo) // [r0 + r1 * 2 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR2_DO(r0, r1, do) 0x84, (((r1) << 3) | (r0) | 0x40), DWORDPTR(do) // [r0 + r1 * 2 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR4(r0, r1) 0x4, (((r1) << 3) | (r0) | 0x80) // [r0 + r2 * 4] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR4_BO(r0, r1, bo) 0x44, (((r1) << 3) | (r0) | 0x80), BYTEPTR(bo) // [r0 + r1 * 4 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR4_DO(r0, r1, do) 0x84, (((r1) << 3) | (r0) | 0x80), DWORDPTR(do) // [r0 + r1 * 4 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR8(r0, r1) 0x4, (((r1) << 3) | (r0) | 0xC0) // [r0 + r1 * 8] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR8_BO(r0, r1, bo) 0x44, (((r1) << 3) | (r0) | 0xC0), BYTEPTR(bo) // [r0 + r1 * 8 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR8_DO(r0, r1, do) 0x84, (((r1) << 3) | (r0) | 0xC0), DWORDPTR(do) // [r0 + r1 * 8 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRSP 0x4, 0x24 // r0, [rsp] [Size: 0x2]
#define MRSP_BO(bo) 0x44, 0x24, BYTEPTR(bo) // r0, [rsp + bo] [Size: 0x3]
#define MRSP_DO(do) 0x84, 0x24, DWORDPTR(do) // r0, [rsp + do] [Size: 0x6]

#define M32(m32) 0x4, 0x25, DWORDPTR(m32) // [m32] [Size: 0x6]

#else

#define R_MR(r0, r1) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (((r0) << 3) | (r1))) // r0, [r1] [Size: 0x1] [r1 - cannot be (rbp/rsp) (ebp/esp)]
#define R_MR_BO(r0, r1, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (((r0) << 3) | (r1) | 0x40), BYTEPTR(bo)) // r0, [r1 + bo] [Size: 0x2]  [r1 - cannot be (rsp) (esp)]
#define R_MR_DO(r0, r1, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (((r0) << 3) | (r1) | 0x80), DWORDPTR(do)) // r0, [r1 + do] [Size: 0x5]  [r1 - cannot be (rsp) (esp)]
#define R_LR(r0, r1) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (((r0) << 3) | (r1) | 0xC0)) // r0, r1 [Size: 0x1]

#define R_REL_DO(r0, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (((r0) << 3) | 0x5), DWORDPTR(do)) // r0, [rip + do] [Size: 0x5]

#define R_MRPR(r0, r1, r2) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x4), (((r2) << 3) | (r1))) // r0, [r1 + r2] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR_BO(r0, r1, r2, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x44), (((r2) << 3) | (r1)), BYTEPTR(bo)) // r0, [r1 + r2 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR_DO(r0, r1, r2, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x84), (((r2) << 3) | (r1)), DWORDPTR(do)) // r0, [r1 + r2 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRPR2(r0, r1, r2) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x4), (((r2) << 3) | (r1) | 0x40)) // r0, [r1 + r2 * 2] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR2_BO(r0, r1, r2, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x44), (((r2) << 3) | (r1) | 0x40), BYTEPTR(bo)) // r0, [r1 + r2 * 2 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR2_DO(r0, r1, r2, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x84), (((r2) << 3) | (r1) | 0x40), DWORDPTR(do)) // r0, [r1 + r2 * 2 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRPR4(r0, r1, r2) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x4), (((r2) << 3) | (r1) | 0x80)) // r0, [r1 + r2 * 4] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR4_BO(r0, r1, r2, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x44), (((r2) << 3) | (r1) | 0x80), BYTEPTR(bo)) // r0, [r1 + r2 * 4 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR4_DO(r0, r1, r2, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x84), (((r2) << 3) | (r1) | 0x80), DWORDPTR(do)) // r0, [r1 + r2 * 4 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRPR8(r0, r1, r2) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x4), (((r2) << 3) | (r1) | 0xC0)) // r0, [r1 + r2 * 8] [Size: 0x2] [r1 - cannot be (rbp) (ebp) r2 - cannot be (rsp) (esp)]
#define R_MRPR8_BO(r0, r1, r2, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x44), (((r2) << 3) | (r1) | 0xC0), BYTEPTR(bo)) // r0, [r1 + r2 * 8 + bo] [Size: 0x3] [r2 - cannot be (rsp) (esp)]
#define R_MRPR8_DO(r0, r1, r2, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x84), (((r2) << 3) | (r1) | 0xC0), DWORDPTR(do)) // r0, [r1 + r2 * 8 + do] [Size: 0x6] [r2 - cannot be (rsp) (esp)]

#define R_MRSP(r0) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x4), 0x24) // r0, [rsp] [Size: 0x2]
#define R_MRSP_BO(r0, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x44), 0x24, BYTEPTR(bo)) // r0, [rsp + bo] [Size: 0x3]
#define R_MRSP_DO(r0, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x84), 0x24, DWORDPTR(do)) // r0, [rsp + do] [Size: 0x6]

#define R_M32(r0, m32) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, (((r0) << 3) | 0x4), 0x25, DWORDPTR(m32)) // r0, [m32] [Size: 0x6]

#define MR_R(r0, r1) R_MR(r1, r0) // [r0], r1 [Size: 0x1] [r0 - cannot be (rbp/rsp) (ebp/esp)]
#define MR_BO_R(r0, r1, bo) R_MR_BO(r1, r0, bo) // [r0 + bo], r1 [Size: 0x2] [r0 - cannot be (rsp) (esp)]
#define MR_DO_R(r0, r1, do) R_MR_DO(r1, r0, do) // [r0 + do], r1 [Size: 0x5] [r0 - cannot be (rsp) (esp)]
#define LR_R(r0, r1) R_LR(r1, r0) // r0, r1 [Size: 0x1]

#define REL_DO_R(r0, do) R_REL_DO(r0, do) // [rip + do], r0 [Size: 0x5]

#define MRPR_R(r0, r1, r2) R_MRPR(r2, r0, r1) // [r0 + r1] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR_BO_R(r0, r1, r2, bo) R_MRPR_BO(r2, r0, r1, bo) // [r0 + r1 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR_DO_R(r0, r1, r2, do) R_MRPR_DO(r2, r0, r1, do) // [r0 + r1 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR2_R(r0, r1, r2) R_MRPR2(r2, r0, r1) // [r0 + r1 * 2] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR2_BO_R(r0, r1, r2, bo) R_MRPR2_BO(r2, r0, r1, bo) // [r0 + r1 * 2 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR2_DO_R(r0, r1, r2, do) R_MRPR2_DO(r2, r0, r1, do) // [r0 + r1 * 2 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR4_R(r0, r1, r2) R_MRPR4(r2, r0, r1) // [r0 + r1 * 4] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR4_BO_R(r0, r1, r2, bo) R_MRPR4_BO(r2, r0, r1, bo) // [r0 + r1 * 4 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR4_DO_R(r0, r1, r2, do) R_MRPR4_DO(r2, r0, r1, do) // [r0 + r1 * 4 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR8_R(r0, r1, r2) R_MRPR8(r2, r0, r1) // [r0 + r1 * 8] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR8_BO_R(r0, r1, r2, bo) R_MRPR8_BO(r2, r0, r1, bo) // [r0 + r1 * 8 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR8_DO_R(r0, r1, r2, do) R_MRPR8_DO(r2, r0, r1, do) // [r0 + r1 * 8 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRSP_R(r0) R_MRSP(r0) // [rsp], r0 [Size: 0x2]
#define MRSP_BO_R(r0, bo) R_MRSP_BO(r0, bo) // [rsp + bo], r0 [Size: 0x3]
#define MRSP_DO_R(r0, do) R_MRSP_DO(r0, do) // [rsp + do], r0 [Size: 0x6]

#define M32_R(r0, m32) R_M32(r0, m32) // [m32], r0 [Size: 0x6]

#define MR(r0) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (r0)) // [r0] [Size: 0x1] [r0 - cannot be (rbp/rsp) (ebp/esp)]
#define MR_BO(r0, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, ((r0) | 0x40), BYTEPTR(bo)) // [r0 + bo] [Size: 0x2] [r0 - cannot be (rsp) (esp)]
#define MR_DO(r0, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, ((r0) | 0x80), DWORDPTR(do)) // [r0 + do] [Size: 0x5] [r0 - cannot be (rsp) (esp)]
#define LR(r0) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, ((r0) | 0xC0)) // r0 [Size: 0x1] [r0 - cannot be (rsp) (esp)]

#define REL_DO(do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x5, DWORDPTR(do)) // [rip + do] [Size: 0x5]

#define MRPR(r0, r1) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x4, (((r1) << 3) | (r0))) // [r0 + r1] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR_BO(r0, r1, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x44, (((r1) << 3) | (r0)), BYTEPTR(bo)) // [r0 + r1 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR_DO(r0, r1, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x84, (((r1) << 3) | (r0)), DWORDPTR(do)) // [r0 + r1 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR2(r0, r1) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x4, (((r1) << 3) | (r0) | 0x40)) // [r0 + r1 * 2] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR2_BO(r0, r1, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x44, (((r1) << 3) | (r0) | 0x40), BYTEPTR(bo)) // [r0 + r1 * 2 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR2_DO(r0, r1, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x84, (((r1) << 3) | (r0) | 0x40), DWORDPTR(do)) // [r0 + r1 * 2 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR4(r0, r1) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x4, (((r1) << 3) | (r0) | 0x80)) // [r0 + r2 * 4] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR4_BO(r0, r1, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x44, (((r1) << 3) | (r0) | 0x80), BYTEPTR(bo)) // [r0 + r1 * 4 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR4_DO(r0, r1, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x84, (((r1) << 3) | (r0) | 0x80), DWORDPTR(do)) // [r0 + r1 * 4 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRPR8(r0, r1) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x4, (((r1) << 3) | (r0) | 0xC0)) // [r0 + r1 * 8] [Size: 0x2] [r0 - cannot be (rbp) (ebp) r1 - cannot be (rsp) (esp)]
#define MRPR8_BO(r0, r1, bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x44, (((r1) << 3) | (r0) | 0xC0), BYTEPTR(bo)) // [r0 + r1 * 8 + bo] [Size: 0x3] [r1 - cannot be (rsp) (esp)]
#define MRPR8_DO(r0, r1, do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x84, (((r1) << 3) | (r0) | 0xC0), DWORDPTR(do)) // [r0 + r1 * 8 + do] [Size: 0x6] [r1 - cannot be (rsp) (esp)]

#define MRSP INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x4, 0x24) // r0, [rsp] [Size: 0x2]
#define MRSP_BO(bo) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x44, 0x24, BYTEPTR(bo)) // r0, [rsp + bo] [Size: 0x3]
#define MRSP_DO(do) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x84, 0x24, DWORDPTR(do)) // r0, [rsp + do] [Size: 0x6]

#define M32(m32) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x02, 0x4, 0x25, DWORDPTR(m32)) // [m32] [Size: 0x6]

#endif
#pragma endregion

#pragma region PREFIXES
#ifndef SHELL_RELATIVITY

#define PFX_0F 0x0F // Extends the instruction set [Size: 0x1]

#define PFX_CS 0x2E // Redirects to cs segment [Size: 0x1]

#define PFX_REX 0x40 // Enables extended 8-bit (example: ah replaced with spl) [Size: 0x1]
#define PFX_REXB 0x41 // Enables extended RM (example: eax replaced with r8d) [Size: 0x1]
#define PFX_REXX 0x42 // Enables extended PR (example: [rax + rax] replaced with [rax + r8]) [Size: 0x1]

#define PFX_REXBX 0x43 // Combines REXB and REXX [Size: 0x1]
#define PFX_REXXB PFX_REXBX // Combines REXX and REXB [Size: 0x1]

#define PFX_REXR 0x44 // Enables extended R (example: eax replaced with r8d) [Size: 0x1]

#define PFX_REXRB 0x45 // Combines REXR and REXB [Size: 0x1]
#define PFX_REXBR PFX_REXRB // Combines REXB and REXR [Size: 0x1]

#define PFX_REXRX 0x46 // Combines REXR and REXX [Size: 0x1]
#define PFX_REXXR PFX_REXRX // Combines REXX and REXR [Size: 0x1]

#define PFX_REXRXB 0x47 // Combines REXR, REXX and REXB [Size: 0x1]
#define PFX_REXRBX PFX_REXRXB // Combines REXR, REXB and REXX [Size: 0x1]
#define PFX_REXXRB PFX_REXRXB // Combines REXX, REXR and REXB [Size: 0x1]
#define PFX_REXXBR PFX_REXRXB // Combines REXX, REXB and REXR [Size: 0x1]
#define PFX_REXBXR PFX_REXRXB // Combines REXB, REXX and REXR [Size: 0x1]
#define PFX_REXBRX PFX_REXRXB // Combines REXB, REXR and REXX [Size: 0x1]

#define PFX_REXW 0x48 // Enables 64-bit R (example: eax replaced with rax) [Size: 0x1]

#define PFX_REXWB 0x49 // Combines REXW and REXB [Size: 0x1]
#define PFX_REXBW PFX_REXWB // Combines REXB and REXW [Size: 0x1]

#define PFX_REXWX 0x4A // Combines REXW and REXX [Size: 0x1]
#define PFX_REXXW PFX_REXWX // Combines REXX and REXW [Size: 0x1]

#define PFX_REXWXB 0x4B // Combines REXW, REXX and REXB [Size: 0x1]
#define PFX_REXWBX PFX_REXWXB // Combines REXW, REXB and REXX [Size: 0x1]
#define PFX_REXXWB PFX_REXWXB // Combines REXX, REXW and REXB [Size: 0x1]
#define PFX_REXXBW PFX_REXWXB // Combines REXX, REXB and REXW [Size: 0x1]
#define PFX_REXBWX PFX_REXWXB // Combines REXB, REXW and REXX [Size: 0x1]
#define PFX_REXBXW PFX_REXWXB // Combines REXB, REXX and REXW [Size: 0x1]

#define PFX_REXWR 0x4C // Combines REXW and REXR [Size: 0x1]
#define PFX_REXRW PFX_REXWR // Combines REXR and REXW [Size: 0x1]

#define PFX_REXWRB 0x4D // Combines REXW, REXR and REXB [Size: 0x1]
#define PFX_REXWBR PFX_REXWRB // Combines REXW, REXB and REXR [Size: 0x1]
#define PFX_REXRWB PFX_REXWRB // Combines REXR, REXW and REXB [Size: 0x1]
#define PFX_REXRBW PFX_REXWRB // Combines REXR, REXB and REXW [Size: 0x1]
#define PFX_REXBWR PFX_REXWRB // Combines REXB, REXW and REXR [Size: 0x1]
#define PFX_REXBRW PFX_REXWRB // Combines REXB, REXR and REXW [Size: 0x1]

#define PFX_REXWRX 0x4E // Combines REXW, REXR and REXX [Size: 0x1]
#define PFX_REXWXR PFX_REXWRX // Combines REXW, REXX and REXR [Size: 0x1]
#define PFX_REXRWX PFX_REXWRX // Combines REXR, REXW and REXX [Size: 0x1]
#define PFX_REXRXW PFX_REXWRX // Combines REXR, REXX and REXW [Size: 0x1]
#define PFX_REXXWR PFX_REXWRX // Combines REXX, REXW and REXR [Size: 0x1]
#define PFX_REXXRW PFX_REXWRX // Combines REXX, REXR and REXW [Size: 0x1]

#define PFX_REXWRXB 0x4F // Combines REXW, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXWRBX PFX_REXWRXB // Combines REXW, REXR, REXB and REXX [Size: 0x1]
#define PFX_REXWBRX PFX_REXWRXB // Combines REXW, REXB, REXR and REXX [Size: 0x1]
#define PFX_REXWBXR PFX_REXWRXB // Combines REXW, REXB, REXX and REXR [Size: 0x1]
#define PFX_REXWXBR PFX_REXWRXB // Combines REXW, REXX, REXB and REXR [Size: 0x1]
#define PFX_REXWXRB PFX_REXWRXB // Combines REXW, REXX, REXR and REXB [Size: 0x1]
#define PFX_REXRWXB PFX_REXWRXB // Combines REXR, REXW, REXX and REXB [Size: 0x1]
#define PFX_REXRWBX PFX_REXWRXB // Combines REXR, REXW, REXB and REXX [Size: 0x1]
#define PFX_REXRBWX PFX_REXWRXB // Combines REXR, REXB, REXW and REXX [Size: 0x1]
#define PFX_REXRBXW PFX_REXWRXB // Combines REXR, REXB, REXX and REXW [Size: 0x1]
#define PFX_REXRXBW PFX_REXWRXB // Combines REXR, REXX, REXB and REXW [Size: 0x1]
#define PFX_REXRXWB PFX_REXWRXB // Combines REXR, REXX, REXW and REXB [Size: 0x1]
#define PFX_REXBXWR PFX_REXWRXB // Combines REXB, REXX, REXW and REXR [Size: 0x1]
#define PFX_REXBXRW PFX_REXWRXB // Combines REXB, REXX, REXR and REXW [Size: 0x1]
#define PFX_REXBRWX PFX_REXWRXB // Combines REXB, REXR, REXW and REXX [Size: 0x1]
#define PFX_REXBRXW PFX_REXWRXB // Combines REXB, REXR, REXX and REXW [Size: 0x1]
#define PFX_REXBWRX PFX_REXWRXB // Combines REXB, REXW, REXR and REXX [Size: 0x1]
#define PFX_REXBWXR PFX_REXWRXB // Combines REXB, REXW, REXX and REXR [Size: 0x1]
#define PFX_REXXBWR PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXBRW PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXRWB PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXRBW PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXWRB PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXWXB PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]

#define PFX_FS 0x64 // Redirects M to FS segment
#define PFX_GS 0x65 // Redirects M to GS segment

#define PFX_WORD 0x66 // Enables 16 bit registers (example: eax replaced with ax)

#define PFX_LOCK 0xF0 // Assert lock signal

#define PFX_REPNZ 0xF2 // repeat string operation
#define PFX_REPNE PFX_REPNZ // repeat string operation

#define PFX_REPZ 0xF3 // repeat string operation
#define PFX_REPE PFX_REPZ // repeat string operation

#else

#define PFX_0F INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x0F) // Extends the instruction set [Size: 0x1]

#define PFX_CS INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x2E) // Redirects to cs segment [Size: 0x1]

#define PFX_REX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x40) // Enables extended 8-bit (example: ah replaced with spl) [Size: 0x1]
#define PFX_REXB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x41) // Enables extended RM (example: eax replaced with r8d) [Size: 0x1]
#define PFX_REXX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x42) // Enables extended PR (example: [rax + rax] replaced with [rax + r8]) [Size: 0x1]

#define PFX_REXBX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x43) // Combines REXB and REXX [Size: 0x1]
#define PFX_REXXB PFX_REXBX // Combines REXX and REXB [Size: 0x1]

#define PFX_REXR INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x44) // Enables extended R (example: eax replaced with r8d) [Size: 0x1]

#define PFX_REXRB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x45) // Combines REXR and REXB [Size: 0x1]
#define PFX_REXBR PFX_REXRB // Combines REXB and REXR [Size: 0x1]

#define PFX_REXRX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x46) // Combines REXR and REXX [Size: 0x1]
#define PFX_REXXR PFX_REXRX // Combines REXX and REXR [Size: 0x1]

#define PFX_REXRXB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x47) // Combines REXR, REXX and REXB [Size: 0x1]
#define PFX_REXRBX PFX_REXRXB // Combines REXR, REXB and REXX [Size: 0x1]
#define PFX_REXXRB PFX_REXRXB // Combines REXX, REXR and REXB [Size: 0x1]
#define PFX_REXXBR PFX_REXRXB // Combines REXX, REXB and REXR [Size: 0x1]
#define PFX_REXBXR PFX_REXRXB // Combines REXB, REXX and REXR [Size: 0x1]
#define PFX_REXBRX PFX_REXRXB // Combines REXB, REXR and REXX [Size: 0x1]

#define PFX_REXW INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x48) // Enables 64-bit R (example: eax replaced with rax) [Size: 0x1]

#define PFX_REXWB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x49) // Combines REXW and REXB [Size: 0x1]
#define PFX_REXBW PFX_REXWB // Combines REXB and REXW [Size: 0x1]

#define PFX_REXWX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4A) // Combines REXW and REXX [Size: 0x1]
#define PFX_REXXW PFX_REXWX // Combines REXX and REXW [Size: 0x1]

#define PFX_REXWXB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4B) // Combines REXW, REXX and REXB [Size: 0x1]
#define PFX_REXWBX PFX_REXWXB // Combines REXW, REXB and REXX [Size: 0x1]
#define PFX_REXXWB PFX_REXWXB // Combines REXX, REXW and REXB [Size: 0x1]
#define PFX_REXXBW PFX_REXWXB // Combines REXX, REXB and REXW [Size: 0x1]
#define PFX_REXBWX PFX_REXWXB // Combines REXB, REXW and REXX [Size: 0x1]
#define PFX_REXBXW PFX_REXWXB // Combines REXB, REXX and REXW [Size: 0x1]

#define PFX_REXWR INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4C) // Combines REXW and REXR [Size: 0x1]
#define PFX_REXRW PFX_REXWR // Combines REXR and REXW [Size: 0x1]

#define PFX_REXWRB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4D) // Combines REXW, REXR and REXB [Size: 0x1]
#define PFX_REXWBR PFX_REXWRB // Combines REXW, REXB and REXR [Size: 0x1]
#define PFX_REXRWB PFX_REXWRB // Combines REXR, REXW and REXB [Size: 0x1]
#define PFX_REXRBW PFX_REXWRB // Combines REXR, REXB and REXW [Size: 0x1]
#define PFX_REXBWR PFX_REXWRB // Combines REXB, REXW and REXR [Size: 0x1]
#define PFX_REXBRW PFX_REXWRB // Combines REXB, REXR and REXW [Size: 0x1]

#define PFX_REXWRX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4E) // Combines REXW, REXR and REXX [Size: 0x1]
#define PFX_REXWXR PFX_REXWRX // Combines REXW, REXX and REXR [Size: 0x1]
#define PFX_REXRWX PFX_REXWRX // Combines REXR, REXW and REXX [Size: 0x1]
#define PFX_REXRXW PFX_REXWRX // Combines REXR, REXX and REXW [Size: 0x1]
#define PFX_REXXWR PFX_REXWRX // Combines REXX, REXW and REXR [Size: 0x1]
#define PFX_REXXRW PFX_REXWRX // Combines REXX, REXR and REXW [Size: 0x1]

#define PFX_REXWRXB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4F) // Combines REXW, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXWRBX PFX_REXWRXB // Combines REXW, REXR, REXB and REXX [Size: 0x1]
#define PFX_REXWBRX PFX_REXWRXB // Combines REXW, REXB, REXR and REXX [Size: 0x1]
#define PFX_REXWBXR PFX_REXWRXB // Combines REXW, REXB, REXX and REXR [Size: 0x1]
#define PFX_REXWXBR PFX_REXWRXB // Combines REXW, REXX, REXB and REXR [Size: 0x1]
#define PFX_REXWXRB PFX_REXWRXB // Combines REXW, REXX, REXR and REXB [Size: 0x1]
#define PFX_REXRWXB PFX_REXWRXB // Combines REXR, REXW, REXX and REXB [Size: 0x1]
#define PFX_REXRWBX PFX_REXWRXB // Combines REXR, REXW, REXB and REXX [Size: 0x1]
#define PFX_REXRBWX PFX_REXWRXB // Combines REXR, REXB, REXW and REXX [Size: 0x1]
#define PFX_REXRBXW PFX_REXWRXB // Combines REXR, REXB, REXX and REXW [Size: 0x1]
#define PFX_REXRXBW PFX_REXWRXB // Combines REXR, REXX, REXB and REXW [Size: 0x1]
#define PFX_REXRXWB PFX_REXWRXB // Combines REXR, REXX, REXW and REXB [Size: 0x1]
#define PFX_REXBXWR PFX_REXWRXB // Combines REXB, REXX, REXW and REXR [Size: 0x1]
#define PFX_REXBXRW PFX_REXWRXB // Combines REXB, REXX, REXR and REXW [Size: 0x1]
#define PFX_REXBRWX PFX_REXWRXB // Combines REXB, REXR, REXW and REXX [Size: 0x1]
#define PFX_REXBRXW PFX_REXWRXB // Combines REXB, REXR, REXX and REXW [Size: 0x1]
#define PFX_REXBWRX PFX_REXWRXB // Combines REXB, REXW, REXR and REXX [Size: 0x1]
#define PFX_REXBWXR PFX_REXWRXB // Combines REXB, REXW, REXX and REXR [Size: 0x1]
#define PFX_REXXBWR PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXBRW PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXRWB PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXRBW PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXWRB PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]
#define PFX_REXXWXB PFX_REXWRXB // Combines REXX, REXR, REXX and REXB [Size: 0x1]

#define PFX_FS INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x64) // Redirects M to FS segment
#define PFX_GS INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x65) // Redirects M to GS segment

#define PFX_WORD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x66) // Enables 16 bit registers (example: eax replaced with ax)

#define PFX_LOCK INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF0) // Assert lock signal

#define PFX_REPNZ INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF2) // repeat string operation
#define PFX_REPNE PFX_REPNZ // repeat string operation

#define PFX_REPZ INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF3) // repeat string operation
#define PFX_REPE PFX_REPZ // repeat string operation

#endif
#pragma endregion

#pragma region FIRST_INSTRUCTION_BATCH
#ifndef SHELL_RELATIVITY

#define ADDB_RM_R(rm_r) 0x00, rm_r // add rm_r [Size: 0x1]
#define ADDD_RM_R(rm_r) 0x01, rm_r // add rm_r [Size: 0x1]

#define ADDB_R_RM(r_rm) 0x02, r_rm // add r_rm [Size: 0x1]
#define ADDD_R_RM(r_rm) 0x03, r_rm // add r_rm [Size: 0x1]

#define ADDB_AL_B(b) 0x04, BYTEPTR(b) // add al, byte [Size: 0x2]
#define ADDW_AX_W(w) PFX_WORD, 0x05, WORDPTR(w) // add al, word [Size: 0x4]
#define ADDD_EAX_D(d) 0x05, DWORDPTR(d) // add eax, dword [Size: 0x5]

#define ORB_RM_R(rm_r) 0x08, rm_r // or rm_r [Size: 0x1]
#define ORD_RM_R(rm_r) 0x09, rm_r // or rm_r [Size: 0x1]

#define ORB_R_RM(r_rm) 0x0A, r_rm // or r_rm [Size: 0x1]
#define ORD_R_RM(r_rm) 0x0B, r_rm // or r_rm [Size: 0x1]

#define ORB_AL_B(b) 0x0C, BYTEPTR(b) // or al, byte [Size: 0x2]
#define ORW_AX_W(w) PFX_WORD, 0x0D, WORDPTR(w) // or al, word [Size: 0x4]
#define ORD_EAX_D(d) 0x0D, DWORDPTR(d) // or eax, dword [Size: 0x5]

#define ADCB_RM_R(rm_r) 0x10, rm_r // adc rm_r [Size: 0x1]
#define ADCD_RM_R(rm_r) 0x11, rm_r // adc rm_r [Size: 0x1]

#define ADCB_R_RM(r_rm) 0x12, r_rm // adc r_rm [Size: 0x1]
#define ADCD_R_RM(r_rm) 0x13, r_rm // adc r_rm [Size: 0x1]

#define ADCB_AL_B(b) 0x14, BYTEPTR(b) // adc al, byte [Size: 0x2]
#define ADCW_AX_W(w) PFX_WORD, 0x15, WORDPTR(w) // adc al, word [Size: 0x4]
#define ADCD_EAX_D(d) 0x15, DWORDPTR(d) // adc eax, dword [Size: 0x5]

#define SBBB_RM_R(rm_r) 0x18, rm_r // sbb rm_r [Size: 0x1]
#define SBBD_RM_R(rm_r) 0x19, rm_r // sbb rm_r [Size: 0x1]

#define SBBB_R_RM(r_rm) 0x1A, r_rm // sbb r_rm [Size: 0x1]
#define SBBD_R_RM(r_rm) 0x1B, r_rm // sbb r_rm [Size: 0x1]

#define SBBB_AL_B(byte) 0x1C, BYTEPTR(byte) // sbb al, byte [Size: 0x2]
#define SBBW_AX_W(word) PFX_WORD, 0x1D, WORDPTR(word) // sbb al, word [Size: 0x4]
#define SBBD_EAX_D(dword) 0x1D, DWORDPTR(dword) // sbb eax, dword [Size: 0x5]

#define ANDB_RM_R(rm_r) 0x20, rm_r // and rm_r [Size: 0x1]
#define ANDD_RM_R(rm_r) 0x21, rm_r // and rm_r [Size: 0x1]

#define ANDB_R_RM(r_rm) 0x22, r_rm // and r_rm [Size: 0x1]
#define ANDD_R_RM(r_rm) 0x23, r_rm // and r_rm [Size: 0x1]

#define ANDB_AL_B(b) 0x24, BYTEPTR(b) // and al, byte [Size: 0x2]
#define ANDW_AX_W(w) PFX_WORD, 0x25, WORDPTR(w) // and al, word [Size: 0x4]
#define ANDD_EAX_D(d) 0x25, DWORDPTR(d) // and eax, dword [Size: 0x5]

#define SUBB_RM_R(rm_r) 0x28, rm_r // sub rm_r [Size: 0x1]
#define SUBD_RM_R(rm_r) 0x29, rm_r // sub rm_r [Size: 0x1]

#define SUBB_R_RM(r_rm) 0x2A, r_rm // sub r_rm [Size: 0x1]
#define SUBD_R_RM(r_rm) 0x2B, r_rm // sub r_rm [Size: 0x1]

#define SUBB_AL_B(b) 0x2C, BYTEPTR(b) // sub al, byte [Size: 0x2]
#define SUBW_AX_W(w) PFX_WORD, 0x2D, WORDPTR(w) // sub al, word [Size: 0x4]
#define SUBD_EAX_D(d) 0x2D, DWORDPTR(d) // sub eax, dword [Size: 0x5]

#define XORB_RM_R(rm_r) 0x30, rm_r // xor rm_r [Size: 0x1]
#define XORD_RM_R(rm_r) 0x31, rm_r // xor rm_r [Size: 0x1]

#define XORB_R_RM(r_rm) 0x32, r_rm // xor r_rm [Size: 0x1]
#define XORD_R_RM(r_rm) 0x33, r_rm // xor r_rm [Size: 0x1]

#define XORB_AL_B(b) 0x34, BYTEPTR(b) // xor al, byte [Size: 0x2]
#define XORW_AX_W(w) PFX_WORD, 0x35, WORDPTR(w) // xor al, word [Size: 0x4]
#define XORD_EAX_D(d) 0x35, DWORDPTR(d) // xor eax, dword [Size: 0x5]

#define CMP_RM_R(rm_r) 0x38, rm_r // xor rm_r [Size: 0x1]
#define CMPD_RM_R(rm_r) 0x39, rm_r // xor rm_r [Size: 0x1]

#define CMP_R_RM(r_rm) 0x3A, r_rm // xor r_rm [Size: 0x1]
#define CMPD_R_RM(r_rm) 0x3B, r_rm // xor r_rm [Size: 0x1]

#define CMP_AL_B(b) 0x3C, BYTEPTR(b) // xor al, byte [Size: 0x2]
#define CMPW_AX_W(w) PFX_WORD, 0x3D, WORDPTR(w) // xor al, word [Size: 0x4]
#define CMPD_EAX_D(d) 0x3D, DWORDPTR(d) // xor eax, dword [Size: 0x5]

#define PUSHQ_R(r0) (0x50 + (r0)) // push r0 [Size: 0x1]
#define POPQ_R(r0) (0x58 + (r0)) // push r0 [Size: 0x1]

#define MOVSXD_R_RM(r_rm) 0x63, r_rm // movsxd r_rm [Size: 0x1]

#define PUSH_W(w) PFX_WORD, 0x68, WORDPTR(w) // push w [Size: 0x4]
#define PUSH_D(d) 0x68, DWORDPTR(d) // push d [Size: 0x5]

#define IMUL_R_RM_W(r_rm, w) PFX_WORD, 0x69, r_rm, WORDPTR(w) // imul r_rm, w [Size: 0x3]
#define IMUL_R_RM_D(r_rm, d) 0x69, r_rm, DWORDPTR(d) // imul r_rm, d [Size: 0x5]

#define PUSH_B(b) 0x6A, BYTEPTR(b) // push b [Size: 0x2]

#define IMUL_R_RM_B(r_rm, b) 0x6B, r_rm, BYTEPTR(b) // imul r_rm, b [Size: 0x2]

#define INSB 0x6C // ins [Size: 0x1]
#define INSD 0x6D // ins [Size: 0x1]

#define OUTB 0x6E // out [Size: 0x1]
#define OUTD 0x6F // out [Size: 0x1]

#define JO_RB(rb) 0x70, BYTEPTR(rb) // jo rb [Size: 0x2]

#define JNO_RB(rb) 0x71, BYTEPTR(rb) // jo rb [Size: 0x2]

#define JB_RB(rb) 0x72, BYTEPTR(rb) // jb rb [Size: 0x2]
#define JNAE_RB(rb) JB_RB(rb) // jnae rb [Size: 0x2]
#define JC_RB(rb) JB_RB(rb) // jc rb [Size: 0x2]

#define JNB_RB(rb) 0x73, BYTEPTR(rb) // jnb rb [Size: 0x2]
#define JAE_RB(rb) JNB_RB(rb) // jae rb [Size: 0x2]
#define JNC_RB(rb) JNB_RB(rb) // jnc rb [Size: 0x2]

#define JZ_RB(rb) 0x74, BYTEPTR(rb) // jz rb [Size: 0x2]
#define JE_RB(rb) JZ_RB(rb) // je rb [Size: 0x2]

#define JNZ_RB(rb) 0x75, BYTEPTR(rb) // jnz rb [Size: 0x2]
#define JNE_RB(rb) JNZ_RB(rb) // jne rb [Size: 0x2]

#define JBE_RB(rb) 0x76, BYTEPTR(rb) // jbe rb [Size: 0x2]
#define JNA_RB(rb) JBE_RB(rb) // jna rb [Size: 0x2]

#define JNBE_RB(rb) 0x77, BYTEPTR(rb) // jnbe rb [Size: 0x2]
#define JA_RB(rb) JNBE_RB(rb) // ja rb [Size: 0x2]

#define JS_RB(rb) 0x78, BYTEPTR(rb) // js rb [Size: 0x2]

#define JNS_RB(rb) 0x79, BYTEPTR(rb) // jns rb [Size: 0x2]

#define JP_RB(rb) 0x7A, BYTEPTR(rb) // jp rb [Size: 0x2]
#define JPE_RB(rb) JP_RB(rb) // jpe rb [Size: 0x2]

#define JNP_RB(rb) 0x7B, BYTEPTR(rb) // jnp rb [Size: 0x2]
#define JPO_RB(rb) JNP_RB(rb) // jpo rb [Size: 0x2]

#define JL_RB(rb) 0x7C, BYTEPTR(rb) // jl rb [Size: 0x2]
#define JNGE_RB(rb) JL_RB(rb) // jnge rb [Size: 0x2]

#define JNL_RB(rb) 0x7D, BYTEPTR(rb) // jnl rb [Size: 0x2]
#define JGE_RB(rb) JNL_RB(rb) // jge rb [Size: 0x2]

#define JLE_RB(rb) 0x7E, BYTEPTR(rb) // jle rb [Size: 0x2]
#define JNG_RB(rb) JLE_RB(rb) // jng rb [Size: 0x2]

#define JNLE_RB(rb) 0x7F, BYTEPTR(rb) // jnle rb [Size: 0x2]
#define JG_RB(rb) JNLE_RB(rb) // jg rb [Size: 0x2]

#define ADD_RM_B(rm, b) 0x80, rm, BYTEPTR(b) // add rm, b [Size: 0x2]
#define OR_RM_B(rm, b) 0x80, 0x8 | rm, BYTEPTR(b) // or rm, b [Size: 0x2]
#define ADC_RM_B(rm, b) 0x80, 0x10 | rm, BYTEPTR(b) // adc rm, b [Size: 0x2]
#define SBB_RM_B(rm, b) 0x80, 0x18 | rm, BYTEPTR(b) // sbb rm, b [Size: 0x2]
#define AND_RM_B(rm, b) 0x80, 0x20 | rm, BYTEPTR(b) // and rm, b [Size: 0x2]
#define SUB_RM_B(rm, b) 0x80, 0x28 | rm, BYTEPTR(b) // sub rm, b [Size: 0x2]
#define XOR_RM_B(rm, b) 0x80, 0x30 | rm, BYTEPTR(b) // xor rm, b [Size: 0x2]
#define CMP_RM_B(rm, b) 0x80, 0x38 | rm, BYTEPTR(b) // cmp rm, b [Size: 0x2]

#define ADD_RM_W(rm, w) PFX_WORD, 0x81, rm, WORDPTR(w) // add rm, w [Size: 0x3]
#define OR_RM_W(rm, w) PFX_WORD, 0x81, 0x8 | rm, WORDPTR(w) // or rm, w [Size: 0x3]
#define ADC_RM_W(rm, w) PFX_WORD, 0x81, 0x10 | rm, WORDPTR(w) // adc rm, w [Size: 0x3]
#define SBB_RM_W(rm, w) PFX_WORD, 0x81, 0x18 | rm, WORDPTR(w) // sbb rm, w [Size: 0x3]
#define AND_RM_W(rm, w) PFX_WORD, 0x81, 0x20 | rm, WORDPTR(w) // and rm, w [Size: 0x3]
#define SUB_RM_W(rm, w) PFX_WORD, 0x81, 0x28 | rm, WORDPTR(w) // sub rm, w [Size: 0x3]
#define XOR_RM_W(rm, w) PFX_WORD, 0x81, 0x30 | rm, WORDPTR(w) // xor rm, w [Size: 0x3]
#define CMP_RM_W(rm, w) PFX_WORD, 0x81, 0x38 | rm, WORDPTR(w) // cmp rm, w [Size: 0x3]

#define ADD_RM_D(rm, d) 0x81, rm, DWORDPTR(d) // add rm, d [Size: 0x5]
#define OR_RM_D(rm, d) 0x81, 0x8 | rm, DWORDPTR(d) // or rm, d [Size: 0x5]
#define ADC_RM_D(rm, d) 0x81, 0x10 | rm, DWORDPTR(d) // adc rm, d [Size: 0x5]
#define SBB_RM_D(rm, d) 0x81, 0x18 | rm, DWORDPTR(d) // sbb rm, d [Size: 0x5]
#define AND_RM_D(rm, d) 0x81, 0x20 | rm, DWORDPTR(d) // and rm, d [Size: 0x5]
#define SUB_RM_D(rm, d) 0x81, 0x28 | rm, DWORDPTR(d) // sub rm, d [Size: 0x5]
#define XOR_RM_D(rm, d) 0x81, 0x30 | rm, DWORDPTR(d) // xor rm, d [Size: 0x5]
#define CMP_RM_D(rm, d) 0x81, 0x38 | rm, DWORDPTR(d) // cmp rm, d [Size: 0x5]

#define ADDD_RM_B(rm, b) 0x83, rm, BYTEPTR(b) // add rm, b [Size: 0x2]
#define ORD_RM_B(rm, b) 0x83, 0x8 | rm, BYTEPTR(b) // or rm, b [Size: 0x2]
#define ADCD_RM_B(rm, b) 0x83, 0x10 | rm, BYTEPTR(b) // adc rm, b [Size: 0x2]
#define SBBD_RM_B(rm, b) 0x83, 0x18 | rm, BYTEPTR(b) // sbb rm, b [Size: 0x2]
#define ANDD_RM_B(rm, b) 0x83, 0x20 | rm, BYTEPTR(b) // and rm, b [Size: 0x2]
#define SUBD_RM_B(rm, b) 0x83, 0x28 | rm, BYTEPTR(b) // sub rm, b [Size: 0x2]
#define XORD_RM_B(rm, b) 0x83, 0x30 | rm, BYTEPTR(b) // xor rm, b [Size: 0x2]
#define CMPD_RM_B(rm, b) 0x83, 0x38 | rm, BYTEPTR(b) // cmp rm, b [Size: 0x2]

#define TESTB_RM_R(rm_r) 0x84, rm_r // test rm_r [Size: 0x1]
#define TESTD_RM_R(rm_r) 0x85, rm_r // test rm_r [Size: 0x1]

#define XCHGB_R_RM(r_rm) 0x86, r_rm // xchg r_rm [Size: 0x1]
#define XCHGD_R_RM(r_rm) 0x87, r_rm // xchg r_rm [Size: 0x1]

#define MOVB_RM_R(rm_r) 0x88, rm_r // mov rm_r [Size: 0x1]
#define MOVD_RM_R(rm_r) 0x89, rm_r // mov rm_r [Size: 0x1]

#define MOVB_R_RM(r_rm) 0x8A, r_rm // mov r_rm [Size: 0x1]
#define MOVD_R_RM(r_rm) 0x8B, r_rm // mov r_rm [Size: 0x1]

#define MOVD_RM_S(rm_s) 0x8C, rm_s // mov rm_s [Size: 0x1]

#define LEAD_R_M(r_m) 0x8D, r_m // lea r_m [Size: 0x1]

#define MOVD_S_RM(rm_s) 0x8E, s_rm // mov s_rm [Size: 0x1]

#define POPD_RM(rm) 0x8F, rm // pop rm [Size: 0x1]

#define NOP 0x90 // nop [Size: 0x1]

#define XCHGD_R_EAX(r) (0x90 + (r)) // xchg r, eax [Size: 0x1]

#define CWDE 0x98 // cwde [Size: 0x1]
#define CDQ 0x99 // cdq [Size: 0x1]

#define WAIT 0x9B // wait [Size: 0x1]

#define PUSHF 0x9C // pushf [Size: 0x1]
#define POPF 0x9D // popf [Size: 0x1]

#define SAHF 0x9E // sahf [Size: 0x1]
#define LAHF 0x9F // lahf [Size: 0x1]

#define MOV_AL_QM(qm) 0xA0, QWORDPTR(qm) // mov al, [qm] [Size: 0x9]
#define MOV_EAX_QM(qm) 0xA1, QWORDPTR(qm) // mov eax, [qm] [Size: 0x9]

#define MOV_QM_AL(qm) 0xA2, QWORDPTR(qm) // mov [qm], al [Size: 0x9]
#define MOV_QM_EAX(qm) 0xA3, QWORDPTR(qm) // mov [qm], eax [Size: 0x9]

#define MOVSB 0xA4 // movsb [Size: 0x1]
#define MOVSD 0xA5 // movsd [Size: 0x1]

#define CMPSB 0xA6 // cmpsb [Size: 0x1]
#define CMPSD 0xA7 // cmpsd [Size: 0x1]

#define TEST_AL_B(b) 0xA8, BYTEPTR(b) // test al, b [Size: 0x2]
#define TEST_AX_D(w) PFX_WORD, 0xA9, WORDPTR(w) // test ax, w [Size: 0x4]
#define TEST_EAX_D(d) 0xA9, DWORDPTR(d) // test eax, d [Size: 0x5]

#define STOSB 0xAA // stosb [Size: 0x1]
#define STOSD 0xAB // stosd [Size: 0x1]

#define LODSB 0xAC // lodsb [Size: 0x1]
#define LODSD 0xAD // lodsd [Size: 0x1]

#define SCASB 0xAE // scasb [Size: 0x1]
#define SCASW 0xAF // scasd [Size: 0x1]

#define MOV_R_B(r, b) (0xB0 + (r)), BYTEPTR(b) // mov r, b [Size: 0x2]
#define MOV_R_W(r, w) PFX_WORD, (0xB8 + (r)), WORDPTR(w) // mov r, w [Size: 0x4]
#define MOV_R_D(r, d) (0xB8 + (r)), DWORDPTR(d) // mov r, d [Size: 0x5]
#define MOV_R_Q(r, q) PFX_REXW, (0xB8 + (r)), QWORDPTR(q) // mov r, q [Size: 0xA]
#define MOV_ER_Q(r, q) PFX_REXWB, (0xB8 + (r)), QWORDPTR(q) // mov r, q [Size: 0xA]

#define ROLB_RM_B(rm, b) 0xC0, rm, BYTEPTR(b) // rol rm, b [Size: 0x2]
#define RORB_RM_B(rm, b) 0xC0, 0x8 | rm, BYTEPTR(b) // ror rm, b [Size: 0x2]
#define RCLB_RM_B(rm, b) 0xC0, 0x10 | rm, BYTEPTR(b) // rcl rm, b [Size: 0x2]
#define RCRB_RM_B(rm, b) 0xC0, 0x18 | rm, BYTEPTR(b) // rcr rm, b [Size: 0x2]
#define SHLB_RM_B(rm, b) 0xC0, 0x20 | rm, BYTEPTR(b) // shl rm, b [Size: 0x2]
#define SHRB_RM_B(rm, b) 0xC0, 0x28 | rm, BYTEPTR(b) // shr rm, b [Size: 0x2]
#define SALB_RM_B(rm, b) 0xC0, 0x30 | rm, BYTEPTR(b) // sal rm, b [Size: 0x2]
#define SARB_RM_B(rm, b) 0xC0, 0x38 | rm, BYTEPTR(b) // sar rm, b [Size: 0x2]

#define ROLD_RM_B(rm, b) 0xC1, rm, BYTEPTR(b) // rol rm, b [Size: 0x2]
#define RORD_RM_B(rm, b) 0xC1, 0x8 | rm, BYTEPTR(b) // ror rm, b [Size: 0x2]
#define RCLD_RM_B(rm, b) 0xC1, 0x10 | rm, BYTEPTR(b) // rcl rm, b [Size: 0x2]
#define RCRD_RM_B(rm, b) 0xC1, 0x18 | rm, BYTEPTR(b) // rcr rm, b [Size: 0x2]
#define SHLD_RM_B(rm, b) 0xC1, 0x20 | rm, BYTEPTR(b) // shl rm, b [Size: 0x2]
#define SHRD_RM_B(rm, b) 0xC1, 0x28 | rm, BYTEPTR(b) // shr rm, b [Size: 0x2]
#define SALD_RM_B(rm, b) 0xC1, 0x30 | rm, BYTEPTR(b) // sal rm, b [Size: 0x2]
#define SARD_RM_B(rm, b) 0xC1, 0x38 | rm, BYTEPTR(b) // sar rm, b [Size: 0x2]

#define RETN_W(w) 0xC2, WORDPTR(w) // ret w [Size: 0x3]
#define RETN 0xC3 // ret [Size: 0x1]

#define MOV_RM_B(rm, b) 0xC6, rm, BYTEPTR(b) // mov rm, b [Size: 0x2]
#define MOV_RM_W(rm, w) PFX_WORD, 0xC7, rm, WORDPTR(w) // mov rm, w [Size: 0x4]
#define MOV_RM_D(rm, w) 0xC7, rm, DWORDPTR(w) // mov rm, d [Size: 0x4]

#define ENTER(w, b) 0xC8, WORDPTR(w), BYTEPTR(b) // enter w, b [Size: 0x4]
#define LEAVE 0xC9 // leave [Size: 0x1]

#define RETF(w) 0xCA, WORDPTR(w) // ret w [Size: 0x3]
#define RETF 0xCB // ret [Size: 0x1]

#define INT_3 0xCC // int 3 [Size: 0x1]
#define INT_B(b) 0xCD, BYTEPTR(b) // int b [Size: 0x2]

#define INTO 0xCE // into [Size: 0x1]

#define IRETD 0xCF // iretd [Size: 0x1]

#define ROLB_RM_1(rm) 0xD0, rm // rol rm, 1 [Size: 0x1]
#define RORB_RM_1(rm) 0xD0, 0x8 | rm // ror rm, 1 [Size: 0x1]
#define RCLB_RM_1(rm) 0xD0, 0x10 | rm // rcl rm, 1 [Size: 0x1]
#define RCRB_RM_1(rm) 0xD0, 0x18 | rm // rcr rm, 1 [Size: 0x1]
#define SHLB_RM_1(rm) 0xD0, 0x20 | rm // shl rm, 1 [Size: 0x1]
#define SHRB_RM_1(rm) 0xD0, 0x28 | rm // shr rm, 1 [Size: 0x1]
#define SALB_RM_1(rm) 0xD0, 0x30 | rm // sal rm, 1 [Size: 0x1]
#define SARB_RM_1(rm) 0xD0, 0x38 | rm // sar rm, 1 [Size: 0x1]

#define ROLD_RM_1(rm) 0xD1, rm // rol rm, 1 [Size: 0x1]
#define RORD_RM_1(rm) 0xD1, 0x8 | rm // ror rm, 1 [Size: 0x1]
#define RCLD_RM_1(rm) 0xD1, 0x10 | rm // rcl rm, 1 [Size: 0x1]
#define RCRD_RM_1(rm) 0xD1, 0x18 | rm // rcr rm, 1 [Size: 0x1]
#define SHLD_RM_1(rm) 0xD1, 0x20 | rm // shl rm, 1 [Size: 0x1]
#define SHRD_RM_1(rm) 0xD1, 0x28 | rm // shr rm, 1 [Size: 0x1]
#define SALD_RM_1(rm) 0xD1, 0x30 | rm // sal rm, 1 [Size: 0x1]
#define SARD_RM_1(rm) 0xD1, 0x38 | rm // sar rm, 1 [Size: 0x1]

#define ROLB_RM_CL(rm) 0xD2, rm // rol rm, cl [Size: 0x1]
#define RORB_RM_CL(rm) 0xD2, 0x8 | rm // ror rm, cl [Size: 0x1]
#define RCLB_RM_CL(rm) 0xD2, 0x10 | rm // rcl rm, cl [Size: 0x1]
#define RCRB_RM_CL(rm) 0xD2, 0x18 | rm // rcr rm, cl [Size: 0x1]
#define SHLB_RM_CL(rm) 0xD2, 0x20 | rm // shl rm, cl [Size: 0x1]
#define SHRB_RM_CL(rm) 0xD2, 0x28 | rm // shr rm, cl [Size: 0x1]
#define SALB_RM_CL(rm) 0xD2, 0x30 | rm // sal rm, cl [Size: 0x1]
#define SARB_RM_CL(rm) 0xD2, 0x38 | rm // sar rm, cl [Size: 0x1]

#define ROLD_RM_CL(rm) 0xD3, rm // rol rm, cl [Size: 0x1]
#define RORD_RM_CL(rm) 0xD3, 0x8 | rm // ror rm, cl [Size: 0x1]
#define RCLD_RM_CL(rm) 0xD3, 0x10 | rm // rcl rm, cl [Size: 0x1]
#define RCRD_RM_CL(rm) 0xD3, 0x18 | rm // rcr rm, cl [Size: 0x1]
#define SHLD_RM_CL(rm) 0xD3, 0x20 | rm // shl rm, cl [Size: 0x1]
#define SHRD_RM_CL(rm) 0xD3, 0x28 | rm // shr rm, cl [Size: 0x1]
#define SALD_RM_CL(rm) 0xD3, 0x30 | rm // sal rm, cl [Size: 0x1]
#define SARD_RM_CL(rm) 0xD3, 0x38 | rm // sar rm, cl [Size: 0x1]

#define LOOPNZ_RB(rb) 0xE0, BYTEPTR(rb) // loopnz rb [Size: 0x2]
#define LOOPNE_RB(rb) LOOPNZ_RB(rb) // loopne rb [Size: 0x2]

#define LOOPZ_RB(rb) 0xE1, BYTEPTR(rb) // loopz rb [Size: 0x2]
#define LOOPE_RB(rb) LOOPNZ_RB(rb) // loope rb [Size: 0x2]

#define LOOP_RB(rb) 0xE2, BYTEPTR(rb) // loop rb [Size: 0x2]

#define JECXZ_RB(rb) 0xE3, BYTEPTR(rb) // jecxz rb [Size: 0x2]

#define IN_AL_B(b) 0xE4, BYTEPTR(b) // in al, b [Size: 0x2]
#define IN_EAX_D(b) 0xE5, BYTEPTR(b) // in eax, b [Size: 0x2]

#define OUT_B_AL(b) 0xE6, BYTEPTR(b) // out b, al [Size: 0x2]
#define OUT_D_EAX(b) 0xE7, BYTEPTR(b) // out b, eax [Size: 0x2]

#define CALL_RW(rw) PFX_WORD, 0xE8, WORDPTR(rw) // call rw [Size: 0x4]
#define CALL_RD(rd) 0xE8, DWORDPTR(rd) // call rd [Size: 0x5]

#define JMP_RW(rw) PFX_WORD, 0xE9, WORDPTR(rw) // jmp rw [Size: 0x4]
#define JMP_RD(rd) 0xE9, DWORDPTR(rd) // jmp rd [Size: 0x4]

#define JMP_RB(rb) 0xEB, BYTEPTR(rb) // jmp rb [Size: 0x2]

#define IN_AL_DX 0xEC // in al, dx [Size: 0x1]
#define IN_EAX_DX 0xED // in eax, dx [Size: 0x1]

#define OUT_AL_DX 0xEE // out al, dx [Size: 0x1]
#define OUT_EAX_DX 0xEF // out eax, dx [Size: 0x1]

#define INT_1 0xF1 // int 1 [Size: 0x1]
#define ICEBP INT_1 // icebp [Size: 0x1]

#define HLT 0xF4 // hlt [Size: 0x1]

#define CMC 0xF5 // cmc [Size: 0x1]

#define TEST_RM_B(rm, b) 0xF6, rm, BYTEPTR(b) // test rm, b [Size: 0x2]
#define NOTB_RM(rm) 0xF6, 0x10 | rm // not rm [Size: 0x1]
#define NEGB_RM(rm) 0xF6, 0x18 | rm // neg rm [Size: 0x1]
#define MULB_RM(rm) 0xF6, 0x20 | rm // mul rm [Size: 0x1]
#define IMULB_RM(rm) 0xF6, 0x28 | rm // imul rm [Size: 0x1]
#define DIVB_RM(rm) 0xF6, 0x30 | rm // div rm [Size: 0x1]
#define IDIVB_RM(rm) 0xF6, 0x38 | rm // idiv rm [Size: 0x1]

#define TEST_RM_W(rm, w) PFX_WORD, 0xF7, rm, WORDPTR(w) // test rm, w [Size: 0x4]
#define TEST_RM_D(rm, d) 0xF7, rm, DWORDPTR(d) // test rm, d [Size: 0x5]
#define NOTD_RM(rm) 0xF7, 0x10 | rm // not rm [Size: 0x1]
#define NEGD_RM(rm) 0xF7, 0x18 | rm // neg rm [Size: 0x1]
#define MULD_RM(rm) 0xF7, 0x20 | rm // mul rm [Size: 0x1]
#define IMULD_RM(rm) 0xF7, 0x28 | rm // imul rm [Size: 0x1]
#define DIVD_RM(rm) 0xF7, 0x30 | rm // div rm [Size: 0x1]
#define IDIVD_RM(rm) 0xF7, 0x38 | rm // idiv rm [Size: 0x1]

#define CLC 0xF8 // clc [Size: 0x1]
#define STC 0xF9 // stc [Size: 0x1]
#define CLI 0xFA // cli [Size: 0x1]
#define STI 0xFB // sti [Size: 0x1]
#define CLD 0xFC // cld [Size: 0x1]
#define STD 0xFD // std [Size: 0x1]

#define INCB_RM(rm) 0xFE, rm // inc rm [Size: 0x1]
#define DECB_RM(rm) 0xFE, 0x8 | rm // dec rm [Size: 0x1]

#define INCD_RM(rm) 0xFF, rm // inc rm [Size: 0x1]
#define DECD_RM(rm) 0xFF, 0x8 | rm // dec rm [Size: 0x1]
#define CALLQ_RM(rm) 0xFF, 0x10 | rm // call rm [Size: 0x1]
#define CALLFQ_RM(rm) 0xFF, 0x18 | rm // callf rm [Size: 0x1]
#define JMPQ_RM(rm) 0xFF, 0x20 | rm // jmp rm [Size: 0x1]
#define JMPFQ_RM(rm) 0xFF, 0x28 | rm // jmpf rm [Size: 0x1]
#define PUSHQ_RM(rm) 0xFF, 0x30 | rm // push rm [Size: 0x1]

#else

#define ADDB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x00, rm_r) // add rm_r [Size: 0x1]
#define ADDD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x01, rm_r) // add rm_r [Size: 0x1]

#define ADDB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x02, r_rm) // add r_rm [Size: 0x1]
#define ADDD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x03, r_rm) // add r_rm [Size: 0x1]

#define ADD_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x04, BYTEPTR(b)) // add al, b [Size: 0x2]
#define ADD_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x05, WORDPTR(w)) // add al, w [Size: 0x4]
#define ADD_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x05, DWORDPTR(d)) // add eax, d [Size: 0x5]

#define ORB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x08, rm_r) // or rm_r [Size: 0x1]
#define ORD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x09, rm_r) // or rm_r [Size: 0x1]

#define ORB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x0A, r_rm) // or r_rm [Size: 0x1]
#define ORD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x0B, r_rm) // or r_rm [Size: 0x1]

#define OR_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x0C, BYTEPTR(b)) // or al, b [Size: 0x2]
#define OR_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x0D, WORDPTR(w)) // or al, w [Size: 0x4]
#define OR_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x0D, DWORDPTR(d)) // or eax, d [Size: 0x5]

#define ADCB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x10, rm_r) // adc rm_r [Size: 0x1]
#define ADCD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x11, rm_r) // adc rm_r [Size: 0x1]

#define ADCB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x12, r_rm) // adc r_rm [Size: 0x1]
#define ADCD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x13, r_rm) // adc r_rm [Size: 0x1]

#define ADC_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x14, BYTEPTR(b)) // adc al, b [Size: 0x2]
#define ADC_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x15, WORDPTR(w)) // adc al, w [Size: 0x4]
#define ADC_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x15, DWORDPTR(d)) // adc eax, d [Size: 0x5]

#define SBBB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x18, rm_r) // sbb rm_r [Size: 0x1]
#define SBBD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x19, rm_r) // sbb rm_r [Size: 0x1]

#define SBBB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x1A, r_rm) // sbb r_rm [Size: 0x1]
#define SBBD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x1B, r_rm) // sbb r_rm [Size: 0x1]

#define SBB_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x1C, BYTEPTR(b)) // sbb al, b [Size: 0x2]
#define SBB_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x1D, WORDPTR(w)) // sbb al, w [Size: 0x4]
#define SBB_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x1D, DWORDPTR(d)) // sbb eax, d [Size: 0x5]

#define ANDB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x20, rm_r) // and rm_r [Size: 0x1]
#define ANDD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x21, rm_r) // and rm_r [Size: 0x1]

#define ANDB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x22, r_rm) // and r_rm [Size: 0x1]
#define ANDD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x23, r_rm) // and r_rm [Size: 0x1]

#define AND_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x24, BYTEPTR(b)) // and al, b [Size: 0x2]
#define AND_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x25, WORDPTR(w)) // and al, w [Size: 0x4]
#define AND_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x25, DWORDPTR(d)) // and eax, d [Size: 0x5]

#define SUBB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x28, rm_r) // sub rm_r [Size: 0x1]
#define SUBD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x29, rm_r) // sub rm_r [Size: 0x1]

#define SUBB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x2A, r_rm) // sub r_rm [Size: 0x1]
#define SUBD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x2B, r_rm) // sub r_rm [Size: 0x1]

#define SUB_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x2C, BYTEPTR(b)) // sub al, b [Size: 0x2]
#define SUB_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x2D, WORDPTR(w)) // sub al, w [Size: 0x4]
#define SUB_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x2D, DWORDPTR(d)) // sub eax, d [Size: 0x5]

#define XORB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x30, rm_r) // xor rm_r [Size: 0x1]
#define XORD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x31, rm_r) // xor rm_r [Size: 0x1]

#define XORB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x32, r_rm) // xor r_rm [Size: 0x1]
#define XORD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x33, r_rm) // xor r_rm [Size: 0x1]

#define XOR_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x34, BYTEPTR(b)) // xor al, b [Size: 0x2]
#define XOR_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x35, WORDPTR(w)) // xor al, w [Size: 0x4]
#define XOR_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x35, DWORDPTR(d)) // xor eax, d [Size: 0x5]

#define CMPB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x38, rm_r) // cmp rm_r [Size: 0x1]
#define CMPD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x39, rm_r) // cmp rm_r [Size: 0x1]

#define CMPB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x3A, r_rm) // cmp r_rm [Size: 0x1]
#define CMPD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x3B, r_rm) // cmp r_rm [Size: 0x1]

#define CMP_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x3C, BYTEPTR(b)) // cmp al, b [Size: 0x2]
#define CMP_AX_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x3D, WORDPTR(w)) // cmp al, w [Size: 0x4]
#define CMP_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x3D, DWORDPTR(d)) // cmp eax, d [Size: 0x5]

#define PUSHQ_R(r0) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0x50 + (r0))) // push r0 [Size: 0x1]
#define POPQ_R(r0) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0x58 + (r0))) // push r0 [Size: 0x1]

#define MOVSXD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x63, r_rm) // movsxd r_rm [Size: 0x1]

#define PUSH_W(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x68, WORDPTR(w)) // push w [Size: 0x4]
#define PUSH_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x68, DWORDPTR(d)) // push d [Size: 0x5]

#define IMUL_R_RM_W(r_rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x69, r_rm, WORDPTR(w)) // imul r_rm, w [Size: 0x3]
#define IMUL_R_RM_D(r_rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x69, r_rm, DWORDPTR(d)) // imul r_rm, d [Size: 0x5]

#define PUSH_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x6A, BYTEPTR(b)) // push b [Size: 0x2]

#define IMUL_R_RM_B(r_rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x6B, r_rm, BYTEPTR(b)) // imul r_rm, b [Size: 0x2]

#define INSB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x6C) // ins [Size: 0x1]
#define INSD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x6D) // ins [Size: 0x1]

#define OUTB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x6E) // out [Size: 0x1]
#define OUTD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x6F) // out [Size: 0x1]

#define JO_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x70, BYTEPTR(rb)) // jo rb [Size: 0x2]

#define JNO_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x71, BYTEPTR(rb)) // jo rb [Size: 0x2]

#define JB_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x72, BYTEPTR(rb)) // jb rb [Size: 0x2]
#define JNAE_RB(rb) JB_RB(rb) // jnae rb [Size: 0x2]
#define JC_RB(rb) JB_RB(rb) // jc rb [Size: 0x2]

#define JNB_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x73, BYTEPTR(rb)) // jnb rb [Size: 0x2]
#define JAE_RB(rb) JNB_RB(rb) // jae rb [Size: 0x2]
#define JNC_RB(rb) JNB_RB(rb) // jnc rb [Size: 0x2]

#define JZ_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x74, BYTEPTR(rb)) // jz rb [Size: 0x2]
#define JE_RB(rb) JZ_RB(rb) // je rb [Size: 0x2]

#define JNZ_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x75, BYTEPTR(rb)) // jnz rb [Size: 0x2]
#define JNE_RB(rb) JNZ_RB(rb) // jne rb [Size: 0x2]

#define JBE_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x76, BYTEPTR(rb)) // jbe rb [Size: 0x2]
#define JNA_RB(rb) JBE_RB(rb) // jna rb [Size: 0x2]

#define JNBE_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x77, BYTEPTR(rb)) // jnbe rb [Size: 0x2]
#define JA_RB(rb) JNBE_RB(rb) // ja rb [Size: 0x2]

#define JS_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x78, BYTEPTR(rb)) // js rb [Size: 0x2]

#define JNS_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x79, BYTEPTR(rb)) // jns rb [Size: 0x2]

#define JP_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x7A, BYTEPTR(rb)) // jp rb [Size: 0x2]
#define JPE_RB(rb) JP_RB(rb) // jpe rb [Size: 0x2]

#define JNP_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x7B, BYTEPTR(rb)) // jnp rb [Size: 0x2]
#define JPO_RB(rb) JNP_RB(rb) // jpo rb [Size: 0x2]

#define JL_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x7C, BYTEPTR(rb)) // jl rb [Size: 0x2]
#define JNGE_RB(rb) JL_RB(rb) // jnge rb [Size: 0x2]

#define JNL_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x7D, BYTEPTR(rb)) // jnl rb [Size: 0x2]
#define JGE_RB(rb) JNL_RB(rb) // jge rb [Size: 0x2]

#define JLE_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x7E, BYTEPTR(rb)) // jle rb [Size: 0x2]
#define JNG_RB(rb) JLE_RB(rb) // jng rb [Size: 0x2]

#define JNLE_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x7F, BYTEPTR(rb)) // jnle rb [Size: 0x2]
#define JG_RB(rb) JNLE_RB(rb) // jg rb [Size: 0x2]

#define ADD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, rm, BYTEPTR(b)) // add rm, b [Size: 0x2]
#define OR_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, 0x8 | rm, BYTEPTR(b)) // or rm, b [Size: 0x2]
#define ADC_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, 0x10 | rm, BYTEPTR(b)) // adc rm, b [Size: 0x2]
#define SBB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, 0x18 | rm, BYTEPTR(b)) // sbb rm, b [Size: 0x2]
#define AND_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, 0x20 | rm, BYTEPTR(b)) // and rm, b [Size: 0x2]
#define SUB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, 0x28 | rm, BYTEPTR(b)) // sub rm, b [Size: 0x2]
#define XOR_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, 0x30 | rm, BYTEPTR(b)) // xor rm, b [Size: 0x2]
#define CMP_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, 0x38 | rm, BYTEPTR(b)) // cmp rm, b [Size: 0x2]

#define ADD_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, rm, WORDPTR(w)) // add rm, w [Size: 0x4]
#define OR_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x8 | rm, WORDPTR(w)) // or rm, w [Size: 0x4]
#define ADC_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x10 | rm, WORDPTR(w)) // adc rm, w [Size: 0x4]
#define SBB_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x18 | rm, WORDPTR(w)) // sbb rm, w [Size: 0x4]
#define AND_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x20 | rm, WORDPTR(w)) // and rm, w [Size: 0x4]
#define SUB_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x28 | rm, WORDPTR(w)) // sub rm, w [Size: 0x4]
#define XOR_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x30 | rm, WORDPTR(w)) // xor rm, w [Size: 0x4]
#define CMP_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x38 | rm, WORDPTR(w)) // cmp rm, w [Size: 0x4]

#define ADD_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, rm, DWORDPTR(d)) // add rm, d [Size: 0x5]
#define OR_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x8 | rm, DWORDPTR(d)) // or rm, d [Size: 0x5]
#define ADC_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x10 | rm, DWORDPTR(d)) // adc rm, d [Size: 0x5]
#define SBB_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x18 | rm, DWORDPTR(d)) // sbb rm, d [Size: 0x5]
#define AND_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x20 | rm, DWORDPTR(d)) // and rm, d [Size: 0x5]
#define SUB_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x28 | rm, DWORDPTR(d)) // sub rm, d [Size: 0x5]
#define XOR_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x30 | rm, DWORDPTR(d)) // xor rm, d [Size: 0x5]
#define CMP_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, 0x38 | rm, DWORDPTR(d)) // cmp rm, d [Size: 0x5]

#define ADDD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, rm, BYTEPTR(b)) // add rm, b [Size: 0x2]
#define ORD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, 0x8 | rm, BYTEPTR(b)) // or rm, b [Size: 0x2]
#define ADCD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, 0x10 | rm, BYTEPTR(b)) // adc rm, b [Size: 0x2]
#define SBBD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, 0x18 | rm, BYTEPTR(b)) // sbb rm, b [Size: 0x2]
#define ANDD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, 0x20 | rm, BYTEPTR(b)) // and rm, b [Size: 0x2]
#define SUBD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, 0x28 | rm, BYTEPTR(b)) // sub rm, b [Size: 0x2]
#define XORD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, 0x30 | rm, BYTEPTR(b)) // xor rm, b [Size: 0x2]
#define CMPD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, 0x38 | rm, BYTEPTR(b)) // cmp rm, b [Size: 0x2]

#define TESTB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x84, rm_r) // test rm_r [Size: 0x1]
#define TESTD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x85, rm_r) // test rm_r [Size: 0x1]

#define XCHGB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x86, r_rm) // xchg r_rm [Size: 0x1]
#define XCHGD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x87, r_rm) // xchg r_rm [Size: 0x1]

#define MOVB_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x88, rm_r) // mov rm_r [Size: 0x1]
#define MOVD_RM_R(rm_r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x89, rm_r) // mov rm_r [Size: 0x1]

#define MOVB_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8A, r_rm) // mov r_rm [Size: 0x1]
#define MOVD_R_RM(r_rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8B, r_rm) // mov r_rm [Size: 0x1]

#define MOVD_RM_S(rm_s) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8C, rm_s) // mov rm_s [Size: 0x1]

#define LEAD_R_M(r_m) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8D, r_m) // lea r_m [Size: 0x1]

#define MOVD_S_RM(rm_s) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8E, s_rm) // mov s_rm [Size: 0x1]

#define POPD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8F, rm) // pop rm [Size: 0x1]

#define NOP INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x90) // nop [Size: 0x1]

#define XCHGD_R_EAX(r) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0x90 + (r))) // xchg r, eax [Size: 0x1]

#define CWDE INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x98) // cwde [Size: 0x1]
#define CDQ INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x99) // cdq [Size: 0x1]

#define WAIT INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9B) // wait [Size: 0x1]

#define PUSHF INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9C) // pushf [Size: 0x1]
#define POPF INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9D) // popf [Size: 0x1]

#define SAHF INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9E) // sahf [Size: 0x1]
#define LAHF INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9F) // lahf [Size: 0x1]

#define MOV_AL_QM(qm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA0, QWORDPTR(qm)) // mov al, [qm] [Size: 0x9]
#define MOV_EAX_QM(qm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA1, QWORDPTR(qm)) // mov eax, [qm] [Size: 0x9]

#define MOV_QM_AL(qm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA2, QWORDPTR(qm)) // mov [qm], al [Size: 0x9]
#define MOV_QM_EAX(qm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA3, QWORDPTR(qm)) // mov [qm], eax [Size: 0x9]

#define MOVSB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA4) // movsb [Size: 0x1]
#define MOVSD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA5) // movsd [Size: 0x1]

#define CMPSB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA6) // cmpsb [Size: 0x1]
#define CMPSD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA7) // cmpsd [Size: 0x1]

#define TEST_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA8, BYTEPTR(b)) // test al, b [Size: 0x2]
#define TEST_AX_D(w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA9, WORDPTR(w)) // test ax, w [Size: 0x4]
#define TEST_EAX_D(d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xA9, DWORDPTR(d)) // test eax, d [Size: 0x5]

#define STOSB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xAA) // stosb [Size: 0x1]
#define STOSD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xAB) // stosd [Size: 0x1]

#define LODSB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xAC) // lodsb [Size: 0x1]
#define LODSD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xAD) // lodsd [Size: 0x1]

#define SCASB INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xAE) // scasb [Size: 0x1]
#define SCASW INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xAF) // scasd [Size: 0x1]

#define MOV_R_B(r, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0xB0 + (r)), BYTEPTR(b)) // mov r, b [Size: 0x2]
#define MOV_R_W(r, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0xB8 + (r)), WORDPTR(w)) // mov r, w [Size: 0x4]
#define MOV_R_D(r, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0xB8 + (r)), DWORDPTR(d)) // mov r, d [Size: 0x5]
#define MOV_R_Q(r, q) PFX_REXW, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0xB8 + (r)), QWORDPTR(q)) // mov r, q [Size: 0xA]
#define MOV_ER_Q(r, q) PFX_REXWB, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, (0xB8 + (r)), QWORDPTR(q)) // mov r, q [Size: 0xA]

#define ROLB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, rm, BYTEPTR(b)) // rol rm, b [Size: 0x2]
#define RORB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, 0x8 | rm, BYTEPTR(b)) // ror rm, b [Size: 0x2]
#define RCLB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, 0x10 | rm, BYTEPTR(b)) // rcl rm, b [Size: 0x2]
#define RCRB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, 0x18 | rm, BYTEPTR(b)) // rcr rm, b [Size: 0x2]
#define SHLB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, 0x20 | rm, BYTEPTR(b)) // shl rm, b [Size: 0x2]
#define SHRB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, 0x28 | rm, BYTEPTR(b)) // shr rm, b [Size: 0x2]
#define SALB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, 0x30 | rm, BYTEPTR(b)) // sal rm, b [Size: 0x2]
#define SARB_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC0, 0x38 | rm, BYTEPTR(b)) // sar rm, b [Size: 0x2]

#define ROLD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, rm, BYTEPTR(b)) // rol rm, b [Size: 0x2]
#define RORD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, 0x8 | rm, BYTEPTR(b)) // ror rm, b [Size: 0x2]
#define RCLD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, 0x10 | rm, BYTEPTR(b)) // rcl rm, b [Size: 0x2]
#define RCRD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, 0x18 | rm, BYTEPTR(b)) // rcr rm, b [Size: 0x2]
#define SHLD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, 0x20 | rm, BYTEPTR(b)) // shl rm, b [Size: 0x2]
#define SHRD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, 0x28 | rm, BYTEPTR(b)) // shr rm, b [Size: 0x2]
#define SALD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, 0x30 | rm, BYTEPTR(b)) // sal rm, b [Size: 0x2]
#define SARD_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC1, 0x38 | rm, BYTEPTR(b)) // sar rm, b [Size: 0x2]

#define RETN_W(w) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC2, WORDPTR(w)) // ret w [Size: 0x3]
#define RETN INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC3) // ret [Size: 0x1]

#define MOV_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC6, rm, BYTEPTR(b)) // mov rm, b [Size: 0x2]
#define MOV_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC7, rm, WORDPTR(w)) // mov rm, w [Size: 0x4]
#define MOV_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC7, rm, DWORDPTR(d)) // mov rm, d [Size: 0x5]

#define ENTER(w, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC8, WORDPTR(w), BYTEPTR(b)) // enter w, b [Size: 0x4]
#define LEAVE INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xC9) // leave [Size: 0x1]

#define RETF(w) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xCA, WORDPTR(w)) // ret w [Size: 0x3]
#define RETF INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xCB) // ret [Size: 0x1]

#define INT_3 INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xCC) // int 3 [Size: 0x1]
#define INT_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xCD, BYTEPTR(b)) // int b [Size: 0x2]

#define INTO INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xCE) // into [Size: 0x1]

#define IRETD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xCF) // iretd [Size: 0x1]

#define ROLB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, rm) // rol rm, 1 [Size: 0x1]
#define RORB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, 0x8 | rm) // ror rm, 1 [Size: 0x1]
#define RCLB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, 0x10 | rm) // rcl rm, 1 [Size: 0x1]
#define RCRB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, 0x18 | rm) // rcr rm, 1 [Size: 0x1]
#define SHLB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, 0x20 | rm) // shl rm, 1 [Size: 0x1]
#define SHRB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, 0x28 | rm) // shr rm, 1 [Size: 0x1]
#define SALB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, 0x30 | rm) // sal rm, 1 [Size: 0x1]
#define SARB_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD0, 0x38 | rm) // sar rm, 1 [Size: 0x1]

#define ROLD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, rm) // rol rm, 1 [Size: 0x1]
#define RORD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, 0x8 | rm) // ror rm, 1 [Size: 0x1]
#define RCLD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, 0x10 | rm) // rcl rm, 1 [Size: 0x1]
#define RCRD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, 0x18 | rm) // rcr rm, 1 [Size: 0x1]
#define SHLD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, 0x20 | rm) // shl rm, 1 [Size: 0x1]
#define SHRD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, 0x28 | rm) // shr rm, 1 [Size: 0x1]
#define SALD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, 0x30 | rm) // sal rm, 1 [Size: 0x1]
#define SARD_RM_1(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD1, 0x38 | rm) // sar rm, 1 [Size: 0x1]

#define ROLB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, rm) // rol rm, cl [Size: 0x1]
#define RORB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, 0x8 | rm) // ror rm, cl [Size: 0x1]
#define RCLB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, 0x10 | rm) // rcl rm, cl [Size: 0x1]
#define RCRB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, 0x18 | rm) // rcr rm, cl [Size: 0x1]
#define SHLB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, 0x20 | rm) // shl rm, cl [Size: 0x1]
#define SHRB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, 0x28 | rm) // shr rm, cl [Size: 0x1]
#define SALB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, 0x30 | rm) // sal rm, cl [Size: 0x1]
#define SARB_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD2, 0x38 | rm) // sar rm, cl [Size: 0x1]

#define ROLD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, rm) // rol rm, cl [Size: 0x1]
#define RORD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, 0x8 | rm) // ror rm, cl [Size: 0x1]
#define RCLD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, 0x10 | rm) // rcl rm, cl [Size: 0x1]
#define RCRD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, 0x18 | rm) // rcr rm, cl [Size: 0x1]
#define SHLD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, 0x20 | rm) // shl rm, cl [Size: 0x1]
#define SHRD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, 0x28 | rm) // shr rm, cl [Size: 0x1]
#define SALD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, 0x30 | rm) // sal rm, cl [Size: 0x1]
#define SARD_RM_CL(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xD3, 0x38 | rm) // sar rm, cl [Size: 0x1]

#define LOOPNZ_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE0, BYTEPTR(rb)) // loopnz rb [Size: 0x2]
#define LOOPNE_RB(rb) LOOPNZ_RB(rb) // loopne rb [Size: 0x2]

#define LOOPZ_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE1, BYTEPTR(rb)) // loopz rb [Size: 0x2]
#define LOOPE_RB(rb) LOOPNZ_RB(rb) // loope rb [Size: 0x2]

#define LOOP_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE2, BYTEPTR(rb)) // loop rb [Size: 0x2]

#define JECXZ_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE3, BYTEPTR(rb)) // jecxz rb [Size: 0x2]

#define IN_AL_B(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE4, BYTEPTR(b)) // in al, b [Size: 0x2]
#define IN_EAX_D(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE5, BYTEPTR(b)) // in eax, b [Size: 0x2]

#define OUT_B_AL(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE6, BYTEPTR(b)) // out b, al [Size: 0x2]
#define OUT_D_EAX(b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE7, BYTEPTR(b)) // out b, eax [Size: 0x2]

#define CALL_RW(rw) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE8, WORDPTR(rw)) // call rw [Size: 0x4]
#define CALL_RD(rd) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE8, DWORDPTR(rd)) // call rd [Size: 0x5]

#define JMP_RW(rw) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE9, WORDPTR(rw)) // jmp rw [Size: 0x4]
#define JMP_RD(rd) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xE9, DWORDPTR(rd)) // jmp rd [Size: 0x5]

#define JMP_RB(rb) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xEB, BYTEPTR(rb)) // jmp rb [Size: 0x2]

#define IN_AL_DX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xEC) // in al, dx [Size: 0x1]
#define IN_EAX_DX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xED) // in eax, dx [Size: 0x1]

#define OUT_AL_DX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xEE) // out al, dx [Size: 0x1]
#define OUT_EAX_DX INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xEF) // out eax, dx [Size: 0x1]

#define INT_1 INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF1) // int 1 [Size: 0x1]
#define ICEBP INT_1 // icebp [Size: 0x1]

#define HLT INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF4) // hlt [Size: 0x1]

#define CMC INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF5) // cmc [Size: 0x1]

#define TEST_RM_B(rm, b) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF6, rm, BYTEPTR(b)) // test rm, b [Size: 0x2]
#define NOTB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF6, 0x10 | rm) // not rm [Size: 0x1]
#define NEGB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF6, 0x18 | rm) // neg rm [Size: 0x1]
#define MULB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF6, 0x20 | rm) // mul rm [Size: 0x1]
#define IMULB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF6, 0x28 | rm) // imul rm [Size: 0x1]
#define DIVB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF6, 0x30 | rm) // div rm [Size: 0x1]
#define IDIVB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF6, 0x38 | rm) // idiv rm [Size: 0x1]

#define TEST_RM_W(rm, w) PFX_WORD, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, rm, WORDPTR(w)) // test rm, w [Size: 0x4]
#define TEST_RM_D(rm, d) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, rm, DWORDPTR(d)) // test rm, d [Size: 0x5]
#define NOTD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, 0x10 | rm) // not rm [Size: 0x1]
#define NEGD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, 0x18 | rm) // neg rm [Size: 0x1]
#define MULD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, 0x20 | rm) // mul rm [Size: 0x1]
#define IMULD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, 0x28 | rm) // imul rm [Size: 0x1]
#define DIVD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, 0x30 | rm) // div rm [Size: 0x1]
#define IDIVD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF7, 0x38 | rm) // idiv rm [Size: 0x1]

#define CLC INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF8) // clc [Size: 0x1]
#define STC INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xF9) // stc [Size: 0x1]
#define CLI INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFA) // cli [Size: 0x1]
#define STI INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFB) // sti [Size: 0x1]
#define CLD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFC) // cld [Size: 0x1]
#define STD INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFD) // std [Size: 0x1]

#define INCB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFE, rm) // inc rm [Size: 0x1]
#define DECB_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFE, 0x8 | rm) // dec rm [Size: 0x1]

#define INCD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFF, rm) // inc rm [Size: 0x1]
#define DECD_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFF, 0x8 | rm) // dec rm [Size: 0x1]
#define CALLQ_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFF, 0x10 | rm) // call rm [Size: 0x1]
#define CALLFQ_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFF, 0x18 | rm) // callf rm [Size: 0x1]
#define JMPQ_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFF, 0x20 | rm) // jmp rm [Size: 0x1]
#define JMPFQ_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFF, 0x28 | rm) // jmpf rm [Size: 0x1]
#define PUSHQ_RM(rm) INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xFF, 0x30 | rm) // push rm [Size: 0x1]

#endif
#pragma endregion

#pragma region SECOND_INSTRUCTION_BATCH
#ifndef SHELL_RELATIVITY

#define MOVUPS_X_XM(x_xm) PFX_0F, 0x10, x_xm // movups x_xm [Size: 0x2]
#define MOVSS_X_XM(x_xm) PFX_REPE, PFX_0F, 0x10, x_xm // movss x_xm [Size: 0x3]
#define MOVUPD_X_XM(x_xm) PFX_WORD, PFX_0F, 0x10, x_xm // movupd x_xm [Size: 0x3]
#define MOVSD_X_XM(x_xm) PFX_REPNE, PFX_0F, 0x10, x_xm // movsd x_xm [Size: 0x3]

#define MOVUPS_XM_X(xm_x) PFX_0F, 0x11, xm_x // movups xm_x [Size: 0x2]
#define MOVSS_XM_X(xm_x) PFX_REPE, PFX_0F, 0x11, xm_x // movss xm_x [Size: 0x3]
#define MOVUPD_XM_X(xm_x) PFX_WORD, PFX_0F, 0x11, xm_x // movupd xm_x [Size: 0x3]
#define MOVSD_XM_X(xm_x) PFX_REPNE, PFX_0F, 0x11, xm_x // movsd xm_x [Size: 0x3]

#define MOVLPS_X_XM(x_xm) PFX_0F, 0x12, x_xm // movlps x_xm [Size: 0x2]
#define MOVLPD_X_M(x_m) PFX_WORD, PFX_0F, 0x12, x_m // movlpd x_m [Size: 0x3]
#define MOVDDUP_X_XM(x_xm) PFX_REPNE, PFX_0F, 0x12, x_xm // movddup x_xm [Size: 0x3]
#define MOVSLDUP_X_XM(x_xm) PFX_REPE, PFX_0F, 0x12, x_xm // movsldup x_xm [Size: 0x3]

#define MOVLPS_M_X(m_x) PFX_0F, 0x13, m_x // movlps m_x [Size: 0x2]
#define MOVLPD_M_X(m_x) PFX_WORD, PFX_0F, 0x13, m_x // movlpd m_x [Size: 0x3]

#define MOVQ_R_C(r_c) PFX_0F, 0x20, r_c // mov r_c [Size: 0x2]
#define MOVQ_R_D(r_d) PFX_0F, 0x21, r_d // mov r_d [Size: 0x2]

#define MOVQ_C_R(c_r) PFX_0F, 0x22, c_r // mov c_r [Size: 0x2]
#define MOVQ_D_R(d_r) PFX_0F, 0x23, d_r // mov d_r [Size: 0x2]

#define JO_RW(rw) PFX_WORD, PFX_0F, 0x80, WORDPTR(rw) // jo rw [Size: 0x5]
#define JO_RD(rd) PFX_0F, 0x80, DWORDPTR(rd) // jo rd [Size: 0x6]

#define JNO_RW(rw) PFX_WORD, PFX_0F, 0x81, WORDPTR(rw) // jno rw [Size: 0x5]
#define JNO_RD(rd) PFX_0F, 0x81, DWORDPTR(rd) // jno rd [Size: 0x6]

#define JB_RW(rw) PFX_WORD, PFX_0F, 0x82, WORDPTR(rw) // jb rw [Size: 0x5]
#define JB_RD(rd) PFX_0F, 0x82, DWORDPTR(rd) // jb rd [Size: 0x6]

#define JNAE_RW(rw) JB_RW(rw) // jnae rw [Size: 0x5]
#define JNAE_RD(rd) JB_RD(rd) // jnae rd [Size: 0x6]

#define JC_RW(rw) JB_RW(rw) // jc rw [Size: 0x5]
#define JC_RD(rd) JB_RD(rd) // jc rd [Size: 0x6]

#define JNB_RW(rw) PFX_WORD, PFX_0F, 0x83, WORDPTR(rw) // jnb rw [Size: 0x5]
#define JNB_RD(rd) PFX_0F, 0x83, DWORDPTR(rd) // jnb rd [Size: 0x6]

#define JAE_RW(rw) JNB_RW(rw) // jae rw [Size: 0x5]
#define JAE_RD(rd) JNB_RD(rd) // jae rd [Size: 0x6]

#define JNC_RW(rw) JNB_RW(rw) // jnc rw [Size: 0x5]
#define JNC_RD(rd) JNB_RD(rd) // jnc rd [Size: 0x6]

#define JZ_RW(rw) PFX_WORD, PFX_0F, 0x84, WORDPTR(rw) // jz rw [Size: 0x5]
#define JZ_RD(rd) PFX_0F, 0x84, DWORDPTR(rd) // jz rd [Size: 0x6]

#define JE_RW(rw) JZ_RW(rw) // je rw [Size: 0x5]
#define JE_RD(rd) JZ_RD(rd) // je rd [Size: 0x6]

#define JNZ_RW(rw) PFX_WORD, PFX_0F, 0x85, WORDPTR(rw) // jnz rw [Size: 0x5]
#define JNZ_RD(rd) PFX_0F, 0x85, DWORDPTR(rd) // jnz rd [Size: 0x6]

#define JNE_RW(rw) JNZ_RW(rw) // jne rw [Size: 0x5]
#define JNE_RD(rd) JNZ_RD(rd) // jne rd [Size: 0x6]

#define JZ_RW(rw) PFX_WORD, PFX_0F, 0x84, WORDPTR(rw) // jz rw [Size: 0x5]
#define JZ_RD(rd) PFX_0F, 0x84, DWORDPTR(rd) // jz rd [Size: 0x6]

#define JE_RW(rw) JZ_RW(rw) // je rw [Size: 0x5]
#define JE_RD(rd) JZ_RD(rd) // je rd [Size: 0x6]

#define JNZ_RW(rw) PFX_WORD, PFX_0F, 0x85, WORDPTR(rw) // jnz rw [Size: 0x5]
#define JNZ_RD(rd) PFX_0F, 0x85, DWORDPTR(rd) // jnz rd [Size: 0x6]

#define JNE_RW(rw) JNZ_RW(rw) // jne rw [Size: 0x5]
#define JNE_RD(rd) JNZ_RD(rd) // jne rd [Size: 0x6]

#define JBE_RW(rw) PFX_WORD, PFX_0F, 0x86, WORDPTR(rw) // jbe rw [Size: 0x5]
#define JBE_RD(rd) PFX_0F, 0x86, DWORDPTR(rd) // jbe rd [Size: 0x6]

#define JNA_RW(rw) JBE_RW(rw) // jna rw [Size: 0x5]
#define JNA_RD(rd) JBE_RD(rd) // jna rd [Size: 0x6]

#define JNBE_RW(rw) PFX_WORD, PFX_0F, 0x87, WORDPTR(rw) // jnbe rw [Size: 0x5]
#define JNBE_RD(rd) PFX_0F, 0x87, DWORDPTR(rd) // jnbe rd [Size: 0x6]

#define JA_RW(rw) JNBE_RW(rw) // ja rw [Size: 0x5]
#define JA_RD(rd) JNBE_RD(rd) // ja rd [Size: 0x6]

#define JS_RW(rw) PFX_WORD, PFX_0F, 0x88, WORDPTR(rw) // js rw [Size: 0x5]
#define JS_RD(rd) PFX_0F, 0x88, DWORDPTR(rd) // js rd [Size: 0x6]

#define JNS_RW(rw) PFX_WORD, PFX_0F, 0x89, WORDPTR(rw) // jns rw [Size: 0x5]
#define JNS_RD(rd) PFX_0F, 0x89, DWORDPTR(rd) // jns rd [Size: 0x6]

#define JP_RW(rw) PFX_WORD, PFX_0F, 0x8A, WORDPTR(rw) // jp rw [Size: 0x5]
#define JP_RD(rd) PFX_0F, 0x8A, DWORDPTR(rd) // jp rd [Size: 0x6]

#define JPE_RW(rw) JP_RW(rw) // jpe rw [Size: 0x5]
#define JPE_RD(rd) JP_RD(rd) // jpe rd [Size: 0x6]

#define JNP_RW(rw) PFX_WORD, PFX_0F, 0x8B, WORDPTR(rw) // jnp rw [Size: 0x5]
#define JNP_RD(rd) PFX_0F, 0x8B, DWORDPTR(rd) // jnp rd [Size: 0x6]

#define JPO_RW(rw) JNP_RW(rw) // jpo rw [Size: 0x5]
#define JPO_RD(rd) JNP_RD(rd) // jpo rd [Size: 0x6]

#define JL_RW(rw) PFX_WORD, PFX_0F, 0x8C, WORDPTR(rw) // jl rw [Size: 0x5]
#define JL_RD(rd) PFX_0F, 0x8C, DWORDPTR(rd) // jl rd [Size: 0x6]

#define JNGE_RW(rw) JL_RW(rw) // jnge rw [Size: 0x5]
#define JNGE_RD(rd) JL_RD(rd) // jnge rd [Size: 0x6]

#define JNL_RW(rw) PFX_WORD, PFX_0F, 0x8D, WORDPTR(rw) // jnl rw [Size: 0x5]
#define JNL_RD(rd) PFX_0F, 0x8D, DWORDPTR(rd) // jnl rd [Size: 0x6]

#define JGE_RW(rw) JNL_RW(rw) // jge rw [Size: 0x5]
#define JGE_RD(rd) JNL_RD(rd) // jge rd [Size: 0x6]

#define JLE_RW(rw) PFX_WORD, PFX_0F, 0x8E, WORDPTR(rw) // jle rw [Size: 0x5]
#define JLE_RD(rd) PFX_0F, 0x8E, DWORDPTR(rd) // jle rd [Size: 0x6]

#define JNG_RW(rw) JLE_RW(rw) // jng rw [Size: 0x5]
#define JNG_RD(rd) JLE_RD(rd) // jng rd [Size: 0x6]

#define JNLE_RW(rw) PFX_WORD, PFX_0F, 0x8F, WORDPTR(rw) // jnle rw [Size: 0x5]
#define JNLE_RD(rd) PFX_0F, 0x8F, DWORDPTR(rd) // jnle rd [Size: 0x6]

#define JG_RW(rw) JNLE_RW(rw) // jg rw [Size: 0x5]
#define JG_RD(rd) JNLE_RD(rd) // jg rd [Size: 0x6]

#define SETO_RM(rm) PFX_0F, 0x90, rm // seto rm [Size: 0x2]

#define SETNO_RM(rm) PFX_0F, 0x91, rm // setno rm [Size: 0x2]

#define SETB_RM(rm) PFX_0F, 0x92, rm // seto rm [Size: 0x2]
#define SETNAE_RM(rm) SETB_RM(rm) // setnae rm [Size: 0x2]
#define SETC_RM(rm) SETB_RM(rm) // setc rm [Size: 0x2]

#define SETNB_RM(rm) PFX_0F, 0x93, rm // setnb [Size: 0x2]
#define SETAE_RM(rm) SETNB_RM(rm) // setae [Size: 0x2]
#define SETNC_RM(rm) SETNB_RM(rm) // setnc [Size: 0x2]

#define SETZ_RM(rm) PFX_0F, 0x94, rm // setz [Size: 0x2]
#define SETE_RM(rm) SETZ_RM(rm) // sete [Size: 0x2]

#define SETNZ_RM(rm) PFX_0F, 0x95, rm // setnz [Size: 0x2]
#define SETNE_RM(rm) SETNZ_RM(rm) // setne [Size: 0x2]

#define SETBE_RM(rm) PFX_0F, 0x96, rm // setbe [Size: 0x2]
#define SETNA_RM(rm) SETBE_RM(rm) // setna [Size: 0x2]

#define SETNBE_RM(rm) PFX_0F, 0x97, rm // setnbe [Size: 0x2]
#define SETA_RM(rm) SETNBE_RM(rm) // seta [Size: 0x2]

#define SETS_RM(rm) PFX_0F, 0x98, rm // sets [Size: 0x2]

#define SETNS_RM(rm) PFX_0F, 0x99, rm // setns [Size: 0x2]

#define SETP_RM(rm) PFX_0F, 0x9A, rm // setp [Size: 0x2]
#define SETPE_RM(rm) SETP_RM(rm) // setpe [Size: 0x2]

#define SETNP_RM(rm) PFX_0F, 0x9B, rm // setnp [Size: 0x2]
#define SETPO_RM(rm) SETNP_RM(rm) // setpo [Size: 0x2]

#define SETL_RM(rm) PFX_0F, 0x9C, rm // setl [Size: 0x2]
#define SETNGE_RM(rm) SETL_RM(rm) // setnge [Size: 0x2]

#define SETNL_RM(rm) PFX_0F, 0x9D, rm // setnl [Size: 0x2]
#define SETGE_RM(rm) SETNL_RM(rm) // setge [Size: 0x2]

#define SETLE_RM(rm) PFX_0F, 0x9E, rm // setle [Size: 0x2]
#define SETNG_RM(rm) SETLE_RM(rm) // setng [Size: 0x2]

#define SETNLE_RM(rm) PFX_0F, 0x9F, rm // setnle [Size: 0x2]
#define SETG_RM(rm) SETNLE_RM(rm) // setg [Size: 0x2]

#define CMPXCHGB_RM_R(rm_r) PFX_0F, 0xB0, rm_r // cmpxchg rm_r [Size: 0x2]
#define CMPXCHGD_RM_R(rm_r) PFX_0F, 0xB1, rm_r // cmpxchg rm_r [Size: 0x2]

#define BT_RM_B(rm, b) PFX_0F, 0xBA, 0x20 | rm // bt rm, b [Size: 0x2]
#define BTS_RM_B(rm, b) PFX_0F, 0xBA, 0x28 | rm // bts rm, b [Size: 0x2]
#define BTR_RM_B(rm, b) PFX_0F, 0xBA, 0x30 | rm // btr rm, b [Size: 0x2]
#define BTC_RM_B(rm, b) PFX_0F, 0xBA, 0x38 | rm // btc rm, b [Size: 0x2]

#define BTCD_RM_R(rm_r) PFX_0F, 0xBB, rm_r // btc rm_r [Size: 0x2]

#else

#define MOVUPS_X_XM(x_xm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x10, x_xm) // movups x_xm [Size: 0x2]
#define MOVSS_X_XM(x_xm) PFX_REPE, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x10, x_xm) // movss x_xm [Size: 0x3]
#define MOVUPD_X_XM(x_xm) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x10, x_xm) // movupd x_xm [Size: 0x3]
#define MOVSD_X_XM(x_xm) PFX_REPNE, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x10, x_xm) // movsd x_xm [Size: 0x3]

#define MOVUPS_XM_X(xm_x) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x11, xm_x) // movups xm_x [Size: 0x2]
#define MOVSS_XM_X(xm_x) PFX_REPE, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x11, xm_x) // movss xm_x [Size: 0x3]
#define MOVUPD_XM_X(xm_x) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x11, xm_x) // movupd xm_x [Size: 0x3]
#define MOVSD_XM_X(xm_x) PFX_REPNE, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x11, xm_x) // movsd xm_x [Size: 0x3]

#define MOVLPS_X_XM(x_xm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x12, x_xm) // movlps x_xm [Size: 0x2]
#define MOVLPD_X_M(x_m) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x12, x_m) // movlpd x_m [Size: 0x3]
#define MOVDDUP_X_XM(x_xm) PFX_REPNE, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x12, x_xm) // movddup x_xm [Size: 0x3]
#define MOVSLDUP_X_XM(x_xm) PFX_REPE, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x12, x_xm) // movsldup x_xm [Size: 0x3]

#define MOVLPS_M_X(m_x) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x13, m_x) // movlps m_x [Size: 0x2]
#define MOVLPD_M_X(m_x) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x13, m_x) // movlpd m_x [Size: 0x3]

#define MOVQ_R_C(r_c) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x20, r_c) // mov r_c [Size: 0x2]
#define MOVQ_R_D(r_d) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x21, r_d) // mov r_d [Size: 0x2]

#define MOVQ_C_R(c_r) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x22, c_r) // mov c_r [Size: 0x2]
#define MOVQ_D_R(d_r) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x23, d_r) // mov d_r [Size: 0x2]

#define CMOVO_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x40, r_rm) // cmovo r_rm [Size: 0x2]

#define CMOVNO_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x41, r_rm) // cmovno r_rm [Size: 0x2]

#define CMOVB_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x42, r_rm) // cmovb r_rm [Size: 0x2]
#define CMOVNAE_R_RM(r_rm) CMOVB_R_RM(r_rm) // cmovnae r_rm [Size: 0x2]
#define CMOVC_R_RM(r_rm) CMOVB_R_RM(r_rm) // cmovc r_rm [Size: 0x2]

#define CMOVNB_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x43, r_rm) // cmovnb r_rm [Size: 0x2]
#define CMOVAE_R_RM(r_rm) CMOVNB_R_RM(r_rm) // cmovae r_rm [Size: 0x2]
#define CMOVNC_R_RM(r_rm) CMOVNB_R_RM(r_rm) // cmovnc r_rm [Size: 0x2]

#define CMOVZ_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x44, r_rm) // cmovz r_rm [Size: 0x2]
#define CMOVE_R_RM(r_rm) CMOVZ_R_RM(r_rm) // cmove r_rm [Size: 0x2]

#define CMOVNZ_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x45, r_rm) // cmovnz r_rm [Size: 0x2]
#define CMOVNE_R_RM(r_rm) CMOVZ_R_RM(r_rm) // cmovne r_rm [Size: 0x2]

#define CMOVBE_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x46, r_rm) // cmovna r_rm [Size: 0x2]
#define CMOVNA_R_RM(r_rm) CMOVBE_R_RM(r_rm) // cmovbe r_rm [Size: 0x2]

#define CMOVNBE_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x47, r_rm) // cmovnbe r_rm [Size: 0x2]
#define CMOVA_R_RM(r_rm) CMOVBE_R_RM(r_rm) // cmova r_rm [Size: 0x2]

#define CMOVS_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x48, r_rm) // cmovs r_rm [Size: 0x2]

#define CMOVNS_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x49, r_rm) // cmovns r_rm [Size: 0x2]

#define CMOVP_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4A, r_rm) // cmovp r_rm [Size: 0x2]
#define CMOVPE_R_RM(r_rm) CMOVP_R_RM(r_rm) // cmovpe r_rm [Size: 0x2]

#define CMOVNP_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4B, r_rm) // cmovnp r_rm [Size: 0x2]
#define CMOVPO_R_RM(r_rm) CMOVNP_R_RM(r_rm) // cmovpo r_rm [Size: 0x2]

#define CMOVL_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4C, r_rm) // cmovl r_rm [Size: 0x2]
#define CMOVNGE_R_RM(r_rm) CMOVL_R_RM(r_rm) // cmovnge r_rm [Size: 0x2]

#define CMOVNL_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4D, r_rm) // cmovnl r_rm [Size: 0x2]
#define CMOVGE_R_RM(r_rm) CMOVNL_R_RM(r_rm) // cmovge r_rm [Size: 0x2]

#define CMOVLE_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4E, r_rm) // cmovle r_rm [Size: 0x2]
#define CMOVNG_R_RM(r_rm) CMOVLE_R_RM(r_rm) // cmovng r_rm [Size: 0x2]

#define CMOVNLE_R_RM(r_rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x4F, r_rm) // cmovnle r_rm [Size: 0x2]
#define CMOVG_R_RM(r_rm) CMOVNLE_R_RM(r_rm) // cmovg r_rm [Size: 0x2]

#define JO_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, WORDPTR(rw)) // jo rw [Size: 0x5]
#define JO_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x80, DWORDPTR(rd)) // jo rd [Size: 0x6]

#define JNO_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, WORDPTR(rw)) // jno rw [Size: 0x5]
#define JNO_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x81, DWORDPTR(rd)) // jno rd [Size: 0x6]

#define JB_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x82, WORDPTR(rw)) // jb rw [Size: 0x5]
#define JB_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x82, DWORDPTR(rd)) // jb rd [Size: 0x6]

#define JNAE_RW(rw) JB_RW(rw) // jnae rw [Size: 0x5]
#define JNAE_RD(rd) JB_RD(rd) // jnae rd [Size: 0x6]

#define JC_RW(rw) JB_RW(rw) // jc rw [Size: 0x5]
#define JC_RD(rd) JB_RD(rd) // jc rd [Size: 0x6]

#define JNB_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, WORDPTR(rw)) // jnb rw [Size: 0x5]
#define JNB_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x83, DWORDPTR(rd)) // jnb rd [Size: 0x6]

#define JAE_RW(rw) JNB_RW(rw) // jae rw [Size: 0x5]
#define JAE_RD(rd) JNB_RD(rd) // jae rd [Size: 0x6]

#define JNC_RW(rw) JNB_RW(rw) // jnc rw [Size: 0x5]
#define JNC_RD(rd) JNB_RD(rd) // jnc rd [Size: 0x6]

#define JZ_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x84, WORDPTR(rw)) // jz rw [Size: 0x5]
#define JZ_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x84, DWORDPTR(rd)) // jz rd [Size: 0x6]

#define JE_RW(rw) JZ_RW(rw) // je rw [Size: 0x5]
#define JE_RD(rd) JZ_RD(rd) // je rd [Size: 0x6]

#define JNZ_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x85, WORDPTR(rw)) // jnz rw [Size: 0x5]
#define JNZ_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x85, DWORDPTR(rd)) // jnz rd [Size: 0x6]

#define JNE_RW(rw) JNZ_RW(rw) // jne rw [Size: 0x5]
#define JNE_RD(rd) JNZ_RD(rd) // jne rd [Size: 0x6]

#define JZ_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x84, WORDPTR(rw)) // jz rw [Size: 0x5]
#define JZ_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x84, DWORDPTR(rd)) // jz rd [Size: 0x6]

#define JE_RW(rw) JZ_RW(rw) // je rw [Size: 0x5]
#define JE_RD(rd) JZ_RD(rd) // je rd [Size: 0x6]

#define JNZ_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x85, WORDPTR(rw)) // jnz rw [Size: 0x5]
#define JNZ_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x85, DWORDPTR(rd)) // jnz rd [Size: 0x6]

#define JNE_RW(rw) JNZ_RW(rw) // jne rw [Size: 0x5]
#define JNE_RD(rd) JNZ_RD(rd) // jne rd [Size: 0x6]

#define JBE_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x86, WORDPTR(rw)) // jbe rw [Size: 0x5]
#define JBE_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x86, DWORDPTR(rd)) // jbe rd [Size: 0x6]

#define JNA_RW(rw) JBE_RW(rw) // jna rw [Size: 0x5]
#define JNA_RD(rd) JBE_RD(rd) // jna rd [Size: 0x6]

#define JNBE_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x87, WORDPTR(rw)) // jnbe rw [Size: 0x5]
#define JNBE_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x87, DWORDPTR(rd)) // jnbe rd [Size: 0x6]

#define JA_RW(rw) JNBE_RW(rw) // ja rw [Size: 0x5]
#define JA_RD(rd) JNBE_RD(rd) // ja rd [Size: 0x6]

#define JS_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x88, WORDPTR(rw)) // js rw [Size: 0x5]
#define JS_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x88, DWORDPTR(rd)) // js rd [Size: 0x6]

#define JNS_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x89, WORDPTR(rw)) // jns rw [Size: 0x5]
#define JNS_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x89, DWORDPTR(rd)) // jns rd [Size: 0x6]

#define JP_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8A, WORDPTR(rw)) // jp rw [Size: 0x5]
#define JP_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8A, DWORDPTR(rd)) // jp rd [Size: 0x6]

#define JPE_RW(rw) JP_RW(rw) // jpe rw [Size: 0x5]
#define JPE_RD(rd) JP_RD(rd) // jpe rd [Size: 0x6]

#define JNP_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8B, WORDPTR(rw)) // jnp rw [Size: 0x5]
#define JNP_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8B, DWORDPTR(rd)) // jnp rd [Size: 0x6]

#define JPO_RW(rw) JNP_RW(rw) // jpo rw [Size: 0x5]
#define JPO_RD(rd) JNP_RD(rd) // jpo rd [Size: 0x6]

#define JL_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8C, WORDPTR(rw)) // jl rw [Size: 0x5]
#define JL_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8C, DWORDPTR(rd)) // jl rd [Size: 0x6]

#define JNGE_RW(rw) JL_RW(rw) // jnge rw [Size: 0x5]
#define JNGE_RD(rd) JL_RD(rd) // jnge rd [Size: 0x6]

#define JNL_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8D, WORDPTR(rw)) // jnl rw [Size: 0x5]
#define JNL_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8D, DWORDPTR(rd)) // jnl rd [Size: 0x6]

#define JGE_RW(rw) JNL_RW(rw) // jge rw [Size: 0x5]
#define JGE_RD(rd) JNL_RD(rd) // jge rd [Size: 0x6]

#define JLE_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8E, WORDPTR(rw)) // jle rw [Size: 0x5]
#define JLE_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8E, DWORDPTR(rd)) // jle rd [Size: 0x6]

#define JNG_RW(rw) JLE_RW(rw) // jng rw [Size: 0x5]
#define JNG_RD(rd) JLE_RD(rd) // jng rd [Size: 0x6]

#define JNLE_RW(rw) PFX_WORD, PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8F, WORDPTR(rw)) // jnle rw [Size: 0x5]
#define JNLE_RD(rd) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x8F, DWORDPTR(rd)) // jnle rd [Size: 0x6]

#define JG_RW(rw) JNLE_RW(rw) // jg rw [Size: 0x5]
#define JG_RD(rd) JNLE_RD(rd) // jg rd [Size: 0x6]

#define SETO_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x90, rm) // seto rm [Size: 0x2]

#define SETNO_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x91, rm) // setno rm [Size: 0x2]

#define SETB_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x92, rm) // seto rm [Size: 0x2]
#define SETNAE_RM(rm) SETB_RM(rm) // setnae rm [Size: 0x2]
#define SETC_RM(rm) SETB_RM(rm) // setc rm [Size: 0x2]

#define SETNB_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x93, rm) // setnb [Size: 0x2]
#define SETAE_RM(rm) SETNB_RM(rm) // setae [Size: 0x2]
#define SETNC_RM(rm) SETNB_RM(rm) // setnc [Size: 0x2]

#define SETZ_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x94, rm) // setz [Size: 0x2]
#define SETE_RM(rm) SETZ_RM(rm) // sete [Size: 0x2]

#define SETNZ_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x95, rm) // setnz [Size: 0x2]
#define SETNE_RM(rm) SETNZ_RM(rm) // setne [Size: 0x2]

#define SETBE_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x96, rm) // setbe [Size: 0x2]
#define SETNA_RM(rm) SETBE_RM(rm) // setna [Size: 0x2]

#define SETNBE_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x97, rm) // setnbe [Size: 0x2]
#define SETA_RM(rm) SETNBE_RM(rm) // seta [Size: 0x2]

#define SETS_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x98, rm) // sets [Size: 0x2]

#define SETNS_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x99, rm) // setns [Size: 0x2]

#define SETP_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9A, rm) // setp [Size: 0x2]
#define SETPE_RM(rm) SETP_RM(rm) // setpe [Size: 0x2]

#define SETNP_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9B, rm) // setnp [Size: 0x2]
#define SETPO_RM(rm) SETNP_RM(rm) // setpo [Size: 0x2]

#define SETL_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9C, rm) // setl [Size: 0x2]
#define SETNGE_RM(rm) SETL_RM(rm) // setnge [Size: 0x2]

#define SETNL_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9D, rm) // setnl [Size: 0x2]
#define SETGE_RM(rm) SETNL_RM(rm) // setge [Size: 0x2]

#define SETLE_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9E, rm) // setle [Size: 0x2]
#define SETNG_RM(rm) SETLE_RM(rm) // setng [Size: 0x2]

#define SETNLE_RM(rm) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0x9F, rm) // setnle [Size: 0x2]
#define SETG_RM(rm) SETNLE_RM(rm) // setg [Size: 0x2]

#define CMPXCHGB_RM_R(rm_r) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xB0, rm_r) // cmpxchg rm_r [Size: 0x2]
#define CMPXCHGD_RM_R(rm_r) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xB1, rm_r) // cmpxchg rm_r [Size: 0x2]

#define BT_RM_B(rm, b) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xBA, 0x20 | rm, BYTEPTR(b)) // bt rm, b [Size: 0x2]
#define BTS_RM_B(rm, b) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xBA, 0x28 | rm, BYTEPTR(b)) // bts rm, b [Size: 0x2]
#define BTR_RM_B(rm, b) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xBA, 0x30 | rm, BYTEPTR(b)) // btr rm, b [Size: 0x2]
#define BTC_RM_B(rm, b) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xBA, 0x38 | rm, BYTEPTR(b)) // btc rm, b [Size: 0x2]

#define BTCD_RM_R(rm_r) PFX_0F, INSERT_INLINECODE_8_BIT_ARRAY(SHELL_RELATIVITY += 0x01, 0xBB, rm_r) // btc rm_r [Size: 0x2]

#endif
#pragma endregion

//#endif