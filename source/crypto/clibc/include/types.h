// Copyright Gleb Obitotsky <https://github.com> 2026.
//
// License: GNU General Public License v3
// You can find the license file in the project root.
//
// Implementation version 1.1
// The code was written for Realix.

/*
 * ===================================================
 * 1. FIXED‑WIDTH INTEGERS
 *    u8..u64, i8..i64   → general‑purpose code, memory structures.
 *    f32, f64           → floating‑point (use sparingly in kernel).
 *
 * 2. MMIO / HARDWARE REGISTERS
 *    vu8, vu16, vu32, vu64   → volatile types for device registers.
 *    vi8, vi16, vi32, vi64   → signed volatile (rare).
 *    Always use them for memory‑mapped I/O, never plain u32.
 *
 * 3. 128‑BIT INTEGERS
 *    u128 / i128   → when __int128 is available (most 64‑bit targets).
 *    If U128_IS_EMULATED is defined, the struct fallback is NOT
 *    constant‑time.
 *
 * 4. POINTER‑SIZED TYPES
 *    usize, isize, uintptr_t, intptr_t   → sizes, offsets, pointer math.
 *
 * 5. BOOLEAN
 *    bool_t   → portable (C: _Bool, C++: bool).
 *    true / false / TRUE / FALSE   → provided if not already defined.
 *
 * 6. ATTRIBUTES & OPTIMISATION
 *    ALWAYS_INLINE, NOINLINE, HOT, COLD   → control inlining & layout.
 *    ALIGN(x), PACKED, CACHE_ALIGN        → alignment.
 *    UNUSED, NORETURN, NONNULL, RESTRICT  → static analysis hints.
 *    MAY_ALIAS                            → bypass strict‑aliasing for type
punning.
 *    OPTIMIZE(level), NO_OPTIMIZE         → per‑function optimisation level.
 *    likely(x), unlikely(x)               → branch prediction hints.
 *
 *    WARNING: PACKED can cause unaligned access faults on strict‑alignment
 *    architectures (ARM, SPARC, MIPS). Use only for protocol headers.
 *
 * 7. LIMITS
 *    i8_MIN..i64_MIN, i8_MAX..i64_MAX, u8_MAX..u64_MAX,
 *    usize_MAX, isize_MAX, isize_MIN.
 *
 * 8. COMPILER BARRIERS
 *    barrier()       → general compiler reordering fence.
 *    ct_barrier()    → constant‑time fence; prevents sensitive operations
 *                       from being optimized away (use after secure_zero,
etc.).
 *
 * 9. SECURE MEMORY ZEROING
 *    secure_zero(ptr, size)   → guaranteed zeroing, never removed by compiler.
 *
 * 10. CONSTANT‑TIME MASK
 *     ct_mask(x)   → returns 0 if x==0, all‑ones otherwise (branch‑free).
 *     Essential for conditional swaps/selects in crypto without leaking timing.
 *
 * 11. FORMAT HELPERS
 *     FMT_USIZE, FMT_ISIZE, FMT_XSIZE   → "zu", "zd", "zx" for printf‑family.
 * =======================================================================
 */

#pragma once

#ifndef _TYPES_H
#define _TYPES_H

/* ==========================================================================
   Compiler requirements
   ========================================================================== */
#if !defined(__UINT8_TYPE__) || !defined(__UINT16_TYPE__) ||  \
    !defined(__UINT32_TYPE__) || !defined(__UINT64_TYPE__) || \
    !defined(__INT8_TYPE__) || !defined(__INT16_TYPE__) ||    \
    !defined(__INT32_TYPE__) || !defined(__INT64_TYPE__) ||   \
    !defined(__SIZE_TYPE__) || !defined(__INTPTR_TYPE__) ||   \
    !defined(__UINTPTR_TYPE__)

#error "types.h requires GCC/Clang compatible integer type extensions"
#endif

/* ==========================================================================
   Fundamental assumptions
   ========================================================================== */
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif
#if CHAR_BIT != 8
#error "types.h requires 8‑bit bytes (CHAR_BIT == 8)"
#endif

/* ==========================================================================
   Fixed‑width integer types (exact width, no padding)
   ========================================================================== */
typedef __UINT8_TYPE__ u8;
typedef __UINT16_TYPE__ u16;
typedef __UINT32_TYPE__ u32;
typedef __UINT64_TYPE__ u64;

typedef __INT8_TYPE__ i8;
typedef __INT16_TYPE__ i16;
typedef __INT32_TYPE__ i32;
typedef __INT64_TYPE__ i64;

typedef float f32;
typedef double f64;

/* --------------------------------------------------------------------------
   128‑bit integers – native when available, emulated otherwise
   -------------------------------------------------------------------------- */
#if defined(__SIZEOF_INT128__)
/* Fast, constant‑time on 64‑bit platforms. Safe for crypto. */
typedef unsigned __int128 u128;
typedef signed __int128 i128;
#define HAVE_NATIVE_128 1
#else
/* Emulated 128‑bit structure – *** INSECURE FOR CRYPTOGRAPHY ***.
   Arithmetic over this structure is NOT constant‑time and will leak
   timing information. The build system MUST NOT link any
   cryptographic primitive against this emulation. */
#define U128_IS_EMULATED 1
typedef struct {
  u64 low;
  u64 high;
} u128;
typedef struct {
  i64 low;
  i64 high;
} i128;

/* In your security‑critical translation units, enforce this check:
   #ifdef U128_IS_EMULATED
   #  error "Native 128‑bit type required for constant‑time crypto"
   #endif
*/
#endif

/* --------------------------------------------------------------------------
   Pointer‑sized types
   -------------------------------------------------------------------------- */
typedef __SIZE_TYPE__ usize;
typedef __INTPTR_TYPE__ isize;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __INTPTR_TYPE__ intptr_t;

#ifndef _SSIZE_T_DEFINED
typedef isize ssize_t;
#define _SSIZE_T_DEFINED
#endif

/* Common aliases */
typedef u8 byte;

/* --------------------------------------------------------------------------
   Volatile MMIO types
   -------------------------------------------------------------------------- */
typedef volatile u8 vu8;
typedef volatile u16 vu16;
typedef volatile u32 vu32;
typedef volatile u64 vu64;
typedef volatile i8 vi8;
typedef volatile i16 vi16;
typedef volatile i32 vi32;
typedef volatile i64 vi64;

/* --------------------------------------------------------------------------
   Strict aliasing helper
   --------------------------------------------------------------------------
   u8 (and byte) is allowed to alias any type. For buffers that must be
   accessed as different types, use explicit memcpy() or declare the
   storage as the may_alias attributed type (see MAY_ALIAS below). */
#ifdef __cplusplus
typedef bool bool_t;
#else
typedef _Bool bool_t;
#endif

/* ==========================================================================
   Compiler attributes & optimisation control
   ========================================================================== */
#if defined(__GNUC__) || defined(__clang__)
#define ALIGN(x) __attribute__((aligned(x)))
#define PACKED __attribute__((packed))
#define UNUSED __attribute__((unused))
#define NORETURN __attribute__((noreturn))
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define NOINLINE __attribute__((noinline))
#define NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#define COLD __attribute__((cold))
#define HOT __attribute__((hot))
#define OPTIMIZE(level) __attribute__((optimize(level)))
#define NO_OPTIMIZE __attribute__((optimize("O0")))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define RESTRICT __restrict
#define MAY_ALIAS __attribute__((__may_alias__))

/* Compiler memory barrier */
#define barrier() __asm__ __volatile__("" ::: "memory")

/* Constant‑time optimisation barrier.
   Prevents the compiler from folding/removing memory operations,
   crucial for secure zeroing and constant‑time comparisons. */
#define ct_barrier() __asm__ __volatile__("" ::: "memory")
#else
#define ALIGN(x)
#define PACKED
#define UNUSED
#define NORETURN
#define ALWAYS_INLINE inline
#define NOINLINE
#define NONNULL(...)
#define COLD
#define HOT
#define OPTIMIZE(level)
#define NO_OPTIMIZE
#define likely(x) (x)
#define unlikely(x) (x)
#define RESTRICT
#define MAY_ALIAS

extern void _types_barrier(void);
#define barrier() _types_barrier()
#define ct_barrier() _types_barrier()
#endif

/* --------------------------------------------------------------------------
   Cache line alignment (configurable)
   -------------------------------------------------------------------------- */
#ifndef CACHE_LINE_SIZE
#if defined(__x86_64__) || defined(__i386__)
#define CACHE_LINE_SIZE 64
#elif defined(__aarch64__)
#define CACHE_LINE_SIZE 64 /* common, but can be 128 on some Apple M1 */
#elif defined(__arm__)
#define CACHE_LINE_SIZE 32
#else
#define CACHE_LINE_SIZE 64 /* safe default */
#endif
#endif
#define CACHE_ALIGN ALIGN(CACHE_LINE_SIZE)

/* --------------------------------------------------------------------------
   WARNING about PACKED
   --------------------------------------------------------------------------
   Applying PACKED to structures accessed via pointers causes unaligned
   memory accesses. Architectures with strict alignment (ARMv5/v6,
   SPARC, older MIPS) will raise a Bus Error or suffer severe
   performance hits. Use PACKED only for on‑wire protocol descriptors
   and always verify with static analysis or runtime checks. */
#if defined(PACKED) && \
    (defined(__arm__) || defined(__sparc__) || defined(__mips__))
#warning "PACKED used on strict‑alignment architecture – inspect all sites"
#endif

/* ==========================================================================
   Limits – mathematically correct
   ========================================================================== */
#define i8_MIN ((i8) - 128)
#define i8_MAX ((i8)127)
#define i16_MIN ((i16) - 32768)
#define i16_MAX ((i16)32767)
#define i32_MIN ((i32)(-2147483647 - 1))
#define i32_MAX ((i32)2147483647)
#define i64_MIN ((i64)(-9223372036854775807LL - 1))
#define i64_MAX ((i64)9223372036854775807LL)

#define u8_MAX ((u8) ~(u8)0)
#define u16_MAX ((u16) ~(u16)0)
#define u32_MAX ((u32) ~(u32)0)
#define u64_MAX ((u64) ~(u64)0)

/* usize / isize – correct computation */
#define usize_MAX ((usize) ~(usize)0)
#define isize_MAX ((isize)((usize) - 1 >> 1))
#define isize_MIN ((-isize_MAX) - 1)

/* ==========================================================================
   Static verification
   ========================================================================== */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert((-1 & 3) == 3,
               "types.h requires two's complement representation");

_Static_assert(sizeof(u8) == 1, "u8 must be 1 byte");
_Static_assert(sizeof(u16) == 2, "u16 must be 2 bytes");
_Static_assert(sizeof(u32) == 4, "u32 must be 4 bytes");
_Static_assert(sizeof(u64) == 8, "u64 must be 8 bytes");
_Static_assert(sizeof(usize) == sizeof(void*), "usize size mismatch");
_Static_assert(sizeof(isize) == sizeof(void*), "isize size mismatch");
_Static_assert(sizeof(uintptr_t) == sizeof(void*), "uintptr_t size mismatch");
_Static_assert(sizeof(f32) == 4 && sizeof(f64) == 8,
               "floating point size mismatch");
_Static_assert(CHAR_BIT == 8, "CHAR_BIT must be 8");

#ifdef __SIZEOF_INT128__
_Static_assert(sizeof(u128) == 16, "u128 must be 16 bytes");
#endif

/* Catch accidental regression of isize_MAX */
_Static_assert(isize_MAX > 0, "isize_MAX is negative – definition bug");
#endif

#define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* ==========================================================================
   Boolean constants
   ========================================================================== */
#ifndef __cplusplus
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* ==========================================================================
   NULL
   ========================================================================== */
#ifndef NULL
#define NULL ((void*)0)
#endif

/* --------------------------------------------------------------------------
   Format helpers
   -------------------------------------------------------------------------- */
#define FMT_USIZE "zu"
#define FMT_ISIZE "zd"
#define FMT_XSIZE "zx"

/* ==========================================================================
   Secure memory zeroing (essential for crypto key handling)
   ==========================================================================
   The compiler must not optimise away memory clearing before free().
   Use secure_zero() to guarantee the store actually happens. */
#if defined(__GNUC__) || defined(__clang__)
#define secure_zero(ptr, size)                 \
  do {                                         \
    volatile char* _p = (volatile char*)(ptr); \
    size_t _n = (size);                        \
    while (_n--) {                             \
      *_p++ = 0;                               \
    }                                          \
    ct_barrier();                              \
  } while (0)
#else
/* Fallback using an external function (linker-provided) */
extern void explicit_bzero(void* s, size_t n);
#define secure_zero(ptr, size) explicit_bzero((ptr), (size))
#endif

/* ==========================================================================
   Constant‑time mask (portable, no branches, relies on two's complement)
   ==========================================================================
   Returns 0 if x is zero, all‑ones (i.e., ~0 of type usize) if x is non‑zero.
   The implementation uses the fact that (usize)(-1) is all‑ones and that
   !!(x) yields exactly 0 or 1, so -(!!(x)) gives 0 or -1 (all ones).
   This is branch‑free on any sane compiler and architecture. */
#define ct_mask(x) ((usize)(-(!!(x))))

#endif /* _TYPES_H */