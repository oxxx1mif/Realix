// Copyright Gleb Obitotsky <https://github.com> 2026.
//
// License: GNU General Public License v3
// You can find the license file in the project root.
//
// Implementation version 1.1
// The code was written for Realix.

/*
 * ============================================================================
 * This header provides standard types and useful macros.
 *
 * Implemented features:
 *
 * • size_t, ptrdiff_t, max_align_t, wchar_t
 * • NULL
 * • offsetof() — using __builtin_offsetof for GNU-compatible compilers
 * • unreachable() — to mark unreachable code
 * • container_of() / container_of_const() — safely obtain a pointer
 *   to a structure given a pointer to one of its members (with field type
 * checking) • ARRAY_SIZE() / array_size() — safe static array size with
 * protection against passing a pointer • nullptr_t
 * ============================================================================
 */

#pragma once

#ifndef _STDDEF_H
#define _STDDEF_H

/* ==========================================================================
   Compiler detection
   ========================================================================== */
#if defined(__GNUC__) || defined(__clang__)
#define STDDEF_HAS_GNU_EXTENSIONS 1
#else
#define STDDEF_HAS_GNU_EXTENSIONS 0
#endif

/* ==========================================================================
   Standard types
   ========================================================================== */

// size_t
#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
#if defined(__SIZE_TYPE__)
typedef __SIZE_TYPE__ size_t;
#else
#error "Compiler does not provide __SIZE_TYPE__"
#endif
#endif

// ptrdiff_t
#ifndef _PTRDIFF_T_DEFINED
#define _PTRDIFF_T_DEFINED
#if defined(__PTRDIFF_TYPE__)
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#else
#error "Compiler does not provide __PTRDIFF_TYPE__"
#endif
#endif

// max_align_t
#ifndef _MAX_ALIGN_T_DEFINED
#define _MAX_ALIGN_T_DEFINED
#if defined(__MAX_ALIGN_T)
typedef __MAX_ALIGN_T max_align_t;
#else
typedef struct {
  long long ll;
  long double ld;
  void* ptr;
} max_align_t;
#endif
#endif

// wchar_t
#ifndef _WCHAR_T_DEFINED
#define _WCHAR_T_DEFINED
#ifndef __cplusplus
#if defined(__WCHAR_TYPE__)
typedef __WCHAR_TYPE__ wchar_t;
#else
typedef int wchar_t;
#endif
#endif
#endif

// nullptr_t
#ifndef _NULLPTR_T_DEFINED
#define _NULLPTR_T_DEFINED
#ifdef __cplusplus
#if __cplusplus >= 201103L
typedef decltype(nullptr) nullptr_t;
#endif
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#if STDDEF_HAS_GNU_EXTENSIONS
typedef typeof(nullptr) nullptr_t;
#endif
#endif
#endif

/* ==========================================================================
   Standard macros
   ========================================================================== */

#ifndef NULL
#ifdef __cplusplus
#if __cplusplus >= 201103L
#define NULL nullptr
#else
#define NULL 0L
#endif
#else
#define NULL ((void*)0)
#endif
#endif

// offsetof
#ifndef offsetof
#if STDDEF_HAS_GNU_EXTENSIONS
#define offsetof(type, member) __builtin_offsetof(type, member)
#else
#define offsetof(type, member) ((size_t)&(((type*)0)->member))
#endif
#endif

// unreachable
#ifndef unreachable
#if STDDEF_HAS_GNU_EXTENSIONS
#define unreachable() __builtin_unreachable()
#else
#define unreachable() ((void)0)
#endif
#endif

/**
 * container_of - get pointer to the containing structure
 *
 * Performs compile-time type checking of the member.
 * Does NOT preserve const/volatile qualifiers
 * (use container_of_const for const-safe version).
 */
#ifndef container_of
#if STDDEF_HAS_GNU_EXTENSIONS
#define container_of(ptr, type, member)              \
  ({                                                 \
    typeof(((type*)0)->member)* __mptr = (ptr);      \
    (type*)((char*)__mptr - offsetof(type, member)); \
  })
#else
#error "container_of requires GCC or Clang extensions"
#endif
#endif

/**
 * container_of_const - const-safe version of container_of
 */
#ifndef container_of_const
#if STDDEF_HAS_GNU_EXTENSIONS
#define container_of_const(ptr, type, member)                    \
  ({                                                             \
    const typeof(((type*)0)->member)* __mptr = (ptr);            \
    (const type*)((const char*)__mptr - offsetof(type, member)); \
  })
#else
#error "container_of requires GCC or Clang extensions"
#endif
#endif

/* ==========================================================================
   Array utilities
   ========================================================================== */

#ifndef STDDEF_MUST_BE_ARRAY
#if STDDEF_HAS_GNU_EXTENSIONS
#define STDDEF_MUST_BE_ARRAY(arr)                                            \
  (0 * sizeof(struct {                                                       \
     int : __builtin_types_compatible_p(typeof(arr), typeof(&(arr)[0])) ? -1 \
                                                                        : 1; \
   }))
#else
#define STDDEF_MUST_BE_ARRAY(arr) 0
#endif
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) \
  (sizeof(arr) / sizeof((arr)[0]) + STDDEF_MUST_BE_ARRAY(arr))
#endif

#ifndef array_size
#define array_size(arr) ARRAY_SIZE(arr)
#endif

/* ==========================================================================
   Compile-time checks
   ========================================================================== */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(size_t) >= sizeof(unsigned int), "size_t is too small");
_Static_assert(sizeof(ptrdiff_t) >= sizeof(int), "ptrdiff_t is too small");
#endif

/* ==========================================================================
   Cleanup (only safe internal macros)
   ========================================================================== */
#undef STDDEF_HAS_GNU_EXTENSIONS

#endif /* _STDDEF_H */