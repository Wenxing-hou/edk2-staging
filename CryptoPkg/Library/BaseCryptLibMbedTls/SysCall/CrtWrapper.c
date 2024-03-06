/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation for MbedTLS-based
  Cryptographic Library.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <stdio.h>

int mbedtls_printf (char const *fmt, ...)
{
  ASSERT(FALSE);
  return 0;
}

int mbedtls_vsnprintf(char *str, size_t size, const char *format, ...)
{
  ASSERT(FALSE);
  return 0;
}

char *
strchr (
  const char  *str,
  int         ch
  )
{
  return ScanMem8 (str, AsciiStrSize (str), (char)ch);
}

// int
// strcmp (
//   const char  *s1,
//   const char  *s2
//   )
// {
//   return (int)AsciiStrCmp (s1, s2);
// }
