/** @file
  SSL/TLS Initialization Library Wrapper Implementation over MbedTLS.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalTlsLib.h"

#define MAX_BUFFER_SIZE  32768

int myrand( void *rng_state, unsigned char *output, size_t len );


int MbedtlsSend( void *ctx, const unsigned char *buf, size_t len )
{
  TLS_CIPHER_BUFFER * TlsCipherCtx;
  UINTN CipherLen;

  // UINT8 test[1500];
  // memset(test, 0, 1500);
  TlsCipherCtx = ctx;




  CipherLen = len;


  // CopyMem(TlsCipherCtx->InBuffer + TlsCipherCtx->InRemainderSize, buf, CipherLen);
  // TlsCipherCtx->InRemainderSize += CipherLen;


  CopyMem(TlsCipherCtx->OutBuffer + TlsCipherCtx->OutRemainderSize, buf, CipherLen);
  TlsCipherCtx->OutRemainderSize += CipherLen;



  return (int)(CipherLen);
}

int MbedtlsRecv( void *ctx, unsigned char *buf, size_t len )
{
  TLS_CIPHER_BUFFER * TlsCipherCtx;
  UINTN CipherLen;

  TlsCipherCtx = ctx;

  CipherLen = len;

  CopyMem(buf, TlsCipherCtx->InBuffer + (TlsCipherCtx->InBufferSize - TlsCipherCtx->InRemainderSize) , CipherLen);

  TlsCipherCtx->InRemainderSize -= CipherLen;



  // UINT8 test[1500];
  // memset(test, 0, 1500);
  // CopyMem(test, buf, CipherLen);

  return (int)(CipherLen);
}

/**
  Initializes the MbedTLS library.

  This function registers ciphers and digests used directly and indirectly
  by SSL/TLS, and initializes the readable error messages.
  This function must be called before any other action takes places.

  @retval TRUE   The MbedTLS library has been initialized.
  @retval FALSE  Failed to initialize the MbedTLS library.

**/
BOOLEAN
EFIAPI
TlsInitialize (
  VOID
  )
{
  return TRUE;
}

/**
  Free an allocated SSL_CTX object.

  @param[in]  TlsCtx    Pointer to the SSL_CTX object to be released.

**/
VOID
EFIAPI
TlsCtxFree (
  IN   VOID  *TlsCtx
  )
{
  if (TlsCtx == NULL) {
    return;
  }

  if (TlsCtx != NULL) {
    mbedtls_ssl_free ((mbedtls_ssl_context *)(TlsCtx));
  }
}

/**
  Creates a new SSL_CTX object as framework to establish TLS/SSL enabled
  connections.

  @param[in]  MajorVer    Major Version of TLS/SSL Protocol.
  @param[in]  MinorVer    Minor Version of TLS/SSL Protocol.

  @return  Pointer to an allocated SSL_CTX object.
           If the creation failed, TlsCtxNew() returns NULL.

**/
VOID *
EFIAPI
TlsCtxNew (
  IN     UINT8  MajorVer,
  IN     UINT8  MinorVer
  )
{
  mbedtls_ssl_context *Ssl;
  Ssl = AllocateZeroPool(sizeof(mbedtls_ssl_context));

  mbedtls_ssl_init(Ssl);

  return (VOID *)Ssl;
}

/**
  Free an allocated TLS object.

  This function removes the TLS object pointed to by Tls and frees up the
  allocated memory. If Tls is NULL, nothing is done.

  @param[in]  Tls    Pointer to the TLS object to be freed.

**/
VOID
EFIAPI
TlsConnFree (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if (TlsConn == NULL) {
    return;
  }

  //
  // Free the internal TLS and related BIO objects.
  //
  if (TlsConn->Ssl != NULL) {
    mbedtls_ssl_free (TlsConn->Ssl);
  }

  if (TlsConn->Conf != NULL) {
    mbedtls_ssl_config_free (TlsConn->Conf);
  }

  if (TlsConn->TlsCipherBuffer.InBuffer != NULL) {
    FreePool(TlsConn->TlsCipherBuffer.InBuffer);
  }

  if (TlsConn->TlsCipherBuffer.OutBuffer != NULL) {
    FreePool(TlsConn->TlsCipherBuffer.OutBuffer);
  }

  if (TlsConn->HostCert != NULL) {
    mbedtls_x509_crt_free (TlsConn->HostCert);
     FreePool(TlsConn->HostCert);
  }

  FreePool (Tls);
}

/**
  Create a new TLS object for a connection.

  This function creates a new TLS object for a connection. The new object
  inherits the setting of the underlying context TlsCtx: connection method,
  options, verification setting.

  @param[in]  TlsCtx    Pointer to the SSL_CTX object.

  @return  Pointer to an allocated SSL object.
           If the creation failed, TlsNew() returns NULL.

**/
VOID *
EFIAPI
TlsNew (
  IN     VOID  *TlsCtx
  )
{
  TLS_CONNECTION  *TlsConn;
  TlsConn = NULL;

  //
  // Allocate one new TLS_CONNECTION object
  //
  TlsConn = (TLS_CONNECTION *)AllocateZeroPool (sizeof (TLS_CONNECTION));
  if (TlsConn == NULL) {
    return NULL;
  }

  TlsConn->Ssl = AllocateZeroPool(sizeof(mbedtls_ssl_context));
  mbedtls_ssl_init(TlsConn->Ssl);
  // TlsConn->Ssl = (mbedtls_ssl_context *)TlsCtx;

  TlsConn->Conf = AllocateZeroPool(sizeof( mbedtls_ssl_config));
  mbedtls_ssl_config_init(TlsConn->Conf);

  mbedtls_ssl_conf_rng(TlsConn->Conf, myrand, NULL);

  TlsConn->HostCert = AllocateZeroPool(sizeof( mbedtls_x509_crt));
  mbedtls_x509_crt_init(TlsConn->HostCert);

  TlsConn->Conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
  TlsConn->Conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;

  if (mbedtls_ssl_setup(TlsConn->Ssl, TlsConn->Conf) != 0) {
    return NULL;
  }

  TlsConn->Ssl->state = MBEDTLS_SSL_CLIENT_HELLO;

  TlsConn->TlsCipherBuffer.InBufferSize = MAX_BUFFER_SIZE;
  TlsConn->TlsCipherBuffer.InBuffer = AllocateZeroPool(MAX_BUFFER_SIZE);

  TlsConn->TlsCipherBuffer.OutBufferSize = 0;
  TlsConn->TlsCipherBuffer.OutRemainderSize = 0;
  TlsConn->TlsCipherBuffer.OutBuffer = AllocateZeroPool(MAX_BUFFER_SIZE);

  mbedtls_ssl_set_bio(TlsConn->Ssl, &(TlsConn->TlsCipherBuffer),
                      MbedtlsSend, MbedtlsRecv, NULL);

  return (VOID *)TlsConn;
}
