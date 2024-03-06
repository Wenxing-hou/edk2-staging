/** @file
  SSL/TLS Process Library Wrapper Implementation over MbedTLS.
  The process includes the TLS handshake and packet I/O.

Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
(C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalTlsLib.h"


/**
  Checks if the TLS handshake was done.

  This function will check if the specified TLS handshake was done.

  @param[in]  Tls    Pointer to the TLS object for handshake state checking.

  @retval  TRUE     The TLS handshake was done.
  @retval  FALSE    The TLS handshake was not done.

**/
BOOLEAN
EFIAPI
TlsInHandshake (
  IN     VOID  *Tls
  )
{
  TLS_CONNECTION  *TlsConn;
  INTN  state;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (TlsConn->Ssl == NULL)) {
    return FALSE;
  }

  //
  // Return the status which indicates if the TLS handshake was done.
  //

  state = mbedtls_ssl_is_handshake_over(TlsConn->Ssl);

  if (state == 1) {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**
  Perform a TLS/SSL handshake.

  This function will perform a TLS/SSL handshake.

  @param[in]       Tls            Pointer to the TLS object for handshake operation.
  @param[in]       BufferIn       Pointer to the most recently received TLS Handshake packet.
  @param[in]       BufferInSize   Packet size in bytes for the most recently received TLS
                                  Handshake packet.
  @param[out]      BufferOut      Pointer to the buffer to hold the built packet.
  @param[in, out]  BufferOutSize  Pointer to the buffer size in bytes. On input, it is
                                  the buffer size provided by the caller. On output, it
                                  is the buffer size in fact needed to contain the
                                  packet.

  @retval EFI_SUCCESS             The required TLS packet is built successfully.
  @retval EFI_INVALID_PARAMETER   One or more of the following conditions is TRUE:
                                  Tls is NULL.
                                  BufferIn is NULL but BufferInSize is NOT 0.
                                  BufferInSize is 0 but BufferIn is NOT NULL.
                                  BufferOutSize is NULL.
                                  BufferOut is NULL if *BufferOutSize is not zero.
  @retval EFI_BUFFER_TOO_SMALL    BufferOutSize is too small to hold the response packet.
  @retval EFI_ABORTED             Something wrong during handshake.

**/
EFI_STATUS
EFIAPI
TlsDoHandshake (
  IN     VOID   *Tls,
  IN     UINT8  *BufferIn  OPTIONAL,
  IN     UINTN  BufferInSize  OPTIONAL,
  OUT UINT8     *BufferOut  OPTIONAL,
  IN OUT UINTN  *BufferOutSize
  )
{
  INTN            Ret;
  TLS_CONNECTION  *TlsConn;

  Ret               = 1;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (TlsConn->Ssl == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((BufferOutSize == NULL) || \
      ((BufferIn == NULL) && (BufferInSize != 0)) || \
      ((BufferIn != NULL) && (BufferInSize == 0)) || \
      ((BufferOut == NULL) && (*BufferOutSize != 0)))
  {
    return EFI_INVALID_PARAMETER;
  }


// client parse server hello
  if ((BufferIn != NULL) && (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )){
      CopyMem(TlsConn->TlsCipherBuffer.InBuffer, BufferIn, BufferInSize);
      TlsConn->TlsCipherBuffer.InBufferSize = BufferInSize;
      TlsConn->TlsCipherBuffer.InRemainderSize = BufferInSize;
  }


  if ((BufferIn != NULL) && (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER ) && (TlsConn->Ssl->state == MBEDTLS_SSL_CLIENT_HELLO)){
    CopyMem(TlsConn->TlsCipherBuffer.InBuffer, BufferIn, BufferInSize);
    TlsConn->TlsCipherBuffer.InBufferSize = BufferInSize;
    TlsConn->TlsCipherBuffer.InRemainderSize = BufferInSize;
  }

// server get client cipher/finished
  if ((BufferIn != NULL) && (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER ) && (TlsConn->Ssl->state == MBEDTLS_SSL_CLIENT_CERTIFICATE)){
    CopyMem(TlsConn->TlsCipherBuffer.InBuffer, BufferIn, BufferInSize);
    TlsConn->TlsCipherBuffer.InBufferSize = BufferInSize;
    TlsConn->TlsCipherBuffer.InRemainderSize = BufferInSize;
  }


if ((TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER ) || ((TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) && (TlsConn->Ssl->state == MBEDTLS_SSL_CLIENT_HELLO) )) {
  while((Ret = mbedtls_ssl_handshake_step(TlsConn->Ssl) ) != 0 )
  {
      if( Ret != MBEDTLS_ERR_SSL_WANT_READ && Ret != MBEDTLS_ERR_SSL_WANT_WRITE )
      {
          return EFI_ABORTED;
      }
  }
} else {

  while(TlsConn->TlsCipherBuffer.InRemainderSize != 0) {
      while((Ret = mbedtls_ssl_handshake_step(TlsConn->Ssl) ) != 0 )
      {
          if( Ret != MBEDTLS_ERR_SSL_WANT_READ && Ret != MBEDTLS_ERR_SSL_WANT_WRITE )
          {
              return EFI_ABORTED;
          }
      }
  }
}



  if ((TlsConn->Ssl->state == MBEDTLS_SSL_SERVER_HELLO_DONE) && (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )) {

    while (TlsConn->Ssl->state <= MBEDTLS_SSL_CLIENT_FINISHED ) {
      while((Ret = mbedtls_ssl_handshake_step(TlsConn->Ssl) ) != 0 )
      {
          if( Ret != MBEDTLS_ERR_SSL_WANT_READ && Ret != MBEDTLS_ERR_SSL_WANT_WRITE )
          {
              return EFI_ABORTED;
          }
      }
    }
  }


  if ((TlsConn->Ssl->state == MBEDTLS_SSL_FLUSH_BUFFERS) && (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )) {

    while (TlsConn->Ssl->state <= MBEDTLS_SSL_HANDSHAKE_WRAPUP ) {
      while((Ret = mbedtls_ssl_handshake_step(TlsConn->Ssl) ) != 0 )
      {
          if( Ret != MBEDTLS_ERR_SSL_WANT_READ && Ret != MBEDTLS_ERR_SSL_WANT_WRITE )
          {
              return EFI_ABORTED;
          }
      }
    }
  }


//  把 clienthello 的信息传出来到 BufferOut
  if ((TlsConn->Ssl->state == MBEDTLS_SSL_SERVER_HELLO) && (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )) {

    if (BufferOut != NULL) {
      CopyMem(BufferOut, TlsConn->Ssl->out_hdr  - TlsConn->Ssl->out_left, TlsConn->Ssl->out_left);
      *BufferOutSize = TlsConn->Ssl->out_left;
      TlsConn->Ssl->out_left = 0;
    }
  }


  if (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER ) {

    if (BufferOut != NULL) {

      if (TlsConn->TlsCipherBuffer.OutRemainderSize != 0) {
        CopyMem(BufferOut, TlsConn->TlsCipherBuffer.OutBuffer, TlsConn->TlsCipherBuffer.OutRemainderSize);
        *BufferOutSize = TlsConn->TlsCipherBuffer.OutRemainderSize;
        TlsConn->TlsCipherBuffer.OutRemainderSize = 0;
      } else {
        *BufferOutSize = 0;
      }
    }
  }



// client 
  if ((TlsConn->Ssl->state == MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC) && (TlsConn->Ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )) {

    if (BufferOut != NULL) {
      CopyMem(BufferOut, TlsConn->TlsCipherBuffer.OutBuffer, TlsConn->TlsCipherBuffer.OutRemainderSize);
      *BufferOutSize = TlsConn->TlsCipherBuffer.OutRemainderSize;

      TlsConn->TlsCipherBuffer.OutRemainderSize = 0;
    }
  }


//handshake over
  if (TlsConn->Ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER) {
    TlsConn->TlsCipherBuffer.InRemainderSize = 0;
    TlsConn->TlsCipherBuffer.InBufferSize = 0;
    TlsConn->TlsCipherBuffer.OutRemainderSize = 0;
    TlsConn->TlsCipherBuffer.OutBufferSize = 0;
  }

  return EFI_SUCCESS;
}

/**
  Handle Alert message recorded in BufferIn. If BufferIn is NULL and BufferInSize is zero,
  TLS session has errors and the response packet needs to be Alert message based on error type.

  @param[in]       Tls            Pointer to the TLS object for state checking.
  @param[in]       BufferIn       Pointer to the most recently received TLS Alert packet.
  @param[in]       BufferInSize   Packet size in bytes for the most recently received TLS
                                  Alert packet.
  @param[out]      BufferOut      Pointer to the buffer to hold the built packet.
  @param[in, out]  BufferOutSize  Pointer to the buffer size in bytes. On input, it is
                                  the buffer size provided by the caller. On output, it
                                  is the buffer size in fact needed to contain the
                                  packet.

  @retval EFI_SUCCESS             The required TLS packet is built successfully.
  @retval EFI_INVALID_PARAMETER   One or more of the following conditions is TRUE:
                                  Tls is NULL.
                                  BufferIn is NULL but BufferInSize is NOT 0.
                                  BufferInSize is 0 but BufferIn is NOT NULL.
                                  BufferOutSize is NULL.
                                  BufferOut is NULL if *BufferOutSize is not zero.
  @retval EFI_ABORTED             An error occurred.
  @retval EFI_BUFFER_TOO_SMALL    BufferOutSize is too small to hold the response packet.

**/
EFI_STATUS
EFIAPI
TlsHandleAlert (
  IN     VOID   *Tls,
  IN     UINT8  *BufferIn  OPTIONAL,
  IN     UINTN  BufferInSize  OPTIONAL,
  OUT UINT8     *BufferOut  OPTIONAL,
  IN OUT UINTN  *BufferOutSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           PendingBufferSize;
  UINT8           *TempBuffer;
  INTN            Ret;

  TlsConn           = (TLS_CONNECTION *)Tls;
  PendingBufferSize = 0;
  TempBuffer        = NULL;
  Ret               = 0;

  if ((TlsConn == NULL) || \
      (TlsConn->Ssl == NULL) || \
      (BufferOutSize == NULL) || \
      ((BufferIn == NULL) && (BufferInSize != 0)) || \
      ((BufferIn != NULL) && (BufferInSize == 0)) || \
      ((BufferOut == NULL) && (*BufferOutSize != 0)))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (mbedtls_ssl_handle_pending_alert(TlsConn->Ssl) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  // mbedtls_net_recv (TlsConn->fd, BufferOut, (UINT32)*BufferOutSize);
  return EFI_SUCCESS;

}

/**
  Build the CloseNotify packet.

  @param[in]       Tls            Pointer to the TLS object for state checking.
  @param[in, out]  Buffer         Pointer to the buffer to hold the built packet.
  @param[in, out]  BufferSize     Pointer to the buffer size in bytes. On input, it is
                                  the buffer size provided by the caller. On output, it
                                  is the buffer size in fact needed to contain the
                                  packet.

  @retval EFI_SUCCESS             The required TLS packet is built successfully.
  @retval EFI_INVALID_PARAMETER   One or more of the following conditions is TRUE:
                                  Tls is NULL.
                                  BufferSize is NULL.
                                  Buffer is NULL if *BufferSize is not zero.
  @retval EFI_BUFFER_TOO_SMALL    BufferSize is too small to hold the response packet.

**/
EFI_STATUS
EFIAPI
TlsCloseNotify (
  IN     VOID   *Tls,
  IN OUT UINT8  *Buffer,
  IN OUT UINTN  *BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN           PendingBufferSize;

  TlsConn           = (TLS_CONNECTION *)Tls;
  PendingBufferSize = 0;

  if ((TlsConn == NULL) || \
      (TlsConn->Ssl == NULL) || \
      (BufferSize == NULL) || \
      ((Buffer == NULL) && (*BufferSize != 0)))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (mbedtls_ssl_close_notify(TlsConn->Ssl) != 0) {
    return EFI_INVALID_PARAMETER;
  } 
  
  // mbedtls_net_recv (TlsConn->fd, Buffer, (UINT32)*BufferSize);
  return EFI_SUCCESS;

}


/**
  Attempts to read bytes from one TLS object and places the data in Buffer.

  This function will attempt to read BufferSize bytes from the TLS object
  and places the data in Buffer.

  @param[in]      Tls           Pointer to the TLS object.
  @param[in,out]  Buffer        Pointer to the buffer to store the data.
  @param[in]      BufferSize    The size of Buffer in bytes.

  @retval  >0    The amount of data successfully read from the TLS object.
  @retval  <=0   No data was successfully read.

**/
INTN
EFIAPI
TlsCtrlTrafficOut (
  IN     VOID   *Tls,
  IN OUT VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;
  UINTN CipherLen;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL)) {
    return -1;
  }

  CopyMem(Buffer, TlsConn->TlsCipherBuffer.OutBuffer,
          TlsConn->TlsCipherBuffer.OutRemainderSize);

  CipherLen = TlsConn->TlsCipherBuffer.OutRemainderSize;
  TlsConn->TlsCipherBuffer.OutRemainderSize = 0;


  return CipherLen;
}

/**
  Attempts to write data from the buffer to TLS object.

  This function will attempt to write BufferSize bytes data from the Buffer
  to the TLS object.

  @param[in]  Tls           Pointer to the TLS object.
  @param[in]  Buffer        Pointer to the data buffer.
  @param[in]  BufferSize    The size of Buffer in bytes.

  @retval  >0    The amount of data successfully written to the TLS object.
  @retval <=0    No data was successfully written.

**/
INTN
EFIAPI
TlsCtrlTrafficIn (
  IN     VOID   *Tls,
  IN     VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL)) {
    return -1;
  }

  CopyMem(TlsConn->TlsCipherBuffer.InBuffer, Buffer, BufferSize);
  TlsConn->TlsCipherBuffer.InRemainderSize = BufferSize;
  TlsConn->TlsCipherBuffer.InBufferSize = BufferSize;
  return BufferSize;
}

/**
  Attempts to read bytes from the specified TLS connection into the buffer.

  This function tries to read BufferSize bytes data from the specified TLS
  connection into the Buffer.

  @param[in]      Tls           Pointer to the TLS connection for data reading.
  @param[in,out]  Buffer        Pointer to the data buffer.
  @param[in]      BufferSize    The size of Buffer in bytes.

  @retval  >0    The read operation was successful, and return value is the
                 number of bytes actually read from the TLS connection.
  @retval  <=0   The read operation was not successful.

**/
INTN
EFIAPI
TlsRead (
  IN     VOID   *Tls,
  IN OUT VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (TlsConn->Ssl == NULL)) {
    return -1;
  }

  //
  // Read bytes from the specified TLS connection.
  //
  return mbedtls_ssl_read (TlsConn->Ssl, Buffer, (UINT32)BufferSize);
}

/**
  Attempts to write data to a TLS connection.

  This function tries to write BufferSize bytes data from the Buffer into the
  specified TLS connection.

  @param[in]  Tls           Pointer to the TLS connection for data writing.
  @param[in]  Buffer        Pointer to the data buffer.
  @param[in]  BufferSize    The size of Buffer in bytes.

  @retval  >0    The write operation was successful, and return value is the
                 number of bytes actually written to the TLS connection.
  @retval <=0    The write operation was not successful.

**/
INTN
EFIAPI
TlsWrite (
  IN     VOID   *Tls,
  IN     VOID   *Buffer,
  IN     UINTN  BufferSize
  )
{
  TLS_CONNECTION  *TlsConn;

  TlsConn = (TLS_CONNECTION *)Tls;
  if ((TlsConn == NULL) || (TlsConn->Ssl == NULL)) {
    return -1;
  }

  //
  // Write bytes to the specified TLS connection.
  //
  return mbedtls_ssl_write (TlsConn->Ssl, Buffer, (UINT32)BufferSize);
}

/**
  Shutdown a TLS connection.

  Shutdown the TLS connection without releasing the resources, meaning a new
  connection can be started without calling TlsNew() and without setting
  certificates etc.

  @param[in]       Tls            Pointer to the TLS object to shutdown.

  @retval EFI_SUCCESS             The TLS is shutdown successfully.
  @retval EFI_INVALID_PARAMETER   Tls is NULL.
  @retval EFI_PROTOCOL_ERROR      Some other error occurred.
**/
EFI_STATUS
EFIAPI
TlsShutdown (
  IN     VOID  *Tls
  )
{
  return EFI_SUCCESS;
}
