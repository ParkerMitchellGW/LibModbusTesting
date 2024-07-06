/*
 * (c) 2011 Guided Wave Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "modbus-private.h"
#include "modbus-crc.h"

#include "modbus-d2x.h"
#include "modbus-d2x-private.h"
#include "fprintf.h"

#define MAXDWORD 0xffffffff

static const char* d2xStatusStrings[] =
{
    "No error",                    /* FT_OK                          */
    "Invalid handle",              /* FT_INVALID_HANDLE              */
    "Device not found",            /* FT_DEVICE_NOT_FOUND            */
    "Device not opened",           /* FT_DEVICE_NOT_OPENED           */
    "I/O error",                   /* FT_IO_ERROR                    */
    "Insufficient resources",      /* FT_INSUFFICIENT_RESOURCES      */
    "Invalid parameter",           /* FT_INVALID_PARAMETER           */
    "Invalid baud rate",           /* FT_INVALID_BAUD_RATE           */
    "Device not opened for erase", /* FT_DEVICE_NOT_OPENED_FOR_ERASE */
    "Device not opened for write", /* FT_DEVICE_NOT_OPENED_FOR_WRITE */
    "Failed to write device",      /* FT_FAILED_TO_WRITE_DEVICE      */
    "EEPROM read failed",          /* FT_EEPROM_READ_FAILED          */
    "EEPROM write failed",         /* FT_EEPROM_WRITE_FAILED         */
    "EEPROM erase failed",         /* FT_EEPROM_ERASE_FAILED         */
    "EEPROM not present",          /* FT_EEPROM_NOT_PRESENT          */
    "EEPROM not programmed",       /* FT_EEPROM_NOT_PROGRAMMED       */
    "Invalid arguments",           /* FT_INVALID_ARGS                */
    "Not supported",               /* FT_NOT_SUPPORTED               */
    "Other error"                  /* FT_OTHER_ERROR                 */
};


/*
 *  D2XX utilities
 */

static const char* strerror_d2x(
    FT_STATUS status)
{
    if (status < 0 || status > FT_OTHER_ERROR)
        status = FT_OTHER_ERROR;

    return d2xStatusStrings[status];
}

static FT_STATUS d2xCreateDeviceInfoList(LPDWORD pNumDevices)
{
    FT_STATUS status = FT_CreateDeviceInfoList(pNumDevices);

    if (status != FT_OK)
    {
        fprintf(stderr, "ERROR Can't create the device list (%s)\n",
                strerror_d2x(status));
    }

    return status;
}

static FT_STATUS d2xGetDeviceInfoList(
    FT_DEVICE_LIST_INFO_NODE* pInfoList,
    LPDWORD                   pNumDevices)
{
    FT_STATUS status = FT_GetDeviceInfoList(pInfoList, pNumDevices);

    if (status != FT_OK)
    {
        fprintf(stderr, "ERROR Can't retrieve the device list (%s)\n",
                strerror_d2x(status));
    }

    return status;
}

static FT_STATUS d2xOpenEx(
    const char* device,
    DWORD       method,
    FT_HANDLE*  pHandle)
{
    FT_STATUS status = FT_OpenEx((PVOID) device, method, pHandle);

    if (status != FT_OK)
    {
        fprintf(stderr, "ERROR Can't open device %s by %s (%s)\n",
                device,
                (method == d2xOpenBySerialNum ? "serial number" : "description"),
                strerror_d2x(status));
    }

    return status;
}

static void d2xSetCommParams(
    FT_HANDLE   handle,
    const char* serialNumber,
    const char* description,
    int         baud)
{
    // Set baud rate and other communications parameters.
    //
    //
    // NOTE:  Should not be called for X_SERIES chips (type 9)!
    //
    //
    FT_STATUS status;
    
    status = FT_SetBaudRate(handle, (DWORD) baud);
    if (status != FT_OK)
        fprintf(stderr, "ERROR Can't set baud rate for device %s - %s (%s)\n",
                serialNumber, description, strerror_d2x(status));

    status = FT_SetDataCharacteristics(handle, FT_BITS_8, FT_STOP_BITS_1, FT_PARITY_NONE);
    if (status != FT_OK)
        fprintf(stderr, "ERROR Can't set data characteristics for device %s - %s (%s)\n",
                serialNumber, description, strerror_d2x(status));

    status = FT_SetFlowControl(handle, FT_FLOW_NONE, 0, 0);
    if (status != FT_OK)
        fprintf(stderr, "ERROR Can't set flow control for device %s - %s (%s)\n",
                serialNumber, description, strerror_d2x(status));
}

static FT_STATUS d2xClose(
    FT_HANDLE handle)
{
    FT_STATUS status = FT_OK;

    if (handle != NULL)
    {
        status = FT_Close(handle);

        if (status != FT_OK)
        {
            fprintf(stderr, "ERROR Can't close device (%s)\n",
                    strerror_d2x(status));
        }
    }

    return status;
}

static FT_STATUS d2xPurge(
    FT_HANDLE handle)
{
    FT_STATUS status = FT_OK;

    if (handle != NULL)
    {
        status = FT_Purge(handle, FT_PURGE_RX | FT_PURGE_TX);
        if (status != FT_OK)
        {
            fprintf(stderr, "ERROR Can't flush device (%s)\n",
                    strerror_d2x(status));
        }
    }

    return status;
}

static FT_STATUS d2xSetTimeouts(
    FT_HANDLE handle,
    DWORD     readTimeout,  /* milliseconds */
    DWORD     writeTimeout) /* milliseconds */
{
    FT_STATUS status = FT_SetTimeouts(handle, readTimeout, writeTimeout);

    if (status != FT_OK)
    {
        fprintf(stderr, "ERROR Can't set device timeouts (%s)\n",
                strerror_d2x(status));
    }

    return status;
}

static FT_STATUS d2xRead(
    FT_HANDLE handle,
    LPVOID    pBuffer,
    DWORD     bytesToRead,
    LPDWORD   pBytesReturned)
{
    FT_STATUS status = FT_Read(handle, pBuffer, bytesToRead, pBytesReturned);

    if (status != FT_OK)
    {
        fprintf(stderr, "ERROR Can't read from the device (%s)\n",
                strerror_d2x(status));
    }

    return status;
}

static FT_STATUS d2xWrite(
    FT_HANDLE handle,
    LPVOID    pBuffer,
    DWORD     bytesToWrite,
    LPDWORD   pBytesWritten)
{
    FT_STATUS status;
    int       remaining = bytesToWrite;
    DWORD     total     = 0;
    DWORD     bytes;
    DWORD     written;
#ifdef _WIN32
	char* tmpPtr;
#endif

    while (remaining > 0)
    {
        bytes      = (remaining > D2X_CHUNK_SIZE ? D2X_CHUNK_SIZE : remaining);
        written    = 0;
        status     = FT_Write(handle, pBuffer, bytes, &written);
        if (status == FT_OK)
        {
            remaining -= written;
#ifdef _WIN32
			tmpPtr = (char*)pBuffer + written;
			pBuffer = tmpPtr;
#else
            pBuffer   += written;
#endif
            total     += written;

            *pBytesWritten = total;
        }
        else
        {
            fprintf(stderr, "ERROR Can't write to the device (%d: %s)\n", (int) status,
                    strerror_d2x(status));
            break;
        }
    }

    return status;
}



/*
 *  This simple implementation is a substitute for the select() call.
 *  d2x_select() tries to read some data from the D2XX device, using
 *  the provided timeout.  The data read is stored into the receive
 *  buffer that is then consumed by d2x_read().  So, d2x_select() does
 *  both the event waiting and the reading, while d2x_read() only
 *  consumes the receive buffer.
 */

static int d2x_select(
    modbus_d2x_t*   ctx_d2x,
    DWORD           nBytesToRead,
    struct timeval* tv)
{
    unsigned int    millisec = 0;
    DWORD           nBytesReturned;
    FT_STATUS       status;
    int             result = 1;

    /* Check if some data still in the buffer to be consumed. */
    if (ctx_d2x->nAvailable == 0)
    {
        /* Setup timeouts like select() would do. */
        if (tv == NULL)
            millisec = MAXDWORD;
        else
        {
            millisec = tv->tv_sec * 1000 + tv->tv_usec / 1000;
            if (millisec < 1) millisec = 1;
        }

        d2xSetTimeouts(ctx_d2x->handle, millisec, millisec);

        if ((nBytesToRead > _D2X_BUF_SIZE))
            nBytesToRead = _D2X_BUF_SIZE;

        result = -1;

        /* Read some bytes. */
        status = d2xRead(ctx_d2x->handle, ctx_d2x->buffer, nBytesToRead, &nBytesReturned);

        if (status == FT_OK)
        {
            ctx_d2x->nAvailable = nBytesReturned;
            ctx_d2x->nUsed      = 0;

            result = (nBytesReturned == nBytesToRead ? 1 : 0);
            if (result == 0)
                fprintf(stderr, "ERROR d2xx %d millisecond timeout\n", millisec);
        }
    }

    return result;
}

static ssize_t d2x_read(
    modbus_d2x_t* ctx_d2x,
    uint8_t*      pBuffer,
    DWORD         nBytesToRead)
{
    DWORD nBytes = ctx_d2x->nAvailable;

    if (nBytes > 0)
    {
        if (nBytesToRead < nBytes)
            nBytes = nBytesToRead;

        memcpy((void*) pBuffer, (void*) (ctx_d2x->buffer + ctx_d2x->nUsed), nBytes);

        ctx_d2x->nAvailable -= nBytes;
        ctx_d2x->nUsed      += nBytes;
    }

    return nBytes;
}

/*
 *  Returns a list of D2XX info nodes representing all D2XX devices
 *  present.  Also returns the number of devices in the list (pNumDevices).
 *  This routine allocates memory for the list.
 *
 *  Note: The caller is responsible for freeing the memory.
 */

d2x_device_info_t* modbus_get_d2x_device_info_list(
    LPDWORD            pNumDevices)
{
    FT_STATUS          status;
    d2x_device_info_t* pInfoList = NULL;

    status = d2xCreateDeviceInfoList(pNumDevices);

    if (status == FT_OK)
    {
        if (*pNumDevices > 0)
        {
            pInfoList = (d2x_device_info_t*)
                            malloc(sizeof(d2x_device_info_t) * (*pNumDevices));
            status = d2xGetDeviceInfoList(pInfoList, pNumDevices);

            if (status != FT_OK)
            {
                free(pInfoList);
                pInfoList = NULL;
                *pNumDevices = 0;
            }
        }
    }
    else
        *pNumDevices = 0;

    return pInfoList;
}

/*
 *  Retrieves D2XX device information and stores it in the struct pointed to
 *  by pInfo.  Returns the device's current position in the device list.
 *  Note:  This position may change as devices are disconnected from the host.
 *  The current device list is generated and searched for a device which matches
 *  either serial number or description depending on how the modbus device was
 *  created (modbus_new_d2x_by_{serial_number|description}).
 *  A return value of -1 indicates that the device could not be found and the
 *  contents of *pInfo have not been modified.
 */
int modbus_get_d2x_device_info(
    modbus_t*          ctx,
    d2x_device_info_t* pInfo)
{
    DWORD numDevices;
    d2x_device_info_t* pInfoList = modbus_get_d2x_device_info_list(&numDevices);
    int index = -1;

    if (pInfoList != NULL)
    {
        modbus_d2x_t* ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
        if (ctx_d2x->method == d2xOpenBySerialNum)
        {
            for (index = numDevices - 1; index >= 0; index--)
            {
                if (strcmp(ctx_d2x->device, pInfoList[index].SerialNumber) == 0)
                    break;
            }
        }
        else
        {
            for (index = numDevices - 1; index >= 0; index--)
            {
                if (strcmp(ctx_d2x->device, pInfoList[index].Description) == 0)
                    break;
            }
        }
    }

    if (index >= 0)
    {
        memcpy((void*) pInfo, (void*) (pInfoList + index),
               sizeof(d2x_device_info_t));
    }

    return index;
}



/* Sets the slave id. */
static int _modbus_set_slave(
    modbus_t* ctx,
    int       slave)
{
    int result = 0;

    /* Broadcast address is 0 (MODBUS_BROADCAST_ADDRESS) */
    if (slave >= 0 && slave <= 247)
        ctx->slave = slave;
    else
    {
        errno = EINVAL;
        result = -1;
    }

    return result;
}

/* Builds a D2X request header */
static int _modbus_d2x_build_request_basis(
    modbus_t* ctx,
    int       function,
    int       addr,
    int       nb,
    uint8_t*  req)
{
    req[0] = ctx->slave;
    req[1] = function;
    req[2] = addr >> 8;
    req[3] = addr & 0x00ff;
    req[4] = nb >> 8;
    req[5] = nb & 0x00ff;

    return _MODBUS_D2X_PRESET_REQ_LENGTH;
}

/* Builds a D2X response header */
static int _modbus_d2x_build_response_basis(
    sft_t*   sft,
    uint8_t* rsp)
{
    rsp[0] = sft->slave;
    rsp[1] = sft->function;

    return _MODBUS_D2X_PRESET_RSP_LENGTH;
}

static int _modbus_d2x_prepare_response_tid(
    const uint8_t* req,
    int*           req_length)
{
    (*req_length) -= _MODBUS_D2X_CHECKSUM_LENGTH;
    /* No TID */
    return 0;
}

static int _modbus_d2x_send_msg_pre(
    uint8_t* req,
    int      req_length)
{
    uint16_t crc = modbus_crc16(req, req_length);
    req[req_length++] = crc >> 8;
    req[req_length++] = crc & 0x00FF;

    return req_length;
}

static ssize_t _modbus_d2x_send(
    modbus_t*      ctx,
    const uint8_t* req,
    int            req_length)
{
    modbus_d2x_t*  ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
    FT_STATUS      status;
    DWORD          bytesWritten = 0;
    ssize_t        result;

    if (ctx_d2x->handle != NULL)
    {
        status = d2xWrite(ctx_d2x->handle, (LPVOID) req, req_length, &bytesWritten);
        result = (status == FT_OK ? bytesWritten : -1);
    }
    else
    {
        fprintf(stderr,
                "ERROR Can't write to the device: the device in not open\n");
        result = -1;
    }

    return result;
}

static ssize_t _modbus_d2x_recv(
    modbus_t*     ctx,
    uint8_t*      rsp,
    int           rsp_length)
{
    modbus_d2x_t* ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
    ssize_t result = d2x_read(ctx_d2x, rsp, (DWORD) rsp_length);
    return result;
}

static int _modbus_d2x_flush(modbus_t*);

/*
 *  The check_crc16 function shall return the message length if the CRC is
 *  valid. Otherwise it shall return -1 and set errno to EMBADCRC.
 */
static int _modbus_d2x_check_integrity(
    modbus_t* ctx,
    uint8_t*  msg,
    const int msg_length)
{
    uint16_t  crc_calculated;
    uint16_t  crc_received;
    int       result = msg_length;

    if (msg[1] == _FC_D2X_READ_SCAN)
        crc_calculated = 0xAAAA;
    else
        crc_calculated = modbus_crc16(msg, msg_length - 2);
    crc_received = (msg[msg_length - 2] << 8) | msg[msg_length - 1];

    /* Check CRC of msg */
    if (crc_calculated != crc_received)
    {

#if 0
{
    static int dumpNum = 0;
    char dumpName[256];
    sprintf(dumpName, "crc_msg_dump_%d.txt", dumpNum++);
    FILE* fp = fopen(dumpName, "w");
    int iii;
    for (iii = 0; iii < msg_length; iii++)
        fprintf(fp, "%02x\n", msg[iii]);
    fclose(fp);
}
#endif

        //if (ctx->debug)
        //{
            fprintf(stderr, "ERROR CRC received %0X != CRC calculated %0X\n",
                    crc_received, crc_calculated);
        //}

        if (ctx->error_recovery & MODBUS_ERROR_RECOVERY_PROTOCOL)
        {
            _modbus_d2x_flush(ctx);
        }

        errno = EMBBADCRC;
        result = -1;
    }

    return result;
}

/* Opens the D2XX device */
static int _modbus_d2x_connect(
    modbus_t*         ctx)
{
    modbus_d2x_t*     ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
    FT_HANDLE         handle;
    FT_STATUS         status;
    d2x_device_info_t info;
    int               result = -1;
#ifdef _WIN32
	int index;
#endif

    if (ctx->debug)
    {
        if (ctx_d2x->method == d2xOpenBySerialNum)
            printf("Opening device with serial number %s\n", ctx_d2x->device);
        else
            printf("Opening device with description %s\n", ctx_d2x->device);
    }

    status = d2xOpenEx(ctx_d2x->device, ctx_d2x->method, &handle);

    if (status == FT_OK)
    {
        result = 0;
        ctx->s = -1;
        ctx_d2x->handle = handle;
        memset((void*) &(ctx_d2x->buffer), 0, sizeof(ctx_d2x->buffer));
        ctx_d2x->nAvailable = 0;
        ctx_d2x->nUsed      = 0;

#ifndef _WIN32
		int
#endif
        index = modbus_get_d2x_device_info(ctx, &info);
        if (index >= 0)
        {
            ctx->s = index;

#if 0
            if (info.Type == 5 || info.Type == 6)
#else
            /*
               WARNING!  Kludge alert!
               At some point, FTDI changed the meaning of the chip type to include several
               disparate chips:  Some that have configurable baud and others that don't.
               Until we figure out how to distinguish between them, we will use the
               serial number to determine the type of chip we have in our products.
               This makes this library specific to our hardware and should be fixed.
            */
            if (strncmp(info.SerialNumber, (const char*) "SX", 2) != 0)
#endif
                d2xSetCommParams(handle, info.SerialNumber, info.Description, ctx_d2x->baud);

            if (ctx->debug)
            {
                printf("Opened device at index %d\n"
                       "  Serial No.  %s\n"
                       "  Description %s\n"
                       "  Flags       0x%08x\n"
                       "  Type        0x%08x\n"
                       "  ID          0x%08x\n"
                       "  LocID       0x%08x\n",
                       ctx->s,
                       info.SerialNumber,
                       info.Description,
                       (unsigned int) info.Flags,
                       (unsigned int) info.Type,
                       (unsigned int) info.ID,
                       (unsigned int) info.LocId);
            }
        }
        else
        {
            fprintf(stderr,
                    "WARNING Opened device %s "
                    "but cannot find it in the list of D2XX devices!\n",
                    ctx_d2x->device);
        }
    }

    return result;
}

static void _modbus_d2x_close(
    modbus_t*     ctx)
{
    modbus_d2x_t* ctx_d2x = (modbus_d2x_t*) ctx->backend_data;

    d2xClose(ctx_d2x->handle);
}

static int _modbus_d2x_flush(
    modbus_t*     ctx)
{
    modbus_d2x_t* ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
    FT_HANDLE     handle = ctx_d2x->handle;
    int           result = 0;

    FT_STATUS status = d2xPurge(handle);
    if (status != FT_OK)
        result = -1;

    return result;
}

static int _modbus_d2x_select(
    modbus_t*       ctx,
    fd_set*         unused_fdset,
    struct timeval* tv,
    int             length_to_read)
{
    modbus_d2x_t*   ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
    int result;

    result = d2x_select(ctx_d2x, length_to_read, tv);

    if (result == 0 && ctx_d2x->nAvailable == 0)
    {
        errno = ETIMEDOUT;
        result = -1;
    }

    return result;
}

static int _modbus_d2x_filter_request(
    modbus_t* ctx,
    int       slave)
{
    /* FIXME: I should care about slave id */
    return 0;
}

static uint8_t _modbus_d2x_compute_meta_length_after_function(
    int        function,
    msg_type_t msg_type)
{
    int        length;

    switch (function)
    {
      case _FC_D2X_READ_SCAN:
        /*
         * Req: 3x2-byte ints (start, stop, speed)
         * Rsp: none--response is variable length;
         *      the end is detected later by a specific byte pattern
         */
        length = (msg_type == MSG_INDICATION ? 6 : 0);
        break;

      default:
        length = _modbus_compute_meta_length_after_function(function, msg_type);
    }

    return length;
}

static int _modbus_d2x_compute_data_length_after_meta(
    modbus_t*  ctx,
    uint8_t*   msg,
    msg_type_t msg_type)
{
    int        length = 0;
    int        function = msg[ctx->backend->header_length];

    switch (function)
    {
      case _FC_D2X_READ_SCAN:
        /*
         * Req: 2-byte CRC
         * Rsp: 2-byte encoder value + 4-byte a2d value
         */
        length = (msg_type == MSG_INDICATION ? 2 : 6);
        break;

      default:
        length = _modbus_compute_data_length_after_meta(ctx, msg, msg_type);
    }

    return length;
}

static int _modbus_d2x_compute_additional_data_length(
    modbus_t*  ctx,
    uint8_t*   msg,
    msg_type_t msg_type,
    int        msg_length)
{
    int        length = 0;
    int        function = msg[ctx->backend->header_length];

    switch (function)
    {
      case _FC_D2X_READ_SCAN:
        /*
         * Req: none
         * Rsp: Are we there yet?  Look for the byte-pattern signaling the end of the response.
         *      If we don't see the pattern, we are still reading the response (look for 6 more
         *      data bytes).
         *      When we detect the byte-pattern the first time, we still need to read the CRC.
         *      (look for 2-byte CRC).
         *      After reading the CRC, we detect the pattern again to know we are finished
         *      (return 0).
         */
        if (msg_type == MSG_INDICATION)
            length = 0;
        else
        {
            if      (msg[msg_length - 6] == 0 && msg[msg_length - 5] == 0 && msg[msg_length - 4] == 0x80 &&
                     msg[msg_length - 3] == 0 && msg[msg_length - 2] == 0 && msg[msg_length - 1] ==    0  )
                length = 2;
            else if (msg[msg_length - 8] == 0 && msg[msg_length - 7] == 0 && msg[msg_length - 6] == 0x80 &&
                     msg[msg_length - 5] == 0 && msg[msg_length - 4] == 0 && msg[msg_length - 3] ==    0  )
                length = 0;
            else
                length = 6;
        }
        break;

      default:
        length = 0;
    }

    return length;
}

/*const*/ modbus_backend_t _modbus_d2x_backend =
{
    _MODBUS_BACKEND_TYPE_D2X,
    _MODBUS_D2X_HEADER_LENGTH,
    _MODBUS_D2X_CHECKSUM_LENGTH,
    MODBUS_D2X_DEFAULT_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_d2x_build_request_basis,
    _modbus_d2x_build_response_basis,
    _modbus_d2x_prepare_response_tid,
    _modbus_d2x_send_msg_pre,
    _modbus_d2x_send,
    _modbus_d2x_recv,
    _modbus_d2x_check_integrity,
    NULL,
    _modbus_d2x_connect,
    _modbus_d2x_close,
    _modbus_d2x_flush,
    _modbus_d2x_select,
    _modbus_d2x_filter_request,
    _modbus_compute_response_length_from_request,
    _modbus_d2x_compute_meta_length_after_function,
    _modbus_d2x_compute_data_length_after_meta,
    _modbus_d2x_compute_additional_data_length,
    _modbus_compute_numbers_of_values
};

static modbus_t* _modbus_new_d2x(
    const char*       device,
    int               baud,
    d2x_open_method_t method,
    int               bufSize)
{
    modbus_t*         ctx;
    modbus_d2x_t*     ctx_d2x;
    size_t            dest_size;
    size_t            ret_size;

    ctx = (modbus_t*) malloc(sizeof(modbus_t));
    _modbus_init_common(ctx);

    bufSize = (bufSize < MODBUS_D2X_DEFAULT_ADU_LENGTH ? MODBUS_D2X_DEFAULT_ADU_LENGTH : bufSize);

    ctx->req_buffer = (uint8_t *) malloc(bufSize * sizeof(uint8_t));
    ctx->rsp_buffer = (uint8_t *) malloc(bufSize * sizeof(uint8_t));

    ctx->backend = &_modbus_d2x_backend;
    ctx->backend_data = (modbus_d2x_t*) calloc(1, sizeof(modbus_d2x_t));
    ctx_d2x = (modbus_d2x_t*) ctx->backend_data;

    ctx_d2x->max_adu_length = bufSize;

    ctx_d2x->method = method;
    ctx_d2x->baud   = baud;

    dest_size = sizeof(ctx_d2x->device);
#ifdef _WIN32
	ret_size  = strncpy(ctx_d2x->device, device, dest_size);
#else
	ret_size  = strlcpy(ctx_d2x->device, device, dest_size);
#endif

    if (ret_size == 0)
    {
        fprintf(stderr, "The indentifying string is empty\n");
        errno = EINVAL;
        modbus_free(ctx);
        ctx = NULL;
    }
    else if (ret_size >= dest_size)
    {
        fprintf(stderr, "The indentifying string has been truncated\n");
        errno = EINVAL;
        modbus_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

modbus_t* modbus_new_d2x_by_serial_number_sized(
    const char* serialNum,
    int         baud,
    int         bufSize)
{
    return _modbus_new_d2x(serialNum, baud, d2xOpenBySerialNum, bufSize);
}

modbus_t* modbus_new_d2x_by_serial_number(
    const char* serialNum,
    int         baud)
{
    return _modbus_new_d2x(serialNum, baud, d2xOpenBySerialNum, MODBUS_D2X_DEFAULT_ADU_LENGTH);
}

modbus_t* modbus_new_d2x_by_description_sized(
    const char* description,
    int         baud,
    int         bufSize)
{
    return _modbus_new_d2x(description, baud, d2xOpenByDescription, bufSize);
}

modbus_t* modbus_new_d2x_by_description(
    const char* description,
    int         baud)
{
    return _modbus_new_d2x(description, baud, d2xOpenByDescription, MODBUS_D2X_DEFAULT_ADU_LENGTH);
}

#if 0
int modbus_d2x_set_baud(modbus_t* ctx, DWORD baud)
{
    int result = 0;
    modbus_d2x_t* ctx_d2x = (modbus_d2x_t*) ctx->backend_data;

    FT_STATUS status = FT_SetBaudRate(ctx_d2x->handle, baud);

    if (status != FT_OK)
    {
        fprintf(stderr, "ERROR Can't set the baud rate (%s)\n", strerror_d2x(status));
        result = -1;
    }

    return status;
}
#endif

int modbus_d2x_get_buffer_length(const modbus_t* ctx)
{
    modbus_d2x_t* ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
    return ctx_d2x->max_adu_length;
}

int modbus_d2x_read_scan(
    modbus_t*     ctx,
    int           start,
    int           stop,
    int           speed,
    int*          array,
    int*          pNumSteps)
{
    modbus_d2x_t* ctx_d2x = (modbus_d2x_t*) ctx->backend_data;
    int           rc;
    int           reqLen;
    int           idx;
    uint8_t*      req = ctx->req_buffer;
    uint8_t*      rsp = ctx->rsp_buffer;

    //uint32_t maxSteps = (ctx->backend->max_adu_length - 10) / 6;
    uint32_t maxSteps = (ctx_d2x->max_adu_length - 10) / 6;
    int numSteps = 0;

    if (stop > start)
        numSteps = stop - start + 1;
    else
        numSteps = start - stop + 1;

    if (numSteps > 0 && numSteps <= maxSteps)
    {
        req[0] = ctx->slave;
        req[1] = _FC_D2X_READ_SCAN;
        MODBUS_SET_INT16_TO_INT8(req, 2, start);
        MODBUS_SET_INT16_TO_INT8(req, 4, stop);
        MODBUS_SET_INT16_TO_INT8(req, 6, speed);
        reqLen = 8;

        rc = modbus_send_message(ctx, req, reqLen);
        if (rc > 0)
        {
#ifndef DEBUG_PRINT_SCAN_RESPONSE
            int save_debug = ctx->debug;
            ctx->debug = 0;
#endif
            rc = modbus_receive_confirmation(ctx, rsp);
#ifndef DEBUG_PRINT_SCAN_RESPONSE
            ctx->debug = save_debug;
#endif
            if (rc > 0) 
            {
                int src;
                int dst;
                numSteps = (rc - 10) / 6;
                *pNumSteps = numSteps;
                for (idx = 0; idx < numSteps; idx++)
                {
                    src = idx * 6;
                    dst = idx * 2;
                    array[dst    ] = (int) MODBUS_GET_INT16_FROM_INT8((rsp + 2), src);
                    array[dst + 1] = (int) MODBUS_GET_INT32_FROM_INT8_SWAPPED((rsp + 4), src);
                }
            }
            else
                fprintf(stderr, "ERROR modbus_receive_confirmation returned %d while scanning\n", rc);
        }
        else
            fprintf(stderr, "ERROR Could not send scan request\n");
    }
    else
    {
        fprintf(stderr, "ERROR Too many scan registers requested (%d > %d)\n", numSteps, maxSteps);
        errno = EMBMDATA;
        rc = -1;
    }

    return rc;
}

FT_HANDLE modbus_d2x_get_handle(modbus_t* ctx)
{
    return ((modbus_d2x_t*) (ctx->backend_data))->handle;
}
