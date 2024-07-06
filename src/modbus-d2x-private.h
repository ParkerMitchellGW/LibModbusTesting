/*
 * Copyright (c) 2011 Steve Elam <steven.elam@guided-wave.com>
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

#ifndef _MODBUS_D2X_PRIVATE_H_
#define _MODBUS_D2X_PRIVATE_H_

#define _MODBUS_D2X_HEADER_LENGTH      1
#define _MODBUS_D2X_PRESET_REQ_LENGTH  6
#define _MODBUS_D2X_PRESET_RSP_LENGTH  2

#define _MODBUS_D2X_CHECKSUM_LENGTH    2

typedef enum _d2x_open_method
{
    d2xOpenBySerialNum   = FT_OPEN_BY_SERIAL_NUMBER,
    d2xOpenByDescription = FT_OPEN_BY_DESCRIPTION
} d2x_open_method_t;
typedef FT_HANDLE d2x_handle_t;

// According to FTDI.com, the optimal read request size should be a multiple
// of 3968 bytes for the default USB buffer size of 4K bytes.
#define _D2X_BUF_SIZE 3968

typedef struct _modbus_d2x
{
    unsigned int      max_adu_length;
    char              device[64];
    d2x_open_method_t method;
    int               baud;
    d2x_handle_t      handle;
	uint8_t           buffer[_D2X_BUF_SIZE];
    DWORD             nAvailable;
    DWORD             nUsed;
} modbus_d2x_t;

#endif /* _MODBUS_D2X_PRIVATE_H_ */
