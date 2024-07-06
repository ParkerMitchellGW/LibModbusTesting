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

#ifndef _MODBUS_D2X_H_
#define _MODBUS_D2X_H_

#include <windows.h>
#ifdef __CYGWIN__
#undef _WIN32
#endif
#include <ftdi/ftd2xx.h>

#define D2X_CHUNK_SIZE 3968
#define MODBUS_D2X_DEFAULT_ADU_LENGTH D2X_CHUNK_SIZE

/* GWI-defined function codes */
#define _FC_D2X_READ_SCAN 0x64

modbus_t* modbus_new_d2x_by_serial_number_sized(const char* serialNum, int baud, int bufSize);
modbus_t* modbus_new_d2x_by_serial_number(const char* serialNum, int baud);
modbus_t* modbus_new_d2x_by_description_sized(const char* description, int baud, int bufSize);
modbus_t* modbus_new_d2x_by_description(const char* description, int baud);

/*int modbus_d2x_set_baud(modbus_t* ctx, DWORD baud);*/

int modbus_d2x_get_buffer_length(const modbus_t* ctx);

int modbus_d2x_read_scan(modbus_t* ctx, int start, int stop, int speed, int* array, int* pNumSteps);

typedef FT_DEVICE_LIST_INFO_NODE d2x_device_info_t;

d2x_device_info_t* modbus_get_d2x_device_info_list(LPDWORD pNumDevices);
int modbus_get_d2x_device_info(modbus_t* ctx, d2x_device_info_t* pInfo);

FT_HANDLE modbus_d2x_get_handle(modbus_t* ctx);

#endif /* _MODBUS_D2X_H_ */
