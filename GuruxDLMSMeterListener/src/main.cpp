//
// --------------------------------------------------------------------------
//  Gurux Ltd
//
//
//
// Filename:        $HeadURL$
//
// Version:         $Revision$,
//                  $Date$
//                  $Author$
//
// Copyright (c) Gurux Ltd
//
//---------------------------------------------------------------------------
//
//  DESCRIPTION
//
// This file is a part of Gurux Device Framework.
//
// Gurux Device Framework is Open Source software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2 of the License.
// Gurux Device Framework is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// More information of Gurux products: http://www.gurux.org
//
// This code is licensed under the GNU General Public License v2.
// Full text may be retrieved at http://www.gnu.org/licenses/gpl-2.0.txt
//---------------------------------------------------------------------------
#if defined(_WIN32) || defined(_WIN64)//Windows includes
#include <tchar.h>
#include <conio.h>
#include <Winsock.h> //Add support for sockets
#include <time.h>
#include <process.h>//Add support for threads
#include "../include/getopt.h"
//Windows doesn't implement strcasecmp. It uses strcmpi.
#define strcasecmp _strcmpi
#else //Linux includes.
#define closesocket close
#include <unistd.h>
#include <pthread.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h> //Add support for sockets
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <strings.h>
#endif
#include "../include/GXDLMSMeterListener.h"
#include "../../development/include/GXDLMSClock.h"

static void ShowHelp()
{
    printf("GuruxDlmsMeterListener waits connections from DLMS/COSEM meter and then reads them.\r\n");
    printf("GuruxDlmsMeterListener -p [Meter Port No] -c 16 -s 1\r\n");
    printf(" -p \t port number or name (Example: 1000).\r\n");
    printf(" -a \t Authentication (None, Low, High, HighMd5, HighSha1, HighGmac, HighSha256).\r\n");
    printf(" -P \t Password for authentication.\r\n");
    printf(" -c \t Client address. (Default: 16)\r\n");
    printf(" -s \t Server address. (Default: 1)\r\n");
    printf(" -n \t Server address as serial number.\r\n");
    printf(" -r [sn, sn]\t Short name or Logican Name (default) referencing is used.\r\n");
    printf(" -w WRAPPER profile is used. HDLC is default.\r\n");
    printf(" -t Trace messages.\r\n");
    printf(" -g \"0.0.1.0.0.255:1; 0.0.1.0.0.255:2\" Get selected object(s) with given attribute index.\r\n");
    printf(" -C \t Security Level. (None, Authentication, Encrypted, AuthenticationEncryption)");
    printf(" -v \t Invocation counter data object Logical Name. Ex. 0.0.43.1.1.255");
    printf(" -I \t Auto increase invoke ID");
    printf(" -o \t Cache association view to make reading faster. Ex. -o C:\\device.xml");
    printf(" -T \t System title that is used with chiphering. Ex -T 4775727578313233");
    printf(" -A \t Authentication key that is used with chiphering. Ex -A D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF");
    printf(" -B \t Block cipher key that is used with chiphering. Ex -B 000102030405060708090A0B0C0D0E0F");
    printf(" -D \t Dedicated key that is used with chiphering. Ex -D 00112233445566778899AABBCCDDEEFF");
    printf("Example:\r\n");
    printf("Read LG device using TCP/IP connection.\r\n");
    printf("GuruxDlmsMeterListener -r SN -c 16 -s 1 -p [Meter Port No]\r\n");
}

#if defined(_WIN32) || defined(_WIN64)//Windows includes
int _tmain(int argc, _TCHAR* argv[])
#else
int main(int argc, char* argv[])
#endif
{
#if defined(_WIN32) || defined(_WIN64)//Windows includes
    //Use user locale settings. This is causing errors in some Linux distros. Example Fedora
    std::locale::global(std::locale(""));
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        // Tell the user that we could not find a usable WinSock DLL.
        return 1;
    }
#endif
    //Remove trace file if exists.
    remove("trace.txt");
    remove("LogFile.txt");
    int ret;
    GX_TRACE_LEVEL trace = GX_TRACE_LEVEL_INFO;
    bool useLogicalNameReferencing = true;
    int clientAddress = 16, serverAddress = 1;
    DLMS_AUTHENTICATION authentication = DLMS_AUTHENTICATION_NONE;
    DLMS_INTERFACE_TYPE interfaceType = DLMS_INTERFACE_TYPE_HDLC;
    DLMS_SECURITY security = DLMS_SECURITY_NONE;
    char* password = NULL;
    char* p, * readObjects = NULL;
    int index, a, b, c, d, e, f;
    int opt = 0;
    int port = 0;
    char* address = NULL;
    char* serialPort = NULL;
    bool iec = false;
    bool autoIncreaseInvokeID = false;
    char* invocationCounter = NULL;
    char* outputFile = NULL;
    char* systemTitle = NULL;
    char* authenticationKey = NULL;
    char* blockCipherKey = NULL;
    char* dedicatedKey = NULL;

    while ((opt = getopt(argc, argv, "h:p:c:s:r:iIt:a:wP:g:S:n:C:v:o:T:A:B:D:")) != -1)
    {
        switch (opt)
        {
        case 'w':
            interfaceType = DLMS_INTERFACE_TYPE_WRAPPER;
            break;
        case 'r':
            if (strcasecmp("sn", optarg) == 0)
            {
                useLogicalNameReferencing = false;
            }
            else if (strcasecmp("ln", optarg) == 0)
            {
                useLogicalNameReferencing = 1;
            }
            else
            {
                printf("Invalid reference option.\n");
                return 1;
            }
            break;
        case 'h':
            //Host address.
            address = optarg;
            break;
        case 't':
            //Trace.
            if (strcasecmp("Error", optarg) == 0)
                trace = GX_TRACE_LEVEL_ERROR;
            else  if (strcasecmp("Warning", optarg) == 0)
                trace = GX_TRACE_LEVEL_WARNING;
            else  if (strcasecmp("Info", optarg) == 0)
                trace = GX_TRACE_LEVEL_INFO;
            else  if (strcasecmp("Verbose", optarg) == 0)
                trace = GX_TRACE_LEVEL_VERBOSE;
            else  if (strcasecmp("Off", optarg) == 0)
                trace = GX_TRACE_LEVEL_OFF;
            else
            {
                printf("Invalid trace option '%s'. (Error, Warning, Info, Verbose, Off)", optarg);
                return 1;
            }
            break;
        case 'p':
            //Port.
            port = atoi(optarg);
            break;
        case 'P':
            password = optarg;
            break;
        case 'i':
            //IEC.
            iec = 1;
            break;
        case 'I':
            // AutoIncreaseInvokeID.
            autoIncreaseInvokeID = true;
            break;
        case 'C':
            if (strcasecmp("None", optarg) == 0)
            {
                security = DLMS_SECURITY_NONE;
            }
            else if (strcasecmp("Authentication", optarg) == 0)
            {
                security = DLMS_SECURITY_AUTHENTICATION;
            }
            else if (strcasecmp("Encryption", optarg) == 0)
            {
                security = DLMS_SECURITY_ENCRYPTION;
            }
            else if (strcasecmp("AuthenticationEncryption", optarg) == 0)
            {
                security = DLMS_SECURITY_AUTHENTICATION_ENCRYPTION;
            }
            else
            {
                printf("Invalid Ciphering option '%s'. (None, Authentication, Encryption, AuthenticationEncryption)", optarg);
                return 1;
            }
            break;
        case 'T':
            systemTitle = optarg;
            break;
        case 'A':
            authenticationKey = optarg;
            break;
        case 'B':
            blockCipherKey = optarg;
            break;
        case 'D':
            dedicatedKey = optarg;
            break;
        case 'o':
            outputFile = optarg;
            break;
        case 'v':
            invocationCounter = optarg;
#if defined(_WIN32) || defined(_WIN64)//Windows
            if ((ret = sscanf_s(optarg, "%d.%d.%d.%d.%d.%d", &a, &b, &c, &d, &e, &f)) != 6)
#else
            if ((ret = sscanf(optarg, "%d.%d.%d.%d.%d.%d", &a, &b, &c, &d, &e, &f)) != 6)
#endif
            {
                ShowHelp();
                return 1;
            }
            break;
        case 'g':
            //Get (read) selected objects.
            p = optarg;
            do
            {
                if (p != optarg)
                {
                    ++p;
                }
#if defined(_WIN32) || defined(_WIN64)//Windows
                if ((ret = sscanf_s(p, "%d.%d.%d.%d.%d.%d:%d", &a, &b, &c, &d, &e, &f, &index)) != 7)
#else
                if ((ret = sscanf(p, "%d.%d.%d.%d.%d.%d:%d", &a, &b, &c, &d, &e, &f, &index)) != 7)
#endif
                {
                    ShowHelp();
                    return 1;
                }
            } while ((p = strchr(p, ',')) != NULL);
            readObjects = optarg;
            break;
        case 'S':
            serialPort = optarg;
            break;
        case 'a':
            if (strcasecmp("None", optarg) == 0)
            {
                authentication = DLMS_AUTHENTICATION_NONE;
            }
            else if (strcasecmp("Low", optarg) == 0)
            {
                authentication = DLMS_AUTHENTICATION_LOW;
            }
            else if (strcasecmp("High", optarg) == 0)
            {
                authentication = DLMS_AUTHENTICATION_HIGH;
            }
            else if (strcasecmp("HighMd5", optarg) == 0)
            {
                authentication = DLMS_AUTHENTICATION_HIGH_MD5;
            }
            else if (strcasecmp("HighSha1", optarg) == 0)
            {
                authentication = DLMS_AUTHENTICATION_HIGH_SHA1;
            }
            else if (strcasecmp("HighGmac", optarg) == 0)
            {
                authentication = DLMS_AUTHENTICATION_HIGH_GMAC;
            }
            else if (strcasecmp("HighSha256", optarg) == 0)
            {
                authentication = DLMS_AUTHENTICATION_HIGH_SHA256;
            }
            else
            {
                printf("Invalid Authentication option. (None, Low, High, HighMd5, HighSha1, HighGmac, HighSha256)\n");
                return 1;
            }
            break;
        case 'c':
            clientAddress = atoi(optarg);
            break;
        case 's':
            serverAddress = atoi(optarg);
            break;
        case 'n':
            serverAddress = CGXDLMSClient::GetServerAddressFromSerialNumber(atoi(optarg), 1);
            break;
        case '?':
        {
            if (optarg[0] == 'c') {
                printf("Missing mandatory client option.\n");
            }
            else if (optarg[0] == 's') {
                printf("Missing mandatory server option.\n");
            }
            else if (optarg[0] == 'h') {
                printf("Missing mandatory host name option.\n");
            }
            else if (optarg[0] == 'p') {
                printf("Missing mandatory port option.\n");
            }
            else if (optarg[0] == 'r') {
                printf("Missing mandatory reference option.\n");
            }
            else if (optarg[0] == 'a') {
                printf("Missing mandatory authentication option.\n");
            }
            else if (optarg[0] == 'S') {
                printf("Missing mandatory Serial port option.\n");
            }
            else if (optarg[0] == 'g') {
                printf("Missing mandatory OBIS code option.\n");
            }
            else if (optarg[0] == 'C') {
                printf("Missing mandatory Ciphering option.\n");
            }
            else if (optarg[0] == 'v') {
                printf("Missing mandatory invocation counter logical name option.\n");
            }
            else if (optarg[0] == 'T') {
                printf("Missing mandatory system title option.");
            }
            else if (optarg[0] == 'A') {
                printf("Missing mandatory authentication key option.");
            }
            else if (optarg[0] == 'B') {
                printf("Missing mandatory block cipher key option.");
            }
            else if (optarg[0] == 'D') {
                printf("Missing mandatory dedicated key option.");
            }
            else
            {
                ShowHelp();
                return 1;
            }
        }
        break;
        default:
            ShowHelp();
            return 1;
        }
    }
    CGXDLMSMeterListener meterListener(useLogicalNameReferencing, clientAddress, serverAddress, authentication, password, interfaceType, security, systemTitle, authenticationKey,
        blockCipherKey, dedicatedKey, trace, invocationCounter);
    ///////////////////////////////////////////////////////////////////////
    //Start listen events.
    ret = meterListener.StartServer(port);
    printf("Listening DLMS Push IEC 62056-47 messages on port %d.\n", port);
    int key = 0;
    if (ret == 0)
    {
        printf("Press Enter to close the server.\r\n");
        getchar();
        printf("Closing the server.\r\n");
        meterListener.StopServer();
    }
#if defined(_WIN32) || defined(_WIN64)//Windows
    WSACleanup();
#if _MSC_VER > 1400
    _CrtDumpMemoryLeaks();
#endif
#endif

    return 0;
}

