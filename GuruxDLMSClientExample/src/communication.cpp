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

#include "../include/communication.h"
#include "../../development/include/GXDLMSConverter.h"
#include "../../development/include/GXDLMSProfileGeneric.h"
#include "../../development/include/GXDLMSDemandRegister.h"
#include "../../development/include/GXDLMSTranslator.h"
#include "../../development/include/GXDLMSData.h"

void CGXCommunication::WriteValue(GX_TRACE_LEVEL trace, std::string line)
{
    if (trace > GX_TRACE_LEVEL_WARNING)
    {
        printf("%s", line.c_str());
    }
    GXHelpers::Write("LogFile.txt", line);
}


CGXCommunication::CGXCommunication(CGXDLMSSecureClient* pParser, uint16_t wt, GX_TRACE_LEVEL trace, char* invocationCounter) :
    m_WaitTime(wt), m_Parser(pParser),
    m_socket(-1), m_Trace(trace), m_InvocationCounter(invocationCounter)
{
#if defined(_WIN32) || defined(_WIN64)//Windows includes
    ZeroMemory(&m_osReader, sizeof(OVERLAPPED));
    ZeroMemory(&m_osWrite, sizeof(OVERLAPPED));
    m_osReader.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_osWrite.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
#endif
    m_hComPort = INVALID_HANDLE_VALUE;
}

CGXCommunication::~CGXCommunication(void)
{
    Close();
}

//Close connection to the meter.
int CGXCommunication::Disconnect()
{
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    if (m_hComPort != INVALID_HANDLE_VALUE || m_socket != -1)
    {
        if ((ret = m_Parser->DisconnectRequest(data)) != 0 ||
            (ret = ReadDataBlock(data, reply)) != 0)
        {
            //Show error but continue close.
            printf("DisconnectRequest failed (%d) %s.\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
        }
    }
    return 0;
}

//Release connection to the meter.
int CGXCommunication::Release()
{
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    if (m_hComPort != INVALID_HANDLE_VALUE || m_socket != -1)
    {
        if ((ret = m_Parser->ReleaseRequest(data)) != 0 ||
            (ret = ReadDataBlock(data, reply)) != 0)
        {
            //Show error but continue close.
            printf("DisconnectRequest failed (%d) %s.\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
        }
    }
    return 0;
}

//Close connection to the meter and close the communcation channel.
int CGXCommunication::Close()
{
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    if ((m_hComPort != INVALID_HANDLE_VALUE || m_socket != -1) &&
        (m_Parser->GetInterfaceType() == DLMS_INTERFACE_TYPE_WRAPPER ||
            m_Parser->GetCiphering()->GetSecurity() != DLMS_SECURITY_NONE))
    {
        if ((ret = m_Parser->ReleaseRequest(data)) != 0 ||
            (ret = ReadDataBlock(data, reply)) != 0)
        {
            //Show error but continue close.
            printf("ReleaseRequest failed (%d) %s.\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
        }
    }
    if (m_hComPort != INVALID_HANDLE_VALUE || m_socket != -1)
    {
        if ((ret = m_Parser->DisconnectRequest(data)) != 0 ||
            (ret = ReadDataBlock(data, reply)) != 0)
        {
            //Show error but continue close.
            printf("DisconnectRequest failed (%d) %s.\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
        }
    }
    if (m_hComPort != INVALID_HANDLE_VALUE)
    {
#if defined(_WIN32) || defined(_WIN64)//Windows includes
        CloseHandle(m_hComPort);
        CloseHandle(m_osReader.hEvent);
        CloseHandle(m_osWrite.hEvent);
#else
        close(m_hComPort);
#endif
        m_hComPort = INVALID_HANDLE_VALUE;
    }
    if (m_socket != -1)
    {
#if defined(_WIN32) || defined(_WIN64)//Windows includes
        closesocket(m_socket);
#else
        close(m_socket);
#endif
        m_socket = -1;
    }
    return 0;
}

bool IsIPv6Address(const char* pAddress)
{
    return strstr(pAddress, ":") != NULL;
}

//Make TCP/IP connection to the meter.
int CGXCommunication::Connect(const char* pAddress, unsigned short Port)
{
    int ret;
    Close();
    //create socket.
    int family = IsIPv6Address(pAddress) ? AF_INET6 : AF_INET;
    m_socket = socket(family, SOCK_STREAM, IPPROTO_IP);
    if (m_socket == -1)
    {
#if defined(_WIN32) || defined(_WIN64)//If Windows
        ret = WSAGetLastError();
#else
        ret = errno;
#endif
        return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
    }
    sockaddr* add;
    int addSize;
    sockaddr_in6 addrIP6;
    sockaddr_in addIP4;
    if (family == AF_INET)
    {
        addIP4.sin_port = htons(Port);
        addIP4.sin_family = AF_INET;
        addIP4.sin_addr.s_addr = inet_addr(pAddress);
        addSize = sizeof(sockaddr_in);
        add = (sockaddr*)&addIP4;
        //If address is give as name
        if (addIP4.sin_addr.s_addr == INADDR_NONE)
        {
            hostent* Hostent = gethostbyname(pAddress);
            if (Hostent == NULL)
            {
#if defined(_WIN32) || defined(_WIN64)//If Windows
                ret = WSAGetLastError();
#else
                ret = errno;
#endif
                Close();
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
            };
            addIP4.sin_addr = *(in_addr*)(void*)Hostent->h_addr_list[0];
        };
    }
    else
    {
        memset(&addrIP6, 0, sizeof(sockaddr_in6));
        addrIP6.sin6_port = htons(Port);
        addrIP6.sin6_family = AF_INET6;
        ret = inet_pton(family, pAddress, &(addrIP6.sin6_addr));
        if (ret == -1)
        {
#if defined(_WIN32) || defined(_WIN64)//If Windows
            ret = WSAGetLastError();
#else
            ret = errno;
#endif
            Close();
            return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
        };
        add = (sockaddr*)&addrIP6;
        addSize = sizeof(sockaddr_in6);
    }

    //Set timeout.
#if defined(_WIN32) || defined(_WIN64)//If Windows
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&m_WaitTime, sizeof(m_WaitTime));
#else
    struct timeval tv;
    tv.tv_sec = m_WaitTime / 1000;
    tv.tv_usec = 0;
    setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
#endif //
    //Connect to the meter.
    ret = connect(m_socket, add, addSize);
    if (ret == -1)
    {
#if defined(_WIN32) || defined(_WIN64)//If Windows
        ret = WSAGetLastError();
#else
        ret = errno;
#endif
        Close();
        return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
    };
    return DLMS_ERROR_CODE_OK;
}

#if defined(_WIN32) || defined(_WIN64)//Windows
int CGXCommunication::GXGetCommState(HANDLE hWnd, LPDCB dcb)
{
    ZeroMemory(dcb, sizeof(DCB));
    dcb->DCBlength = sizeof(DCB);
    if (!GetCommState(hWnd, dcb))
    {
        DWORD err = GetLastError(); //Save occured error.
        if (err == 995)
        {
            COMSTAT comstat;
            unsigned long RecieveErrors;
            if (!ClearCommError(hWnd, &RecieveErrors, &comstat))
            {
                return GetLastError();
            }
            if (!GetCommState(hWnd, dcb))
            {
                return GetLastError(); //Save occured error.
            }
        }
        else
        {
            //If USB to serial port converters do not implement this.
            if (err != ERROR_INVALID_FUNCTION)
            {
                return err;
            }
        }
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXCommunication::GXSetCommState(HANDLE hWnd, LPDCB DCB)
{
    if (!SetCommState(hWnd, DCB))
    {
        DWORD err = GetLastError(); //Save occured error.
        if (err == 995)
        {
            COMSTAT comstat;
            unsigned long RecieveErrors;
            if (!ClearCommError(hWnd, &RecieveErrors, &comstat))
            {
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | GetLastError();
            }
            if (!SetCommState(hWnd, DCB))
            {
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | GetLastError();
            }
        }
        else
        {
            //If USB to serial port converters do not implement this.
            if (err != ERROR_INVALID_FUNCTION)
            {
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | err;
            }
        }
    }
    return DLMS_ERROR_CODE_OK;
}

#endif //Windows

int CGXCommunication::Read(unsigned char eop, CGXByteBuffer& reply)
{
#if defined(_WIN32) || defined(_WIN64)//Windows
    unsigned long RecieveErrors;
    COMSTAT comstat;
    DWORD bytesRead = 0;
#else //If Linux.
    unsigned short bytesRead = 0;
    int ret, readTime = 0;
#endif
    int pos;
    unsigned long cnt = 1;
    bool bFound = false;
    int lastReadIndex = reply.GetPosition();
    do
    {
#if defined(_WIN32) || defined(_WIN64)//Windows
        //We do not want to read byte at the time.
        if (!ClearCommError(m_hComPort, &RecieveErrors, &comstat))
        {
            return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | WSAGetLastError();
        }
        bytesRead = 0;
        cnt = 1;
        //Try to read at least one byte.
        if (comstat.cbInQue > 0)
        {
            cnt = comstat.cbInQue;
        }
        //If there is more data than can fit to buffer.
        if (cnt > RECEIVE_BUFFER_SIZE)
        {
            cnt = RECEIVE_BUFFER_SIZE;
        }
        if (!ReadFile(m_hComPort, m_Receivebuff, cnt, &bytesRead, &m_osReader))
        {
            DWORD nErr = GetLastError();
            if (nErr != ERROR_IO_PENDING)
            {
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | WSAGetLastError();
            }
            //Wait until data is actually read
            if (::WaitForSingleObject(m_osReader.hEvent, m_WaitTime) != WAIT_OBJECT_0)
            {
                return DLMS_ERROR_CODE_RECEIVE_FAILED;
            }
            if (!GetOverlappedResult(m_hComPort, &m_osReader, &bytesRead, TRUE))
            {
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | WSAGetLastError();
            }
        }
#else
        //Get bytes available.
        ret = ioctl(m_hComPort, FIONREAD, &cnt);
        //If driver is not supporting this functionality.
        if (ret < 0)
        {
            cnt = RECEIVE_BUFFER_SIZE;
        }
        else if (cnt == 0)
        {
            //Try to read at least one byte.
            cnt = 1;
        }
        //If there is more data than can fit to buffer.
        if (cnt > RECEIVE_BUFFER_SIZE)
        {
            cnt = RECEIVE_BUFFER_SIZE;
        }
        bytesRead = read(m_hComPort, m_Receivebuff, cnt);
        if (bytesRead == 0xFFFF)
        {
            //If wait time has elapsed.
            if (errno == EAGAIN)
            {
                if (readTime > m_WaitTime)
                {
                    printf("Read failed. Timeout occurred.\n");
                    return DLMS_ERROR_CODE_RECEIVE_FAILED;
                }
                readTime += 100;
                bytesRead = 0;
            }
            //If connection is closed.
            else if (errno == EBADF)
            {
                printf("Read failed. Connection closed.\n");
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | errno;
            }
            else
            {
                printf("Read failed. %d.\n", errno);
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | errno;
            }
        }
#endif
        reply.Set(m_Receivebuff, bytesRead);
        //Note! Some USB converters can return true for ReadFile and Zero as bytesRead.
        //In that case wait for a while and read again.
        if (bytesRead == 0)
        {
#if defined(_WIN32) || defined(_WIN64)//Windows
            Sleep(100);
#else
            usleep(100000);
#endif
            continue;
        }
        if (reply.GetSize() > 5)
        {
            //Some optical strobes can return extra bytes.
            for (pos = reply.GetSize() - 1; pos != lastReadIndex; --pos)
            {
                if (reply.GetData()[pos] == eop)
                {
                    bFound = true;
                    break;
                }
            }
            lastReadIndex = pos;
        }
    } while (!bFound);
    return DLMS_ERROR_CODE_OK;
}

//Open serial port.
int CGXCommunication::Open(const char* settings, bool iec, int maxBaudrate)
{
    Close();
    unsigned short baudRate;
#if defined(_WIN32) || defined(_WIN64)
    unsigned char parity;
#else //Linux
    int parity;
#endif
    unsigned char stopBits, dataBits = 8;
    std::string port;
    port = settings;
    std::vector< std::string > tmp = GXHelpers::Split(port, ':');
    std::string tmp2;
    port.clear();
    port = tmp[0];
    if (tmp.size() > 1)
    {
        baudRate = atoi(tmp[1].c_str());
        dataBits = atoi(tmp[2].substr(0, 1).c_str());
        tmp2 = tmp[2].substr(1, tmp[2].size() - 2);
        if (tmp2.compare("None") == 0)
        {
#if defined(_WIN32) || defined(_WIN64)
            parity = NOPARITY;
#else //Linux
            parity = 0;
#endif
        }
        else if (tmp2.compare("Odd") == 0)
        {
#if defined(_WIN32) || defined(_WIN64)
            parity = ODDPARITY;
#else //Linux
            parity = PARENB | PARODD;
#endif
        }
        else if (tmp2.compare("Even") == 0)
        {
#if defined(_WIN32) || defined(_WIN64)
            parity = EVENPARITY;
#else //Linux
            parity = PARENB | PARENB;
#endif
        }
        else if (tmp2.compare("Mark") == 0)
        {
#if defined(_WIN32) || defined(_WIN64)
            parity = MARKPARITY;
#else //Linux
            parity = PARENB | PARODD | CMSPAR;
#endif
        }
        else if (tmp2.compare("Space") == 0)
        {
#if defined(_WIN32) || defined(_WIN64)
            parity = SPACEPARITY;
#else //Linux
            parity = PARENB | CMSPAR;
#endif
        }
        else
        {
            printf("Invalid parity :\"%s\"\n", tmp2.c_str());
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        stopBits = atoi(tmp[2].substr(tmp[2].size() - 1, 1).c_str());
    }
    else
    {
#if defined(_WIN32) || defined(_WIN64)
        baudRate = 9600;
        parity = NOPARITY;
        stopBits = ONESTOPBIT;
#else
        baudRate = B9600;
        parity = 0;
        stopBits = 0;
#endif
        dataBits = 8;
    }

    CGXByteBuffer reply;
    int ret, len, pos;
    unsigned char ch;
    //In Linux serial port name might be very long.
    char buff[50];
#if defined(_WIN32) || defined(_WIN64)
    DCB dcb = { 0 };
    unsigned long sendSize = 0;
#if _MSC_VER > 1000
    sprintf_s(buff, 50, "\\\\.\\%s", port.c_str());
#else
    sprintf(buff, "\\\\.\\%s", port.c_str());
#endif
    //Open serial port for read / write. Port can't share.
    m_hComPort = CreateFileA(buff,
        GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (m_hComPort == INVALID_HANDLE_VALUE)
    {
        ret = WSAGetLastError();
        printf("Failed to open serial port: \"%s\"\n", port.c_str());
        return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
    }
    dcb.DCBlength = sizeof(DCB);
    if ((ret = GXGetCommState(m_hComPort, &dcb)) != 0)
    {
        return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
    }
    dcb.fBinary = 1;
    dcb.fOutX = dcb.fInX = 0;
    //Abort all reads and writes on Error.
    dcb.fAbortOnError = 1;
    if (iec)
    {
        dcb.BaudRate = 300;
        dcb.StopBits = ONESTOPBIT;
        dcb.Parity = EVENPARITY;
        dcb.ByteSize = 7;
    }
    else
    {
        dcb.BaudRate = baudRate;
        dcb.ByteSize = dataBits;
        dcb.StopBits = stopBits;
        dcb.Parity = parity;
    }
    if ((ret = GXSetCommState(m_hComPort, &dcb)) != 0)
    {
        return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
    }
#else //#if defined(__LINUX__)
    struct termios options;
    // read/write | not controlling term | don't wait for DCD line signal.
    m_hComPort = open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (m_hComPort == -1) // if open is unsuccessful.
    {
        ret = errno;
        printf("Failed to open serial port: \"%s\"\n", port.c_str());
        return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
    }
    else
    {
        if (!isatty(m_hComPort))
        {
            ret = errno;
            printf("Failed to Open port. This is not a serial port.\n");
            return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
        }
        memset(&options, 0, sizeof(options));
        options.c_iflag = 0;
        options.c_oflag = 0;
        if (iec)
        {
            options.c_cflag |= PARENB;
            options.c_cflag &= ~PARODD;
            options.c_cflag &= ~CSTOPB;
            options.c_cflag &= ~CSIZE;
            options.c_cflag |= CS7;
            //Set Baud Rates
            cfsetospeed(&options, B300);
            cfsetispeed(&options, B300);
        }
        else
        {
            // 8n1, see termios.h for more information
            options.c_cflag = CS8 | CREAD | CLOCAL;
            options.c_cflag |= parity;
            /*
            options.c_cflag &= ~PARENB
            options.c_cflag &= ~CSTOPB
            options.c_cflag &= ~CSIZE;
            options.c_cflag |= CS8;
            */
            //Set Baud Rates
            cfsetospeed(&options, B9600);
            cfsetispeed(&options, B9600);
        }
        options.c_lflag = 0;
        options.c_cc[VMIN] = 1;
        //How long we are waiting reply charachter from serial port.
        options.c_cc[VTIME] = m_WaitTime / 1000;
        //hardware flow control is used as default.
        //options.c_cflag |= CRTSCTS;
        if (tcsetattr(m_hComPort, TCSAFLUSH, &options) != 0)
        {
            ret = errno;
            printf("Failed to Open port. tcsetattr failed.\n");
            return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
        }
    }
#endif
    if (iec)
    {
#if _MSC_VER > 1000
        strcpy_s(buff, 50, "/?!\r\n");
#else
        strcpy(buff, "/?!\r\n");
#endif
        len = (int)strlen(buff);
        if (m_Trace > GX_TRACE_LEVEL_WARNING)
        {
            printf("\nTX:\t");
            for (pos = 0; pos != len; ++pos)
            {
                printf("%.2X ", buff[pos]);
            }
            printf("\n");
        }
#if defined(_WIN32) || defined(_WIN64)
        ret = WriteFile(m_hComPort, buff, len, &sendSize, &m_osWrite);
        if (ret == 0)
        {
            ret = GetLastError();
            //If error occurs...
            if (ret != ERROR_IO_PENDING)
            {
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
            }
            //Wait until data is actually sent
            WaitForSingleObject(m_osWrite.hEvent, INFINITE);
        }
#else //#if defined(__LINUX__)
        ret = write(m_hComPort, buff, len);
        if (ret != len)
        {
            ret = errno;
            printf("write failed %d\n", ret);
            return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
        }
#endif
        //Read reply data.
        if (Read('\n', reply) != 0)
        {
            return DLMS_ERROR_CODE_RECEIVE_FAILED;
        }
        //Remove echo.
        if (reply.Compare((unsigned char*)buff, len))
        {
            if (Read('\n', reply) != 0)
            {
                return DLMS_ERROR_CODE_RECEIVE_FAILED;
            }
        }

        if (m_Trace > GX_TRACE_LEVEL_WARNING)
        {
            printf("RX:\t%s\n", reply.ToHexString().c_str());
        }
        if (reply.GetUInt8(&ch) != 0 || ch != '/')
        {
            //Send disc
            buff[0] = 1;
            buff[1] = 'B';
            buff[2] = '0';
            buff[3] = 3;
            buff[4] = '\r';
            buff[5] = '\n';
            len = 6;
#if defined(_WIN32) || defined(_WIN64)
            ret = WriteFile(m_hComPort, buff, len, &sendSize, &m_osWrite);
            if (ret == 0)
            {
                DWORD err = GetLastError();
                //If error occurs...
                if (err != ERROR_IO_PENDING)
                {
                    return DLMS_ERROR_CODE_SEND_FAILED;
                }
                //Wait until data is actually sent
                WaitForSingleObject(m_osWrite.hEvent, INFINITE);
            }
#else //#if defined(__LINUX__)
            ret = write(m_hComPort, buff, len);
            if (ret != len)
            {
                printf("write failed %d\n", errno);
                return DLMS_ERROR_CODE_SEND_FAILED;
            }
#endif
            if (Read('\n', reply) != 0)
            {
                return DLMS_ERROR_CODE_SEND_FAILED;
            }
            return DLMS_ERROR_CODE_SEND_FAILED;
        }
        //Get used baud rate.
        if ((ret = reply.GetUInt8(reply.GetPosition() + 3, &ch)) != 0)
        {
            return DLMS_ERROR_CODE_SEND_FAILED;
        }
        switch (ch)
        {
        case '0':
#if defined(_WIN32) || defined(_WIN64)
            baudRate = 300;
#else
            baudRate = B300;
#endif
            break;
        case '1':
#if defined(_WIN32) || defined(_WIN64)
            baudRate = 600;
#else
            baudRate = B600;
#endif
            break;
        case '2':
#if defined(_WIN32) || defined(_WIN64)
            baudRate = 1200;
#else
            baudRate = B1200;
#endif
            break;
        case '3':
#if defined(_WIN32) || defined(_WIN64)
            baudRate = 2400;
#else
            baudRate = B2400;
#endif
            break;
        case '4':
#if defined(_WIN32) || defined(_WIN64)
            baudRate = 4800;
#else
            baudRate = B4800;
#endif
            break;
        case '5':
#if defined(_WIN32) || defined(_WIN64)
            baudRate = 9600;
#else
            baudRate = B9600;
#endif
            break;
        case '6':
#if defined(_WIN32) || defined(_WIN64)
            baudRate = 19200;
#else
            baudRate = B19200;
#endif
            break;
        default:
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        //Send ACK
        buff[0] = 0x06;
        //Send Protocol control character
        buff[1] = '2';// "2" HDLC protocol procedure (Mode E)
        buff[2] = (char)ch;
        buff[3] = '2';
        buff[4] = (char)0x0D;
        buff[5] = 0x0A;
        len = 6;
        reply.Clear();
        if (m_Trace > GX_TRACE_LEVEL_WARNING)
        {
            printf("\nTX: ");
            for (pos = 0; pos != len; ++pos)
            {
                printf("%.2X ", buff[pos]);
            }
            printf("\n");
        }
#if defined(_WIN32) || defined(_WIN64)//Windows
        ret = WriteFile(m_hComPort, buff, len, &sendSize, &m_osWrite);
        if (ret == 0)
        {
            int err = GetLastError();
            //If error occurs...
            if (err != ERROR_IO_PENDING)
            {
                printf("WriteFile %d\n", err);
                return DLMS_ERROR_CODE_SEND_FAILED;
            }
            //Wait until data is actually sent
            WaitForSingleObject(m_osWrite.hEvent, INFINITE);
        }
#else //#if defined(__LINUX__)
        ret = write(m_hComPort, buff, len);
        if (ret != len)
        {
            printf("write failed %dr\n", errno);
            return DLMS_ERROR_CODE_SEND_FAILED;
        }
#endif
#if defined(_WIN32) || defined(_WIN64)//Windows
        //Some meters need this sleep. Do not remove.
        Sleep(200);
        dcb.BaudRate = baudRate;
        printf("New baudrate %d\n", (int)dcb.BaudRate);
        dcb.ByteSize = 8;
        dcb.StopBits = ONESTOPBIT;
        dcb.Parity = NOPARITY;
        if ((ret = GXSetCommState(m_hComPort, &dcb)) != 0)
        {
            printf("GXSetCommState failed %d\n", ret);
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        //Some meters need this sleep. Do not remove.
        Sleep(800);
#else
        //Some meters need this sleep. Do not remove.
        usleep(200000);
        // 8n1, see termios.h for more information
        options.c_cflag = CS8 | CREAD | CLOCAL;
        //Set Baud Rates
        cfsetospeed(&options, baudRate);
        cfsetispeed(&options, baudRate);
        if (tcsetattr(m_hComPort, TCSAFLUSH, &options) != 0)
        {
            printf("Failed to Open port. tcsetattr failed %d.\n", errno);
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        //Some meters need this sleep. Do not remove.
        usleep(800000);
#endif
        //It's ok if this fails.
        Read('\n', reply);
    }
    return DLMS_ERROR_CODE_OK;
}

/// Read Invocation counter (frame counter) from the meter and update it.
int CGXCommunication::UpdateFrameCounter()
{
    int ret = 0;
    //Read frame counter if GeneralProtection is used.
    if (m_InvocationCounter != NULL && m_Parser->GetCiphering() != NULL && m_Parser->GetCiphering()->GetSecurity() != DLMS_SECURITY_NONE)
    {
        if (m_Trace > GX_TRACE_LEVEL_WARNING)
        {
            printf("UpdateFrameCounter\n");
        }
        m_Parser->SetProposedConformance((DLMS_CONFORMANCE)(m_Parser->GetProposedConformance() | DLMS_CONFORMANCE_GENERAL_PROTECTION));
        unsigned long add = m_Parser->GetClientAddress();
        DLMS_AUTHENTICATION auth = m_Parser->GetAuthentication();
        DLMS_SECURITY security = m_Parser->GetCiphering()->GetSecurity();
        CGXByteBuffer challenge = m_Parser->GetCtoSChallenge();
        std::vector<CGXByteBuffer> data;
        CGXReplyData reply;
        m_Parser->SetClientAddress(16);
        m_Parser->SetAuthentication(DLMS_AUTHENTICATION_NONE);
        m_Parser->GetCiphering()->SetSecurity(DLMS_SECURITY_NONE);
        //Get meter's send and receive buffers size.
        if ((ret = m_Parser->SNRMRequest(data)) != 0 ||
            (ret = ReadDataBlock(data, reply)) != 0 ||
            (ret = m_Parser->ParseUAResponse(reply.GetData())) != 0)
        {
            printf("SNRMRequest failed %d.\n", ret);
            return ret;
        }
        reply.Clear();
        if ((ret = m_Parser->AARQRequest(data)) != 0 ||
            (ret = ReadDataBlock(data, reply)) != 0 ||
            (ret = m_Parser->ParseAAREResponse(reply.GetData())) != 0)
        {
            if (ret == DLMS_ERROR_CODE_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED)
            {
                printf("Use Logical Name referencing is wrong. Change it!\n");
                return ret;
            }
            printf("AARQRequest failed %s\n", CGXDLMSConverter::GetErrorMessage(ret));
            return ret;
        }
        reply.Clear();
        std::string ln;
        ln.append(m_InvocationCounter);
        CGXDLMSData d(ln);
        std::string str;
        if ((ret = Read(&d, 2, str)) == 0)
        {
            m_Parser->GetCiphering()->SetInvocationCounter(1 + d.GetValue().ToInteger());
        }
        printf("Invocation counter: %ld\n", m_Parser->GetCiphering()->GetInvocationCounter());
        reply.Clear();
        Disconnect();
        m_Parser->SetClientAddress(add);
        m_Parser->SetAuthentication(auth);
        m_Parser->GetCiphering()->SetSecurity(security);
        m_Parser->SetCtoSChallenge(challenge);
    }
    return ret;
}


//Initialize connection to the meter.
int CGXCommunication::InitializeConnection()
{
    int ret = 0;
    if ((ret = UpdateFrameCounter()) != 0)
    {
        return ret;
    }
    if (m_Trace > GX_TRACE_LEVEL_WARNING)
    {
        printf("InitializeConnection\n");
    }
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    //Get meter's send and receive buffers size.
    if ((ret = m_Parser->SNRMRequest(data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->ParseUAResponse(reply.GetData())) != 0)
    {
        printf("SNRMRequest failed %d.\n", ret);
        return ret;
    }
    reply.Clear();
    if ((ret = m_Parser->AARQRequest(data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->ParseAAREResponse(reply.GetData())) != 0)
    {
        if (ret == DLMS_ERROR_CODE_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED)
        {
            printf("Use Logical Name referencing is wrong. Change it!\n");
            return ret;
        }
        printf("AARQRequest failed (%d) %s\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
        return ret;
    }
    reply.Clear();
    // Get challenge Is HLS authentication is used.
    if (m_Parser->GetAuthentication() > DLMS_AUTHENTICATION_LOW)
    {
        if ((ret = m_Parser->GetApplicationAssociationRequest(data)) != 0 ||
            (ret = ReadDataBlock(data, reply)) != 0 ||
            (ret = m_Parser->ParseApplicationAssociationResponse(reply.GetData())) != 0)
        {
            printf("Authentication failed (%d) %s\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
            return ret;
        }
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXCommunication::SendData(CGXByteBuffer& data)
{
    int ret;
    uint16_t len = (uint16_t)data.GetSize();
    if (m_hComPort != INVALID_HANDLE_VALUE)
    {
#if defined(_WIN32) || defined(_WIN64)//If Windows
        DWORD sendSize = 0;
        BOOL bRes = ::WriteFile(m_hComPort, data.GetData(), len, &sendSize, &m_osWrite);
        if (!bRes)
        {
            COMSTAT comstat;
            unsigned long RecieveErrors;
            DWORD err = GetLastError();
            //If error occurs...
            if (err != ERROR_IO_PENDING)
            {
                ret = WSAGetLastError();
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
            }
            //Wait until data is actually sent
            ret = WaitForSingleObject(m_osWrite.hEvent, m_WaitTime);
            if (ret != 0)
            {
                ret = WSAGetLastError();
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
            }
            //Read bytes in output buffer. Some USB converts require this.
            if (!ClearCommError(m_hComPort, &RecieveErrors, &comstat))
            {
                ret = WSAGetLastError();
                return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
            }
        }
#else //If Linux
        ret = write(m_hComPort, data.GetData(), len);
        if (ret != len)
        {
            ret = errno;
            return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
        }
#endif
    }
    else if (send(m_socket, (const char*)data.GetData(), len, 0) == -1)
    {
#if defined(_WIN32) || defined(_WIN64)//If Windows
        ret = WSAGetLastError();
#else
        ret = errno;
#endif
        return DLMS_ERROR_TYPE_COMMUNICATION_ERROR | ret;
    }
    return 0;
}

int CGXCommunication::ReadData(CGXByteBuffer& reply, std::string& str)
{
    int ret;
    if (m_hComPort != INVALID_HANDLE_VALUE)
    {
        unsigned short pos = (unsigned short)reply.GetSize();
        if (ret = Read(0x7E, reply) != 0)
        {
            str += reply.ToHexString(pos, reply.GetSize() - pos, true);
            printf("Read failed.\n%s", str.c_str());
            return DLMS_ERROR_CODE_RECEIVE_FAILED;
        }
        if (str.size() == 0)
        {
            Now(str);
            str = "RX:\t" + str + "\t";
        }
        else
        {
            str += " ";
        }
        str += reply.ToHexString(pos, reply.GetSize() - pos, true);
    }
    else
    {
        int len = RECEIVE_BUFFER_SIZE;
        if ((ret = recv(m_socket, (char*)m_Receivebuff, len, 0)) == -1)
        {
            if (ret != 10060)
            {
#if defined(_WIN32) || defined(_WIN64)//If Windows
                printf("recv failed %d\n", WSAGetLastError());
#else
                printf("recv failed %d\n", errno);
#endif
            }
            return DLMS_ERROR_CODE_RECEIVE_FAILED;
        }
        reply.Set(m_Receivebuff, ret);
        if (str.size() == 0)
        {
            Now(str);
            str = "RX:\t" + str + "\t";
        }
        else
        {
            str += " ";
        }
        str += GXHelpers::BytesToHex(m_Receivebuff, ret);
    }
    return 0;
}

// Read DLMS Data frame from the device.
int CGXCommunication::ReadDLMSPacket(CGXByteBuffer& data, CGXReplyData& reply)
{
    int ret;
    CGXByteBuffer bb;
    std::string tmp;
    CGXReplyData notify;
    if (data.GetSize() == 0)
    {
        return DLMS_ERROR_CODE_OK;
    }
    Now(tmp);
    tmp = "TX:\t" + tmp;
    tmp += "\t" + data.ToHexString();
    if (m_Trace > GX_TRACE_LEVEL_INFO)
    {
        printf("%s\n", tmp.c_str());
    }
    GXHelpers::Write("trace.txt", tmp + "\n");
    if ((ret = SendData(data)) != 0)
    {
        return ret;
    }
    // Loop until whole DLMS packet is received.
    tmp = "";
    unsigned char pos = 0;
    do
    {
        if (notify.GetData().GetSize() != 0)
        {
            //Handle notify.
            if (!notify.IsMoreData())
            {
                //Show received push message as XML.
                std::string xml;
                CGXDLMSTranslator t(DLMS_TRANSLATOR_OUTPUT_TYPE_SIMPLE_XML);
                if ((ret = t.DataToXml(notify.GetData(), xml)) != 0)
                {
                    printf("ERROR! DataToXml failed.");
                }
                else
                {
                    printf("%s\n", xml.c_str());
                }
                notify.Clear();
            }
            continue;
        }
        if ((ret = ReadData(bb, tmp)) != 0)
        {
            if (ret != DLMS_ERROR_CODE_RECEIVE_FAILED || pos == 3)
            {
                break;
            }
            ++pos;
            printf("Data send failed. Try to resend %d/3\n", pos);
            if ((ret = SendData(data)) != 0)
            {
                break;
            }
        }
    } while ((ret = m_Parser->GetData(bb, reply, notify)) == DLMS_ERROR_CODE_FALSE);
    tmp += "\n";
    if (m_Trace > GX_TRACE_LEVEL_INFO)
    {
        printf("%s", tmp.c_str());
    }
    GXHelpers::Write("trace.txt", tmp);
    if (ret == DLMS_ERROR_CODE_REJECTED)
    {
#if defined(_WIN32) || defined(_WIN64)//Windows
        Sleep(1000);
#else
        usleep(1000000);
#endif
        ret = ReadDLMSPacket(data, reply);
    }
    return ret;
}

int CGXCommunication::ReadDataBlock(CGXByteBuffer& data, CGXReplyData& reply)
{
    //If ther is no data to send.
    if (data.GetSize() == 0)
    {
        return DLMS_ERROR_CODE_OK;
    }
    int ret;
    CGXByteBuffer bb;
    //Send data.
    if ((ret = ReadDLMSPacket(data, reply)) != DLMS_ERROR_CODE_OK)
    {
        return ret;
    }
    while (reply.IsMoreData())
    {
        bb.Clear();
        if ((ret = m_Parser->ReceiverReady(reply.GetMoreData(), bb)) != 0)
        {
            return ret;
        }
        if ((ret = ReadDLMSPacket(bb, reply)) != DLMS_ERROR_CODE_OK)
        {
            return ret;
        }
    }
    return DLMS_ERROR_CODE_OK;
}


int CGXCommunication::ReadDataBlock(std::vector<CGXByteBuffer>& data, CGXReplyData& reply)
{
    //If ther is no data to send.
    if (data.size() == 0)
    {
        return DLMS_ERROR_CODE_OK;
    }
    int ret;
    CGXByteBuffer bb;
    //Send data.
    for (std::vector<CGXByteBuffer>::iterator it = data.begin(); it != data.end(); ++it)
    {
        //Send data.
        if ((ret = ReadDLMSPacket(*it, reply)) != DLMS_ERROR_CODE_OK)
        {
            return ret;
        }
        while (reply.IsMoreData())
        {
            bb.Clear();
            if ((ret = m_Parser->ReceiverReady(reply.GetMoreData(), bb)) != 0)
            {
                return ret;
            }
            if ((ret = ReadDLMSPacket(bb, reply)) != DLMS_ERROR_CODE_OK)
            {
                return ret;
            }
        }
    }
    return DLMS_ERROR_CODE_OK;
}

//Get Association view.
int CGXCommunication::GetAssociationView()
{
    if (m_Trace > GX_TRACE_LEVEL_WARNING)
    {
        printf("GetAssociationView\n");
    }
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    if ((ret = m_Parser->GetObjectsRequest(data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->ParseObjects(reply.GetData(), true)) != 0)
    {
        printf("GetObjects failed %d.\n", ret);
        return ret;
    }
    return DLMS_ERROR_CODE_OK;
}

//Read selected object.
int CGXCommunication::Read(CGXDLMSObject* pObject, int attributeIndex, std::string& value)
{
    value.clear();
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    //Read data from the meter.
    if ((ret = m_Parser->Read(pObject, attributeIndex, data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->UpdateValue(*pObject, attributeIndex, reply.GetValue())) != 0)
    {
        return ret;
    }
    //Update data type.
    DLMS_DATA_TYPE type;
    if ((ret = pObject->GetDataType(attributeIndex, type)) != 0)
    {
        return ret;
    }
    if (type == DLMS_DATA_TYPE_NONE)
    {
        type = reply.GetValue().vt;
        if ((ret = pObject->SetDataType(attributeIndex, type)) != 0)
        {
            return ret;
        }
    }
    //Get read value as string.
    //Note! This is for example. It's faster if you handle read COSEM object directly.
    std::vector<std::string> values;
    pObject->GetValues(values);
    value = values[attributeIndex - 1];
    return DLMS_ERROR_CODE_OK;
}

int CGXCommunication::ReadList(
    std::vector<std::pair<CGXDLMSObject*, unsigned char> >& list)
{
    int ret;
    CGXReplyData reply;
    std::vector<CGXByteBuffer> data;
    if (list.size() == 0)
    {
        return 0;
    }
    //Get values from the meter.
    if ((ret = m_Parser->ReadList(list, data)) != 0)
    {
        return ret;
    }

    std::vector<CGXDLMSVariant> values;
    for (std::vector<CGXByteBuffer>::iterator it = data.begin(); it != data.end(); ++it)
    {
        if ((ret = ReadDataBlock(*it, reply)) != 0)
        {
            return ret;
        }
        if (reply.GetValue().vt == DLMS_DATA_TYPE_ARRAY)
        {
            values.insert(values.end(), reply.GetValue().Arr.begin(), reply.GetValue().Arr.end());
        }
        reply.Clear();
    }
    if (values.size() != list.size())
    {
        //Invalid reply. Read items count do not match.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    return m_Parser->UpdateValues(list, values);
}

int CGXCommunication::WriteList(
    std::vector<std::pair<CGXDLMSObject*, unsigned char> >& list)
{
    int ret;
    CGXReplyData reply;
    std::vector<CGXByteBuffer> data;
    if (list.size() == 0)
    {
        return 0;
    }
    //Get values from the meter.
    if ((ret = m_Parser->WriteList(list, data)) != 0)
    {
        return ret;
    }
    std::vector<CGXDLMSVariant> values;
    for (std::vector<CGXByteBuffer>::iterator it = data.begin(); it != data.end(); ++it)
    {
        if ((ret = ReadDataBlock(*it, reply)) != 0)
        {
            break;
        }
        reply.Clear();
    }
    return ret;
}


//Write selected object.
int CGXCommunication::Write(CGXDLMSObject* pObject, int attributeIndex, CGXDLMSVariant& value)
{
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    //Get meter's send and receive buffers size.
    if ((ret = m_Parser->Write(pObject, attributeIndex, value, data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0)
    {
        return ret;
    }
    return DLMS_ERROR_CODE_OK;
}

//Write selected object.
int CGXCommunication::Write(CGXDLMSObject* pObject, int attributeIndex)
{
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    //Get meter's send and receive buffers size.
    if ((ret = m_Parser->Write(pObject, attributeIndex, data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0)
    {
        return ret;
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXCommunication::Method(CGXDLMSObject* pObject, int attributeIndex, CGXDLMSVariant& value)
{
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    //Get meter's send and receive buffers size.
    if ((ret = m_Parser->Method(pObject, attributeIndex, value, data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0)
    {
        return ret;
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXCommunication::ReadRowsByRange(
    CGXDLMSProfileGeneric* pObject,
    CGXDateTime& start,
    CGXDateTime& end,
    CGXDLMSVariant& rows)
{
    return ReadRowsByRange(pObject, &start.GetValue(), &end.GetValue(), rows);
}

int CGXCommunication::ReadRowsByRange(
    CGXDLMSProfileGeneric* pObject,
    struct tm* start,
    struct tm* end,
    CGXDLMSVariant& rows)
{
    rows.Clear();
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    if ((ret = m_Parser->ReadRowsByRange(pObject, start, end, data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->UpdateValue(*pObject, 2, reply.GetValue())) != 0)
    {
        return ret;
    }
    //Get rows value as string.
    //Note! This is for example. It's faster if you handle read COSEM object directly.
    std::vector<std::string> values;
    pObject->GetValues(values);
    rows = values[2 - 1];
    return DLMS_ERROR_CODE_OK;
}

int CGXCommunication::ReadRowsByEntry(
    CGXDLMSProfileGeneric* pObject,
    unsigned int index,
    unsigned int count,
    CGXDLMSVariant& rows)
{
    rows.Clear();
    int ret;
    std::vector<CGXByteBuffer> data;
    CGXReplyData reply;
    if ((ret = m_Parser->ReadRowsByEntry(pObject, index, count, data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->UpdateValue(*pObject, 2, reply.GetValue())) != 0)
    {
        return ret;
    }
    //Get rows value as string.
    //Note! This is for example. It's faster if you handle read COSEM object directly.
    std::vector<std::string> values;
    pObject->GetValues(values);
    rows = values[2 - 1];
    return DLMS_ERROR_CODE_OK;
}

int CGXCommunication::ReadScalerAndUnits()
{
    int ret = 0;
    std::string str;
    std::string ln;
    std::vector<std::pair<CGXDLMSObject*, unsigned char> > list;
    if ((m_Parser->GetNegotiatedConformance() & DLMS_CONFORMANCE_MULTIPLE_REFERENCES) != 0)
    {
        // Read scalers and units from the device.
        for (std::vector<CGXDLMSObject*>::iterator it = m_Parser->GetObjects().begin(); it != m_Parser->GetObjects().end(); ++it)
        {
            if (((*it)->GetObjectType() == DLMS_OBJECT_TYPE_REGISTER ||
                (*it)->GetObjectType() == DLMS_OBJECT_TYPE_EXTENDED_REGISTER) &&
                ((*it)->GetAccess(3) & DLMS_ACCESS_MODE_READ) != 0)
            {
                list.push_back(std::make_pair(*it, 3));
            }
            else if ((*it)->GetObjectType() == DLMS_OBJECT_TYPE_DEMAND_REGISTER &&
                ((*it)->GetAccess(4) & DLMS_ACCESS_MODE_READ) != 0)
            {
                list.push_back(std::make_pair(*it, 4));
            }
        }
        if ((ret = ReadList(list)) != 0)
        {
            printf("Err! Failed to read register: %s", CGXDLMSConverter::GetErrorMessage(ret));
            m_Parser->SetNegotiatedConformance((DLMS_CONFORMANCE)(m_Parser->GetNegotiatedConformance() & ~DLMS_CONFORMANCE_MULTIPLE_REFERENCES));
        }
    }
    if ((m_Parser->GetNegotiatedConformance() & DLMS_CONFORMANCE_MULTIPLE_REFERENCES) == 0)
    {
        //If readlist is not supported read one value at the time.
        for (std::vector<CGXDLMSObject*>::iterator it = m_Parser->GetObjects().begin(); it != m_Parser->GetObjects().end(); ++it)
        {
            if ((*it)->GetObjectType() == DLMS_OBJECT_TYPE_REGISTER ||
                (*it)->GetObjectType() == DLMS_OBJECT_TYPE_EXTENDED_REGISTER)
            {
                (*it)->GetLogicalName(ln);
                WriteValue(m_Trace, ln.c_str());
                if ((ret = Read(*it, 3, str)) != 0)
                {
                    printf("Err! Failed to read register: %s %s", ln.c_str(), CGXDLMSConverter::GetErrorMessage(ret));
                    //Continue reading.
                    continue;
                }
            }
            else if ((*it)->GetObjectType() == DLMS_OBJECT_TYPE_DEMAND_REGISTER)
            {
                (*it)->GetLogicalName(ln);
                WriteValue(m_Trace, ln.c_str());
                if ((ret = Read(*it, 4, str)) != 0)
                {
                    printf("Err! Failed to read register: %s %s", ln.c_str(), CGXDLMSConverter::GetErrorMessage(ret));
                    //Continue reading.
                    continue;
                }
            }
        }
    }
    return ret;
}

int CGXCommunication::GetProfileGenericColumns()
{
    int ret = 0;
    std::string ln;
    std::string value;
    //Read columns.
    CGXDLMSObjectCollection profileGenerics;
    m_Parser->GetObjects().GetObjects(DLMS_OBJECT_TYPE_PROFILE_GENERIC, profileGenerics);
    for (std::vector<CGXDLMSObject*>::iterator it = profileGenerics.begin(); it != profileGenerics.end(); ++it)
    {
        //Read Profile Generic columns first.
        CGXDLMSProfileGeneric* pg = (CGXDLMSProfileGeneric*)*it;
        if ((ret = Read(pg, 3, value)) != 0)
        {
            printf("Err! Failed to read columns: %s", CGXDLMSConverter::GetErrorMessage(ret));
            //Continue reading.
            continue;
        }

        //Update columns scalers.
        DLMS_OBJECT_TYPE ot;
        CGXDLMSObject* obj;
        for (std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject*> >::iterator it2 = pg->GetCaptureObjects().begin(); it2 != pg->GetCaptureObjects().end(); ++it2)
        {
            ot = it2->first->GetObjectType();
            if (ot == DLMS_OBJECT_TYPE_REGISTER ||
                ot == DLMS_OBJECT_TYPE_EXTENDED_REGISTER ||
                ot == DLMS_OBJECT_TYPE_DEMAND_REGISTER)
            {
                it2->first->GetLogicalName(ln);
                obj = m_Parser->GetObjects().FindByLN(ot, ln);
                if (obj != NULL)
                {
                    if (ot == DLMS_OBJECT_TYPE_REGISTER || ot == DLMS_OBJECT_TYPE_EXTENDED_REGISTER)
                    {
                        ((CGXDLMSRegister*)it2->first)->SetScaler(((CGXDLMSRegister*)obj)->GetScaler());
                        ((CGXDLMSRegister*)it2->first)->SetUnit(((CGXDLMSRegister*)obj)->GetUnit());
                    }
                    else if (ot == DLMS_OBJECT_TYPE_DEMAND_REGISTER)
                    {
                        ((CGXDLMSDemandRegister*)it2->first)->SetScaler(((CGXDLMSDemandRegister*)obj)->GetScaler());
                        ((CGXDLMSDemandRegister*)it2->first)->SetUnit(((CGXDLMSDemandRegister*)obj)->GetUnit());
                    }
                }
            }
        }
        WriteValue(m_Trace, "Profile Generic " + (*it)->GetName().ToString() + " Columns:\n");
        std::string str;
        for (std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject*> >::iterator it2 = pg->GetCaptureObjects().begin(); it2 != pg->GetCaptureObjects().end(); ++it2)
        {
            if (str.size() != 0)
            {
                str.append(" | ");
            }
            str.append((*it2).first->GetName().ToString());
            str.append(" ");
            str.append((*it2).first->GetDescription());
        }
        str.append("\n");
        WriteValue(m_Trace, str);
    }
    return ret;
}

int CGXCommunication::GetReadOut()
{
    int ret = 0;
    char buff[200];
    std::string value;
    for (std::vector<CGXDLMSObject*>::iterator it = m_Parser->GetObjects().begin(); it != m_Parser->GetObjects().end(); ++it)
    {
        // Profile generics are read later because they are special cases.
        // (There might be so lots of data and we so not want waste time to read all the data.)
        if ((*it)->GetObjectType() == DLMS_OBJECT_TYPE_PROFILE_GENERIC)
        {
            continue;
        }

        if (dynamic_cast<CGXDLMSCustomObject*>((*it)) != NULL)
        {
            //If interface is not implemented.
            //Example manufacturer specific interface.
            printf("Unknown Interface: %d\n", (*it)->GetObjectType());
            continue;
        }
#if _MSC_VER > 1000
        sprintf_s(buff, 200, "-------- Reading %s %s %s\n", CGXDLMSClient::ObjectTypeToString((*it)->GetObjectType()).c_str(), (*it)->GetName().ToString().c_str(), (*it)->GetDescription().c_str());
#else
        sprintf(buff, "-------- Reading %s %s %s\n", CGXDLMSClient::ObjectTypeToString((*it)->GetObjectType()).c_str(), (*it)->GetName().ToString().c_str(), (*it)->GetDescription().c_str());
#endif

        WriteValue(m_Trace, buff);
        std::vector<int> attributes;
        (*it)->GetAttributeIndexToRead(true, attributes);
        for (std::vector<int>::iterator pos = attributes.begin(); pos != attributes.end(); ++pos)
        {
            value.clear();
            if (((*it)->GetAccess(*pos) & DLMS_ACCESS_MODE_READ) != 0)
            {
                if ((ret = Read(*it, *pos, value)) != DLMS_ERROR_CODE_OK)
                {
#if _MSC_VER > 1000
                    sprintf_s(buff, 100, "Error! Index: %d %s\n", *pos, CGXDLMSConverter::GetErrorMessage(ret));
#else
                    sprintf(buff, "Error! Index: %d read failed: %s\n", *pos, CGXDLMSConverter::GetErrorMessage(ret));
#endif
                    WriteValue(GX_TRACE_LEVEL_ERROR, buff);
                    //Continue reading.
                }
                else
                {
#if _MSC_VER > 1000
                    sprintf_s(buff, 100, "Index: %d Value: ", *pos);
#else
                    sprintf(buff, "Index: %d Value: ", *pos);
#endif
                    WriteValue(m_Trace, buff);
                    WriteValue(m_Trace, value.c_str());
                    WriteValue(m_Trace, "\n");
                }
            }
            else
            {
                WriteValue(GX_TRACE_LEVEL_INFO, "Attribute" + GXHelpers::IntToString(*pos) + " is not readable.");
            }
        }
    }
    return ret;
}

int CGXCommunication::GetProfileGenerics()
{
    char buff[200];
    int ret = 0;
    std::string str;
    std::string value;
    //Find profile generics and read them.
    CGXDLMSObjectCollection pgs;
    m_Parser->GetObjects().GetObjects(DLMS_OBJECT_TYPE_PROFILE_GENERIC, pgs);
    for (std::vector<CGXDLMSObject*>::iterator it = pgs.begin(); it != pgs.end(); ++it)
    {
#if _MSC_VER > 1000
        sprintf_s(buff, 200, "-------- Reading %s %s %s\n", CGXDLMSClient::ObjectTypeToString((*it)->GetObjectType()).c_str(), (*it)->GetName().ToString().c_str(), (*it)->GetDescription().c_str());
#else
        sprintf(buff, "-------- Reading %s %s %s\n", CGXDLMSClient::ObjectTypeToString((*it)->GetObjectType()).c_str(), (*it)->GetName().ToString().c_str(), (*it)->GetDescription().c_str());
#endif

        WriteValue(m_Trace, buff);

        if ((ret = Read(*it, 7, value)) != DLMS_ERROR_CODE_OK)
        {
#if _MSC_VER > 1000
            sprintf_s(buff, 100, "Error! Index: %d: %s\n", 7, CGXDLMSConverter::GetErrorMessage(ret));
#else
            sprintf(buff, "Error! Index: %d: %s\n", 7, CGXDLMSConverter::GetErrorMessage(ret));
#endif
            WriteValue(GX_TRACE_LEVEL_ERROR, buff);
            //Continue reading.
        }

        std::string entriesInUse = value;
        if ((ret = Read(*it, 8, value)) != DLMS_ERROR_CODE_OK)
        {
#if _MSC_VER > 1000
            sprintf_s(buff, 100, "Error! Index: %d: %s\n", 8, CGXDLMSConverter::GetErrorMessage(ret));
#else
            sprintf(buff, "Error! Index: %d: %s\n", 8, CGXDLMSConverter::GetErrorMessage(ret));
#endif
            WriteValue(GX_TRACE_LEVEL_ERROR, buff);
            //Continue reading.
        }
        std::string entries = value;
        str = "Entries: ";
        str += entriesInUse;
        str += "/";
        str += entries;
        str += "\n";
        WriteValue(m_Trace, str);
        //If there are no columns or rows.
        if (((CGXDLMSProfileGeneric*)*it)->GetEntriesInUse() == 0 || ((CGXDLMSProfileGeneric*)*it)->GetCaptureObjects().size() == 0)
        {
            continue;
        }
        //All meters are not supporting parameterized read.
        CGXDLMSVariant rows;
        if ((m_Parser->GetNegotiatedConformance() & (DLMS_CONFORMANCE_PARAMETERIZED_ACCESS | DLMS_CONFORMANCE_SELECTIVE_ACCESS)) != 0)
        {
            //Read first row from Profile Generic.
            if ((ret = ReadRowsByEntry((CGXDLMSProfileGeneric*)*it, 1, 1, rows)) != 0)
            {
                str = "Error! Failed to read first row:";
                str += CGXDLMSConverter::GetErrorMessage(ret);
                str += "\n";
                WriteValue(GX_TRACE_LEVEL_ERROR, str);
                //Continue reading.
            }
            else
            {
                //////////////////////////////////////////////////////////////////////////////
                //Show rows.
                WriteValue(m_Trace, rows.ToString());
            }
        }

        //All meters are not supporting parameterized read.
        if ((m_Parser->GetNegotiatedConformance() & (DLMS_CONFORMANCE_PARAMETERIZED_ACCESS | DLMS_CONFORMANCE_SELECTIVE_ACCESS)) != 0)
        {
            CGXDateTime start = CGXDateTime::Now();
            start.ResetTime();
            CGXDateTime end = CGXDateTime::Now();
            if ((ret = ReadRowsByRange((CGXDLMSProfileGeneric*)(*it), start, end, rows)) != 0)
            {
                str = "Error! Failed to read last day:";
                str += CGXDLMSConverter::GetErrorMessage(ret);
                str += "\n";
                WriteValue(GX_TRACE_LEVEL_ERROR, str);
                //Continue reading.
            }
            else
            {
                //////////////////////////////////////////////////////////////////////////////
                //Show rows.
                WriteValue(m_Trace, rows.ToString());
            }
        }
    }
    return ret;
}

int CGXCommunication::ReadAll(char* outputFile)
{
    bool read = false;
    int ret;
    if ((ret = InitializeConnection()) == 0)
    {
        if (outputFile != NULL)
        {
            if ((ret = m_Parser->GetObjects().Load(outputFile)) == 0)
            {
                read = true;
            }
        }
        if (!read)
        {
            // Get list of objects that meter supports.
            if ((ret = GetAssociationView()) != 0)
            {
                printf("GetAssociationView failed (%d) %s\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
            }
            // Read Scalers and units from the register objects.
            if (ret == 0 && (ret = ReadScalerAndUnits()) != 0)
            {
                printf("ReadScalerAndUnits failed (%d) %s\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
            }
            // Read Profile Generic columns.
            if (ret == 0 && (ret = GetProfileGenericColumns()) != 0)
            {
                printf("GetProfileGenericColumns failed (%d) %s\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
            }
        }
        if (ret == 0 && (ret = GetReadOut()) != 0)
        {
            printf("GetReadOut failed (%d) %s\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
        }
        // Read historical data.
        if (ret == 0 && (ret = GetProfileGenerics()) != 0)
        {
            printf("GetProfileGenerics failed (%d) %s\n", ret, CGXDLMSConverter::GetErrorMessage(ret));
        }
    }
    Close();
    if (outputFile != NULL && ret == 0)
    {
        CGXXmlWriterSettings settings;
        settings.SetSkipDefaults(false);
        ret = m_Parser->GetObjects().Save(outputFile, settings);
    }
    return ret;
}
