See An [Gurux](http://www.gurux.org/ "Gurux") for an overview.

Join the Gurux Community or follow [@Gurux](https://twitter.com/guruxorg "@Gurux") for project updates.

GuruxDLMS.cpp library is a high-performance ANSI C++ component that helps you to read you DLMS/COSEM compatible electricity, gas or water meters. We have try to make component so easy to use that you do not need understand protocol at all.

For more info check out [Gurux.DLMS](http://www.gurux.fi/index.php?q=Gurux.DLMS "Gurux.DLMS").

We are updating documentation on Gurux web page. 

Read should read [DLMS/COSEM FAQ](http://www.gurux.org/index.php?q=DLMSCOSEMFAQ) first to get started. Read Instructions for making your own [meter reading application](http://www.gurux.org/index.php?q=DLMSIntro) or build own 
DLMS/COSEM [meter/simulator/proxy](http://www.gurux.org/index.php?q=OwnDLMSMeter).

If you have problems you can ask your questions in Gurux [Forum](http://www.gurux.org/forum).

You can use any connection (TCP, serial, PLC) library you want to.
Gurux.DLMS classes only parse the data.

Before start
=========================== 

If you find an issue, please report it here:
http://www.gurux.fi/fi/project/issues/gurux.dlms.cpp

We have made makefile for linux environment. You should go development folder and create lib and obj directories.
Then run make. gurux_dlms_cpp static library is made.

For Client example you should also create bin and obj -directories.
Change Host name, port and DLMS settings for example. Run make and you are ready to test.

Simple example
=========================== 
Before use you must set following device parameters. 
Parameters are manufacturer specific.


```C++

All default parameters are given in constructor.
// Is used Logican Name or Short Name referencing.
CGXDLMSClient client(true);

```

HDLC addressing
=========================== 

Each meter has own server address. Server address is divided to Logical address and Physical address.
Usually you can use value 1 for meter address. You can count server address from serial number of the meter.
You can use GetServerAddress method for that.

```C++
//Count server address from serial number.
int serverAddress = CGXDLMSClient::GetServerAddress(Serial number);
//Count server address from logican and physical address.
serverAddress = CGXDLMSClient::GetServerAddress(logical Address, physical Address);
```


If you are using IEC handshake you must first send identify command and move to mode E.

```C++
//Open serial port.
int GXClient::Open(const char* pPortName, bool IEC)
{	
	char buff[10];
#if _MSC_VER > 1000
	sprintf_s(buff, 10, "\\\\.\\%s", pPortName);
#else
	sprintf(buff, "\\\\.\\%s", pPortName);
#endif
	//Open serial port for read / write. Port can't share.
	m_hComPort = CreateFileA(buff, 
					GENERIC_READ | GENERIC_WRITE, 0, NULL, 
					OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (m_hComPort == INVALID_HANDLE_VALUE)
	{
		return DLMS_DLMS_ERROR_CODE_INVALID_PARAMETER;
	}	
	COMMCONFIG conf = {0};	
	DWORD dwSize = sizeof(conf);
	conf.dwSize = dwSize;
	//This might fail with virtual COM ports are used.
	GetDefaultCommConfigA(buff, &conf, &dwSize);
	if (IEC)
	{
		conf.dcb.BaudRate = CBR_300; 
		conf.dcb.ByteSize = 7; 
		conf.dcb.StopBits = ONESTOPBIT; 
		conf.dcb.Parity = EVENPARITY; 
	}
	else
	{
		conf.dcb.BaudRate = CBR_9600; 
		conf.dcb.ByteSize = 8; 
		conf.dcb.StopBits = ONESTOPBIT; 
		conf.dcb.Parity = NOPARITY; 
	}
	conf.dcb.fDtrControl = DTR_CONTROL_ENABLE; 
	conf.dcb.fRtsControl = DTR_CONTROL_ENABLE; 
	SetCommState(m_hComPort, &conf.dcb); 	
	int cnt;
	if (IEC)
	{	
#if _MSC_VER > 1000
		strcpy_s(buff, 10, "/?!\r\n");
#else
		strcpy(buff, "/?!\r\n");
#endif		
		cnt = strlen(buff);
		DWORD sendSize = 0;		
		if (m_Trace)
		{
			TRACE1("\r\n<-");
			for(int pos = 0; pos != cnt; ++pos)
			{
				TRACE("%.2X ", buff[pos]);
			}
			TRACE1("\r\n");
		}
		BOOL bRes = ::WriteFile(m_hComPort, buff, cnt, &sendSize, &m_osWrite);
		if (!bRes)
		{				
			DWORD err = GetLastError();
			//If error occurs...
			if (err != ERROR_IO_PENDING)
			{				
				return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
			}
			//Wait until data is actually sent
			::WaitForSingleObject(m_osWrite.hEvent, INFINITE);			
		}
		if (m_Trace)
		{
			TRACE1("\r\n->");
		}
		//Read reply data.				
		DWORD bytesRead = 0;
		do
		{
			cnt = 0;
			do
			{
				//Read reply one byte at time.
				if (!ReadFile(m_hComPort, m_Receivebuff + cnt, 1, &bytesRead, &m_osReader))
				{
					DWORD nErr = GetLastError();
					if (nErr != ERROR_IO_PENDING)     
					{
						return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
					}			
					//Wait until data is actually read
					::WaitForSingleObject(m_osReader.hEvent, INFINITE);
				}
				if (m_Trace)
				{
					TRACE("%.2X ", m_Receivebuff[cnt]);
				}
				++cnt;
			}while(m_Receivebuff[cnt - 1] != 0x0A);
			m_Receivebuff[cnt] = 0;			
		}
		while(memcmp(buff, m_Receivebuff, cnt) == 0);//Remove echo.
		if (m_Trace)
		{
			TRACE1("\r\n");
		}
		if (m_Receivebuff[0] != '/')
		{
			return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
		}
		char baudrate = m_Receivebuff[4];
		if (baudrate == ' ')
        {
            baudrate = '5';
        }
        int bitrate = 0;
        switch (baudrate)
        {
            case '0':
                bitrate = 300;
                break;
            case '1':
                bitrate = 600;
                break;
            case '2':
                bitrate = 1200;
                break;
            case '3':
                bitrate = 2400;
                break;
            case '4':
                bitrate = 4800;
                break;
            case '5':                            
                bitrate = 9600;
                break;
            case '6':
                bitrate = 19200;
                break;
            default:
                return DLMS_DLMS_ERROR_CODE_INVALID_PARAMETER;
        }   
		//Send ACK
		buff[0] = 0x06;
        //Send Protocol control character
        buff[1] = '2';// "2" HDLC protocol procedure (Mode E)
		buff[2] = baudrate;
		buff[3] = '2';
		buff[4] = (char) 0x0D;
		buff[5] = 0x0A;
		if (m_Trace)
		{
			TRACE1("\r\n<-");
			for(int pos = 0; pos != 6; ++pos)
			{
				TRACE("%.2X ", buff[pos]);
			}
			TRACE1("\r\n");
		}
		bRes = ::WriteFile(m_hComPort, buff, 6, &sendSize, &m_osWrite);
		if (!bRes)
		{
			DWORD err = GetLastError();
			//If error occurs...
			if (err != ERROR_IO_PENDING)
			{				
				return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
			}
			//Wait until data is actually sent
			::WaitForSingleObject(m_osWrite.hEvent, INFINITE);			
		}
		m_Receivebuff[cnt] = 0;					
		//Read reply data.				
		bytesRead = 0;
		cnt = 0;
		//This sleep is in standard. Do not remove.
		Sleep(500);
		//Change bit rate.
		conf.dcb.BaudRate = bitrate;
		SetCommState(m_hComPort, &conf.dcb);
		if (m_Trace)
		{
			TRACE1("\r\n->");
		}
		do
		{
			//Read reply one byte at time.
			if (!ReadFile(m_hComPort, m_Receivebuff + cnt, 1, &bytesRead, &m_osReader))
			{
				DWORD nErr = GetLastError();
				if (nErr != ERROR_IO_PENDING)     
				{
					return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
				}			
				//Wait until data is actually read
				::WaitForSingleObject(m_osReader.hEvent, INFINITE);
			}
			TRACE("%.2x ", m_Receivebuff[cnt]);
			++cnt;
		}
		while(m_Receivebuff[cnt - 1] != 0x0A);				
		if (m_Trace)
		{
			TRACE1("\r\n");
		}
		TRACE("Changing bit rate.\r\n", 0);
		conf.dcb.ByteSize = 8; 
		conf.dcb.StopBits = ONESTOPBIT; 
		conf.dcb.Parity = NOPARITY; 		
		SetCommState(m_hComPort, &conf.dcb); 	
		//Some meters need this sleep. Do not remove.
		Sleep(300);
	}
	return DLMS_DLMS_ERROR_CODE_OK;
}

```

After you have set parameters you can try to connect to the meter.
First you should send SNRM request and handle UA response.
After that you will send AARQ request and handle AARE response.


```C++

std::vector<CGXByteBuffer> data;
CGXReplyData reply;
int ret = 0;
//Get meter's send and receive buffers size.
if ((ret = m_Parser->SNRMRequest(data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->ParseUAResponse(reply.GetData())) != 0)
{
    TRACE("SNRMRequest failed %d.\r\n", ret);
    return ret;
}
reply.Clear();
if ((ret = m_Parser->AARQRequest(data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->ParseAAREResponse(reply.GetData())) != 0)
{
    if (ret == DLMS_DLMS_ERROR_CODE_APPLICATION_CONTEXT_NAME_NOT_SUPPORTED)
    {
        TRACE1("Use Logical Name referencing is wrong. Change it!\r\n");
        return ret;
    }
    TRACE("AARQRequest failed %d.\r\n", ret);
    return ret;
}

```

If parameters are right connection is made.
Next you can read Association view and show all objects that meter can offer.

```C++
/// Read Association View from the meter.
int ret;
std::vector<CGXByteBuffer> data;
CGXReplyData reply;
if ((ret = m_Parser->GetObjectsRequest(data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0 ||
        (ret = m_Parser->ParseObjects(reply.GetData(), objects, false)) != 0)
{
    TRACE("GetObjects failed %d.\r\n", ret);
    return ret;
}

```
Now you can read wanted objects. After read you must close the connection by sending
disconnecting request.

```C++

std::vector<CGXByteBuffer> data;
CGXReplyData reply;
if ((ret = m_Parser->DisconnectRequest(data)) != 0 ||
        (ret = ReadDataBlock(data, reply)) != 0)
{
    //Show error but continue close.
}
//Close media.

```

```C++

// Read DLMS Data frame from the device.
int GXClient::ReadDLMSPacket(CGXByteBuffer& data, CGXReplyData& reply)
{
    int ret;
    CGXByteBuffer bb;
    string tmp;
    if (data.GetSize() == 0)
    {
        return DLMS_DLMS_ERROR_CODE_OK;
    }
    int len = data.GetSize();
    if (m_hComPort != INVALID_HANDLE_VALUE)
    {
#if defined(_WIN32) || defined(_WIN64)//Windows includes
        DWORD sendSize = 0;
        BOOL bRes = ::WriteFile(m_hComPort, data.GetData(), len, &sendSize, &m_osWrite);
        if (!bRes)
        {
            DWORD err = GetLastError();
            //If error occurs...
            if (err != ERROR_IO_PENDING)
            {
                return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
            }
            //Wait until data is actually sent
            ::WaitForSingleObject(m_osWrite.hEvent, INFINITE);
        }
#else
        ret = write(settings->con.comPort, data->data, data->size);
        if (ret != data->size)
        {
            return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
        }
#endif
    }
    else if (send(m_socket, (const char*) data.GetData(), len, 0) == -1)
    {
        //If error has occured
        return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
    }
    // Loop until whole DLMS packet is received.
    while ((ret = m_Parser->GetData(bb, reply)) == DLMS_DLMS_ERROR_CODE_FALSE)
    {
        if (m_hComPort != INVALID_HANDLE_VALUE)
        {
            if(Read(0x7E, bb) != 0)
            {
                return DLMS_DLMS_ERROR_CODE_SEND_FAILED;
            }
        }
        else
        {
            len = RECEIVE_BUFFER_SIZE;
            if ((ret = recv(m_socket, (char*) m_Receivebuff, len, 0)) == -1)
            {
                return DLMS_DLMS_ERROR_CODE_RECEIVE_FAILED;
            }
            bb.Set(m_Receivebuff, ret);
        }
    }
    return ret;
}
```
