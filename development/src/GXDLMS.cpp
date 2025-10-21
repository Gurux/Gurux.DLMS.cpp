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

#include "../include/GXDLMS.h"
#include "../include/GXAPDU.h"
#include "../include/GXDLMSClient.h"
#include "../include/GXDLMSObjectFactory.h"
#include "../include/GXBytebuffer.h"
#include "../include/GXDLMSTranslator.h"
#include "../include/GXDLMSLNCommandHandler.h"

static unsigned char CIPHERING_HEADER_SIZE = 7 + 12 + 3;
//CRC table.
static unsigned short FCS16Table[256] =
{
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
};

bool CGXDLMS::UseHdlc(DLMS_INTERFACE_TYPE type)
{
    return type == DLMS_INTERFACE_TYPE_HDLC ||
        type == DLMS_INTERFACE_TYPE_HDLC_WITH_MODE_E ||
        type == DLMS_INTERFACE_TYPE_PLC_HDLC;
}

bool CGXDLMS::IsReplyMessage(DLMS_COMMAND cmd)
{
    return cmd == DLMS_COMMAND_GET_RESPONSE ||
        cmd == DLMS_COMMAND_SET_RESPONSE ||
        cmd == DLMS_COMMAND_METHOD_RESPONSE;
}

int CGXDLMS::GetAddress(long value, unsigned long& address, int& size)
{
    if (value < 0x80)
    {
        address = (unsigned char)(value << 1 | 1);
        size = 1;
        return 0;
    }
    else if (value < 0x4000)
    {
        address = (unsigned short)((value & 0x3F80) << 2 | (value & 0x7F) << 1 | 1);
        size = 2;
    }
    else if (value < 0x10000000)
    {
        address = (unsigned long)((value & 0xFE00000) << 4 | (value & 0x1FC000) << 3
            | (value & 0x3F80) << 2 | (value & 0x7F) << 1 | 1);
        size = 4;
    }
    else
    {
        //Invalid address
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::CheckInit(CGXDLMSSettings& settings)
{
    if (settings.GetClientAddress() == 0)
    {
        return DLMS_ERROR_CODE_INVALID_CLIENT_ADDRESS;
    }
    if (settings.GetServerAddress() == 0)
    {
        return DLMS_ERROR_CODE_INVALID_SERVER_ADDRESS;
    }
    return DLMS_ERROR_CODE_OK;
}

/////////////////////////////////////////////////////////////////////////////
// Get data from Block.
/////////////////////////////////////////////////////////////////////////////
// data : Stored data block.
// index : Position where data starts.
// Returns : Amount of removed bytes.
/////////////////////////////////////////////////////////////////////////////
int GetDataFromBlock(CGXByteBuffer& data, int index)
{
    if (data.GetSize() == data.GetPosition())
    {
        data.Clear();
        return 0;
    }
    int len = data.GetPosition() - index;
    if (len < 0)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    unsigned long pos = data.GetPosition();
    data.SetPosition(pos - len);
    data.Move(pos, pos - len, data.GetSize() - pos);
    return 0;
}

int CGXDLMS::ReceiverReady(
    CGXDLMSSettings& settings,
    DLMS_DATA_REQUEST_TYPES type,
    CGXCipher* cipher,
    CGXByteBuffer& reply)
{
    CGXReplyData data;
    data.SetMoreData(type);
    data.SetGbtWindowSize(settings.GetGbtWindowSize());
    data.SetBlockNumberAck(settings.GetBlockNumberAck());
    data.SetBlockNumber(settings.GetBlockIndex());
    return ReceiverReady(settings, data, cipher, reply);
}

int CGXDLMS::ReceiverReady(
    CGXDLMSSettings& settings,
    CGXReplyData& data,
    CGXCipher* cipher,
    CGXByteBuffer& reply)
{
    int ret;
    reply.Clear();
    if (data.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    // Get next frame.
    if ((data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) != 0)
    {
        unsigned char id = settings.GetReceiverReady();
        if (settings.GetInterfaceType() == DLMS_INTERFACE_TYPE_PLC_HDLC)
        {
            return CGXDLMS::GetMacHdlcFrame(settings, id, 0, NULL, reply);
        }
        else
        {
            ret = CGXDLMS::GetHdlcFrame(settings, id, NULL, reply);
        }
        return ret;
    }
    DLMS_COMMAND cmd = (DLMS_COMMAND)settings.GetCommand();
    std::vector<CGXByteBuffer> tmp;
    if (data.GetMoreData() == DLMS_DATA_REQUEST_TYPES_GBT)
    {
        CGXDLMSLNParameters p(&settings, 0, DLMS_COMMAND_GENERAL_BLOCK_TRANSFER,
            0, NULL, NULL, 0xff, DLMS_COMMAND_NONE);
        p.SetWindowSize(data.GetGbtWindowSize());
        p.SetBlockNumberAck(data.GetBlockNumber());
        p.SetBlockIndex(settings.GetBlockIndex());
        ret = GetLnMessages(p, tmp);
    }
    else
    {
        // Get next block.
        CGXByteBuffer bb(6);
        if (settings.GetUseLogicalNameReferencing())
        {
            bb.SetUInt32(settings.GetBlockIndex());
        }
        else
        {
            bb.SetUInt16((unsigned short)settings.GetBlockIndex());
        }
        settings.IncreaseBlockIndex();
        if (settings.GetUseLogicalNameReferencing())
        {
            CGXDLMSLNParameters p(&settings, 0, cmd,
                DLMS_GET_COMMAND_TYPE_NEXT_DATA_BLOCK, &bb, NULL, 0xff, DLMS_COMMAND_NONE);
            ret = GetLnMessages(p, tmp);
        }
        else
        {
            CGXDLMSSNParameters p(&settings, cmd, 1,
                DLMS_VARIABLE_ACCESS_SPECIFICATION_BLOCK_NUMBER_ACCESS,
                &bb, NULL);
            ret = GetSnMessages(p, tmp);
        }
    }
    reply.Set(&tmp.at(0), 0, -1);
    return ret;
}

/**
     * Split DLMS PDU to wrapper frames.
     *
     * @param settings
     *            DLMS settings.
     * @param data
     *            Wrapped data.
     * @return Wrapper frames.
*/
int CGXDLMS::GetWrapperFrame(
    CGXDLMSSettings& settings,
    DLMS_COMMAND command,
    CGXByteBuffer& data,
    CGXByteBuffer& reply)
{
    reply.Clear();
    // Add version.
    reply.SetUInt16(1);
    if (settings.IsServer())
    {
        reply.SetUInt16((unsigned short)settings.GetServerAddress());
        if (settings.GetPushClientAddress() != 0 && (command == DLMS_COMMAND_DATA_NOTIFICATION || command == DLMS_COMMAND_EVENT_NOTIFICATION))
        {
            reply.SetUInt16((unsigned short)settings.GetPushClientAddress());
        }
        else
        {
            reply.SetUInt16((unsigned short)settings.GetClientAddress());
        }
    }
    else
    {
        reply.SetUInt16((unsigned short)settings.GetClientAddress());
        reply.SetUInt16((unsigned short)settings.GetServerAddress());
    }
    // Data length.
    reply.SetUInt16((unsigned short)data.GetSize());
    // Data
    reply.Set(&data, data.GetPosition(), -1);

    // Remove sent data in server side.
    if (settings.IsServer())
    {
        if (data.GetSize() == data.GetPosition())
        {
            data.Clear();
        }
        else
        {
            data.Move(data.GetPosition(), 0, data.GetSize() - data.GetPosition());
            data.SetPosition(0);
        }
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::GetHdlcFrame(
    CGXDLMSSettings& settings,
    unsigned char frame,
    CGXByteBuffer* data,
    CGXByteBuffer& reply)
{
    reply.Clear();
    unsigned short frameSize;
    int ret, len;
    CGXByteBuffer primaryAddress, secondaryAddress;
    if (settings.IsServer())
    {
        if (frame == 0x13 && settings.GetPushClientAddress() != 0)
        {
            if ((ret = GetAddressBytes(settings.GetPushClientAddress(), primaryAddress)) != 0)
            {
                return ret;
            }
        }
        else
        {
            if ((ret = GetAddressBytes(settings.GetClientAddress(), primaryAddress)) != 0)
            {
                return ret;
            }
        }
        if ((ret = GetAddressBytes(settings.GetServerAddress(), secondaryAddress)) != 0)
        {
            return ret;
        }
    }
    else
    {
        if ((ret = GetAddressBytes(settings.GetServerAddress(), primaryAddress)) != 0)
        {
            return ret;
        }
        if ((ret = GetAddressBytes(settings.GetClientAddress(), secondaryAddress)) != 0)
        {
            return ret;
        }
    }

    // Add BOP
    reply.SetUInt8(HDLC_FRAME_START_END);
    frameSize = settings.GetHdlcSettings().GetMaxInfoTX();
    if (data != NULL && data->GetPosition() == 0)
    {
        frameSize -= 3;
    }
    // If no data
    if (data == NULL || data->GetSize() == 0)
    {
        len = 0;
        reply.SetUInt8(0xA0);
    }
    else if (data->GetSize() - data->GetPosition() <= frameSize)
    {
        len = data->Available();
        // Is last packet.
        reply.SetUInt8(0xA0 | (((7 + primaryAddress.GetSize() +
            secondaryAddress.GetSize() + len) >> 8) & 0x7));
    }
    else
    {
        len = frameSize;
        // More data to left.
        reply.SetUInt8(0xA8 | (((7 + primaryAddress.GetSize() +
            secondaryAddress.GetSize() + len) >> 8) & 0x7));
    }
    // Frame len.
    if (len == 0)
    {
        reply.SetUInt8((unsigned char)(5 + primaryAddress.GetSize() +
            secondaryAddress.GetSize() + len));
    }
    else
    {
        reply.SetUInt8((unsigned char)(7 + primaryAddress.GetSize() +
            secondaryAddress.GetSize() + len));
    }
    // Add primary address.
    reply.Set(&primaryAddress);
    // Add secondary address.
    reply.Set(&secondaryAddress);

    // Add frame ID.
    if (frame == 0)
    {
        reply.SetUInt8(settings.GetNextSend(1));
    }
    else
    {
        reply.SetUInt8(frame);
    }
    // Add header CRC.
    int crc = CountFCS16(reply, 1, reply.GetSize() - 1);
    reply.SetUInt16(crc);
    if (len != 0)
    {
        // Add data.
        reply.Set(data, data->GetPosition(), len);
        // Add data CRC.
        crc = CountFCS16(reply, 1, reply.GetSize() - 1);
        reply.SetUInt16(crc);
    }
    // Add EOP
    reply.SetUInt8(HDLC_FRAME_START_END);
    // Remove sent data in server side.
    if (settings.IsServer())
    {
        if (data != NULL)
        {
            if (data->GetSize() == data->GetPosition())
            {
                data->Clear();
            }
            else
            {
                data->Move(data->GetPosition(), 0, data->GetSize() - data->GetPosition());
                data->SetPosition(0);
            }
        }
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::GetMacFrame(
    CGXDLMSSettings& settings,
    unsigned char frame,
    unsigned char creditFields,
    CGXByteBuffer* data,
    CGXByteBuffer& reply)
{
    if (settings.GetInterfaceType() == DLMS_INTERFACE_TYPE_PLC)
    {
        return GetPlcFrame(settings, creditFields, data, reply);
    }
    return GetMacHdlcFrame(settings, frame, creditFields, data, reply);
}

int CGXDLMS::GetPlcFrame(
    CGXDLMSSettings& settings,
    unsigned char creditFields,
    CGXByteBuffer* data,
    CGXByteBuffer& reply)
{
    int frameSize = data->Available();
    //Max frame size is 124 bytes.
    if (frameSize > 134)
    {
        frameSize = 134;
    }
    //PAD Length.
    int padLen = (36 - ((11 + frameSize) % 36)) % 36;
    reply.Capacity(15 + frameSize + padLen);
    //Add STX
    reply.SetUInt8(2);
    //Length.
    reply.SetUInt8((11 + frameSize));
    //Length.
    reply.SetUInt8(0x50);
    //Add  Credit fields.
    reply.SetUInt8(creditFields);
    //Add source and target MAC addresses.
    reply.SetUInt8((settings.GetPlcSettings().GetMacSourceAddress() >> 4));
    int val = settings.GetPlcSettings().GetMacSourceAddress() << 12;
    val |= settings.GetPlcSettings().GetMacDestinationAddress() & 0xFFF;
    reply.SetUInt16(val);
    reply.SetUInt8(padLen);
    //Control byte.
    reply.SetUInt8(DLMS_PLC_DATA_LINK_DATA_REQUEST);
    reply.SetUInt8((unsigned char)settings.GetServerAddress());
    reply.SetUInt8((unsigned char)settings.GetClientAddress());
    reply.Set(data, data->GetPosition(), frameSize);
    //Add padding.
    while (padLen != 0)
    {
        reply.SetUInt8(0);
        --padLen;
    }
    //Checksum.
    uint16_t crc = CountFCS16(reply, 0, reply.GetSize());
    reply.SetUInt16(crc);
    //Remove sent data in server side.
    if (settings.IsServer())
    {
        if (data->GetSize() == data->GetPosition())
        {
            data->Clear();
        }
        else
        {
            data->Move(data->GetPosition(), 0, data->GetSize() - data->GetPosition());
            data->SetPosition(0);
        }
    }
    return 0;
}

int CGXDLMS::GetMacHdlcFrame(
    CGXDLMSSettings& settings,
    unsigned char frame,
    unsigned char creditFields,
    CGXByteBuffer* data,
    CGXByteBuffer& reply)
{
    if (settings.GetHdlcSettings().GetMaxInfoTX() > 126)
    {
        settings.GetHdlcSettings().SetMaxInfoTX(86);
    };
    int ret;
    CGXByteBuffer tmp;
    //Length is updated last.
    reply.SetUInt16(0);
    //Add  Credit fields.
    reply.SetUInt8(creditFields);
    //Add source and target MAC addresses.
    reply.SetUInt8((settings.GetPlcSettings().GetMacSourceAddress() >> 4));
    int val = settings.GetPlcSettings().GetMacSourceAddress() << 12;
    val |= settings.GetPlcSettings().GetMacDestinationAddress() & 0xFFF;
    reply.SetUInt16(val);
    if ((ret = CGXDLMS::GetHdlcFrame(settings, frame, data, tmp)) == 0)
    {
        unsigned char padLen = (unsigned char)((36 - ((10 + tmp.GetSize()) % 36)) % 36);
        reply.SetUInt8(padLen);
        reply.Set(&tmp);
        //Add padding.
        while (padLen != 0)
        {
            reply.SetUInt8(0);
            --padLen;
        }
        //Checksum.
        uint32_t crc = CountFCS24(reply.GetData(), 2, reply.GetSize() - 2 - padLen);
        reply.SetUInt8((crc >> 16));
        reply.SetUInt16(crc);
        //Add NC
        val = reply.GetSize() / 36;
        if (reply.GetSize() % 36 != 0)
        {
            ++val;
        }
        if (val == 1)
        {
            val = DLMS_PLC_MAC_SUB_FRAMES_ONE;
        }
        else if (val == 2)
        {
            val = DLMS_PLC_MAC_SUB_FRAMES_TWO;
        }
        else if (val == 3)
        {
            val = DLMS_PLC_MAC_SUB_FRAMES_THREE;
        }
        else if (val == 4)
        {
            val = DLMS_PLC_MAC_SUB_FRAMES_FOUR;
        }
        else if (val == 5)
        {
            val = DLMS_PLC_MAC_SUB_FRAMES_FIVE;
        }
        else if (val == 6)
        {
            val = DLMS_PLC_MAC_SUB_FRAMES_SIX;
        }
        else if (val == 7)
        {
            val = DLMS_PLC_MAC_SUB_FRAMES_SEVEN;
        }
        else
        {
            return DLMS_ERROR_CODE_OUTOFMEMORY;
        }
        ret = reply.SetUInt16(0, val);
    }
    return ret;
}

/*
* Get used ded message.
*
* command: Executed DLMS_COMMAND_
* Returns Integer value of ded message.
*/
unsigned char GetDedMessage(DLMS_COMMAND command)
{
    unsigned char cmd;
    switch (command)
    {
    case DLMS_COMMAND_READ_REQUEST:
        cmd = DLMS_COMMAND_DED_READ_REQUEST;
        break;
    case DLMS_COMMAND_GET_REQUEST:
        cmd = DLMS_COMMAND_DED_GET_REQUEST;
        break;
    case DLMS_COMMAND_WRITE_REQUEST:
        cmd = DLMS_COMMAND_DED_WRITE_REQUEST;
        break;
    case DLMS_COMMAND_SET_REQUEST:
        cmd = DLMS_COMMAND_DED_SET_REQUEST;
        break;
    case DLMS_COMMAND_METHOD_REQUEST:
        cmd = DLMS_COMMAND_DED_METHOD_REQUEST;
        break;
    case DLMS_COMMAND_READ_RESPONSE:
        cmd = DLMS_COMMAND_DED_READ_RESPONSE;
        break;
    case DLMS_COMMAND_GET_RESPONSE:
        cmd = DLMS_COMMAND_DED_GET_RESPONSE;
        break;
    case DLMS_COMMAND_WRITE_RESPONSE:
        cmd = DLMS_COMMAND_DED_WRITE_RESPONSE;
        break;
    case DLMS_COMMAND_SET_RESPONSE:
        cmd = DLMS_COMMAND_DED_SET_RESPONSE;
        break;
    case DLMS_COMMAND_METHOD_RESPONSE:
        cmd = DLMS_COMMAND_DED_METHOD_RESPONSE;
        break;
    case DLMS_COMMAND_DATA_NOTIFICATION:
        cmd = DLMS_COMMAND_GENERAL_DED_CIPHERING;
        break;
    case DLMS_COMMAND_RELEASE_REQUEST:
        cmd = DLMS_COMMAND_RELEASE_REQUEST;
        break;
    case DLMS_COMMAND_RELEASE_RESPONSE:
        cmd = DLMS_COMMAND_RELEASE_RESPONSE;
        break;
    default:
        cmd = DLMS_COMMAND_NONE;
    }
    return cmd;
}

/*
* Get used glo message.
*
* command: Executed DLMS_COMMAND_
* Returns Integer value of glo message.
*/
unsigned char GetGloMessage(DLMS_COMMAND command)
{
    unsigned char cmd;
    switch (command)
    {
    case DLMS_COMMAND_READ_REQUEST:
        cmd = DLMS_COMMAND_GLO_READ_REQUEST;
        break;
    case DLMS_COMMAND_GET_REQUEST:
        cmd = DLMS_COMMAND_GLO_GET_REQUEST;
        break;
    case DLMS_COMMAND_WRITE_REQUEST:
        cmd = DLMS_COMMAND_GLO_WRITE_REQUEST;
        break;
    case DLMS_COMMAND_SET_REQUEST:
        cmd = DLMS_COMMAND_GLO_SET_REQUEST;
        break;
    case DLMS_COMMAND_METHOD_REQUEST:
        cmd = DLMS_COMMAND_GLO_METHOD_REQUEST;
        break;
    case DLMS_COMMAND_READ_RESPONSE:
        cmd = DLMS_COMMAND_GLO_READ_RESPONSE;
        break;
    case DLMS_COMMAND_GET_RESPONSE:
        cmd = DLMS_COMMAND_GLO_GET_RESPONSE;
        break;
    case DLMS_COMMAND_WRITE_RESPONSE:
        cmd = DLMS_COMMAND_GLO_WRITE_RESPONSE;
        break;
    case DLMS_COMMAND_SET_RESPONSE:
        cmd = DLMS_COMMAND_GLO_SET_RESPONSE;
        break;
    case DLMS_COMMAND_METHOD_RESPONSE:
        cmd = DLMS_COMMAND_GLO_METHOD_RESPONSE;
        break;
    case DLMS_COMMAND_DATA_NOTIFICATION:
        cmd = DLMS_COMMAND_GENERAL_GLO_CIPHERING;
        break;
    case DLMS_COMMAND_RELEASE_REQUEST:
        cmd = DLMS_COMMAND_RELEASE_REQUEST;
        break;
    case DLMS_COMMAND_RELEASE_RESPONSE:
        cmd = DLMS_COMMAND_RELEASE_RESPONSE;
        break;
    default:
        cmd = DLMS_COMMAND_NONE;
    }
    return cmd;
}

unsigned char GetInvokeIDPriority(CGXDLMSSettings& settings, bool increase)
{
    unsigned char value = 0;
    if (settings.GetPriority() == DLMS_PRIORITY_HIGH)
    {
        value = 0x80;
    }
    if (settings.GetServiceClass() == DLMS_SERVICE_CLASS_CONFIRMED)
    {
        value |= 0x40;
    }
    if (increase)
    {
        settings.SetInvokeID((unsigned char)((settings.GetInvokeID() + 1) & 0xF));
    }
    value |= settings.GetInvokeID() & 0xF;
    return value;
}

/**
     * Generates Invoke ID and priority.
     *
     * @param settings
     *            DLMS settings.
     * @return Invoke ID and priority.
     */
long GetLongInvokeIDPriority(CGXDLMSSettings& settings)
{
    long value = 0;
    if (settings.GetPriority() == DLMS_PRIORITY_HIGH)
    {
        value = 0x80000000;
    }
    if (settings.GetServiceClass() == DLMS_SERVICE_CLASS_CONFIRMED)
    {
        value |= 0x40000000;
    }
    value |= (settings.GetLongInvokeID() & 0xFFFFFF);
    settings.SetLongInvokeID(settings.GetLongInvokeID() + 1);
    return value;
}

/**
     * Add LLC bytes to generated message.
     *
     * @param settings
     *            DLMS settings.
     * @param data
     *            Data where bytes are added.
     */
void AddLLCBytes(CGXDLMSSettings* settings, CGXByteBuffer& data)
{
    CGXByteBuffer tmp;
    tmp.Set(&data);
    data.Clear();
    if (settings->IsServer())
    {
        data.Set(LLC_REPLY_BYTES, 3);
    }
    else
    {
        data.Set(LLC_SEND_BYTES, 3);
    }
    data.Set(&tmp);
}

/**
     * Check is all data fit to one data block.
     *
     * @param p
     *            LN parameters.
     * @param reply
     *            Generated reply.
     */
void MultipleBlocks(
    CGXDLMSLNParameters& p,
    CGXByteBuffer& reply,
    unsigned char ciphering)
{
    // Check is all data fit to one message if data is given.
    int len = p.GetData()->GetSize() - p.GetData()->GetPosition();
    if (p.GetAttributeDescriptor() != NULL)
    {
        len += p.GetAttributeDescriptor()->GetSize();
    }
    if (ciphering)
    {
        len += CIPHERING_HEADER_SIZE;
    }
    if (!p.IsMultipleBlocks())
    {
        // Add command type and invoke and priority.
        p.SetMultipleBlocks(2 + reply.GetSize() + len > p.GetSettings()->GetMaxPduSize());
    }
    if (p.IsMultipleBlocks())
    {
        // Add command type and invoke and priority.
        p.SetLastBlock(!(8 + reply.GetSize() + len > p.GetSettings()->GetMaxPduSize()));
    }
    if (p.IsLastBlock())
    {
        // Add command type and invoke and priority.
        p.SetLastBlock(!(8 + reply.GetSize() + len > p.GetSettings()->GetMaxPduSize()));
    }
}

unsigned char IsGloMessage(unsigned char cmd)
{
    return cmd == DLMS_COMMAND_GLO_GET_REQUEST ||
        cmd == DLMS_COMMAND_GLO_SET_REQUEST ||
        cmd == DLMS_COMMAND_GLO_METHOD_REQUEST;
}

int Cipher0(CGXDLMSLNParameters& p,
    CGXByteBuffer& reply)
{
    int ret;
    CGXByteBuffer tmp;
    CGXByteBuffer* key;
    unsigned char cmd;
    // If client.
    if (p.GetCipheredCommand() == DLMS_COMMAND_NONE) {
        if (((p.GetSettings()->GetConnected() & DLMS_CONNECTION_STATE_DLMS) == 0 ||
            (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_PROTECTION) == 0) &&
            (p.GetSettings()->GetPreEstablishedSystemTitle().GetSize() == 0 || (p.GetSettings()->GetProposedConformance() & DLMS_CONFORMANCE_GENERAL_PROTECTION) == 0))
        {
            if (p.GetSettings()->GetCipher()->GetDedicatedKey().GetSize() != 0 &&
                (p.GetSettings()->GetConnected() & DLMS_CONNECTION_STATE_DLMS) != 0)
            {
                cmd = GetDedMessage(p.GetCommand());
                key = &p.GetSettings()->GetCipher()->GetDedicatedKey();
            }
            else
            {
                cmd = GetGloMessage(p.GetCommand());
                key = &p.GetSettings()->GetCipher()->GetBlockCipherKey();
            }
        }
        else
        {
            if (p.GetSettings()->GetCipher()->GetDedicatedKey().GetSize() != 0)
            {
                cmd = DLMS_COMMAND_GENERAL_DED_CIPHERING;
                key = &p.GetSettings()->GetCipher()->GetDedicatedKey();
            }
            else
            {
                cmd = DLMS_COMMAND_GENERAL_GLO_CIPHERING;
                key = &p.GetSettings()->GetCipher()->GetBlockCipherKey();
            }
        }
    }
    else // If server.
    {
        if (p.GetCipheredCommand() == DLMS_COMMAND_GENERAL_DED_CIPHERING)
        {
            cmd = DLMS_COMMAND_GENERAL_DED_CIPHERING;
            key = &p.GetSettings()->GetCipher()->GetDedicatedKey();
        }
        else if (p.GetCipheredCommand() == DLMS_COMMAND_GENERAL_GLO_CIPHERING)
        {
            cmd = DLMS_COMMAND_GENERAL_GLO_CIPHERING;
            key = &p.GetSettings()->GetCipher()->GetBlockCipherKey();
        }
        else if (IsGloMessage(p.GetCipheredCommand()))
        {
            cmd = GetGloMessage(p.GetCommand());
            key = &p.GetSettings()->GetCipher()->GetBlockCipherKey();
        }
        else {
            cmd = GetDedMessage(p.GetCommand());
            key = &p.GetSettings()->GetCipher()->GetDedicatedKey();
        }
    }
    CGXByteBuffer& title = p.GetSettings()->GetCipher()->GetSystemTitle();
    ret = p.GetSettings()->GetCipher()->Encrypt(
        p.GetSettings()->GetCipher()->GetSecuritySuite(),
        p.GetSettings()->GetCipher()->GetSecurity(),
        DLMS_COUNT_TYPE_PACKET,
        p.GetSettings()->GetCipher()->GetFrameCounter(),
        cmd,
        title,
        *key,
        reply,
        true);
    if (ret != 0)
    {
        return ret;
    }
    return 0;
}

int CGXDLMS::GetLNPdu(
    CGXDLMSLNParameters& p,
    CGXByteBuffer& reply)
{
    int ret;
    unsigned char ciphering = p.GetCommand() != DLMS_COMMAND_AARQ && p.GetCommand() != DLMS_COMMAND_AARE
        && p.GetSettings()->GetCipher() != NULL
        && p.GetSettings()->GetCipher()->GetSecurity() != DLMS_SECURITY_NONE;
    int len = 0;
    if (p.GetCommand() == DLMS_COMMAND_AARQ)
    {
        reply.Set(p.GetAttributeDescriptor());
    }
    else
    {
        if (p.GetCommand() != DLMS_COMMAND_GENERAL_BLOCK_TRANSFER)
        {
            // Add DLMS_COMMAND_
            reply.SetUInt8((unsigned char)p.GetCommand());
        }

        if (p.GetCommand() == DLMS_COMMAND_EVENT_NOTIFICATION ||
            p.GetCommand() == DLMS_COMMAND_DATA_NOTIFICATION ||
            p.GetCommand() == DLMS_COMMAND_ACCESS_REQUEST ||
            p.GetCommand() == DLMS_COMMAND_ACCESS_RESPONSE)
        {
            // Add Long-Invoke-Id-And-Priority
            if (p.GetCommand() != DLMS_COMMAND_EVENT_NOTIFICATION)
            {
                if (p.GetInvokeId() != 0)
                {
                    reply.SetUInt32(p.GetInvokeId());
                }
                else
                {
                    reply.SetUInt32(GetLongInvokeIDPriority(*p.GetSettings()));
                }
            }

            // Add date time.
            if (p.GetTime() == NULL)
            {
                reply.SetUInt8(DLMS_DATA_TYPE_NONE);
            }
            else
            {
                // Data is send in octet string. Remove data type except from event Notification.
                int pos = reply.GetSize();
                CGXDLMSVariant tmp = *p.GetTime();
                if ((ret = GXHelpers::SetData(p.GetSettings(), reply, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
                {
                    return ret;
                }
                if (p.GetCommand() != DLMS_COMMAND_EVENT_NOTIFICATION)
                {
                    reply.Move(pos + 1, pos, reply.GetSize() - pos - 1);
                }
            }
        }
        else if (p.GetCommand() != DLMS_COMMAND_RELEASE_REQUEST && p.GetCommand() != DLMS_COMMAND_EXCEPTION_RESPONSE)
        {
            // Get request size can be bigger than PDU size.
            if (p.GetCommand() != DLMS_COMMAND_GET_REQUEST && p.GetData() != NULL
                && p.GetData()->GetSize() != 0)
            {
                MultipleBlocks(p, reply, ciphering);
            }
            // Change Request type if Set request and multiple blocks is needed.
            if (p.GetCommand() == DLMS_COMMAND_SET_REQUEST)
            {
                if (p.IsMultipleBlocks() &&
                    (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) == 0)
                {
                    if (p.GetRequestType() == DLMS_SET_REQUEST_TYPE_NORMAL)
                    {
                        p.SetRequestType(DLMS_SET_REQUEST_TYPE_FIRST_DATA_BLOCK);
                    }
                    else if (p.GetRequestType() == DLMS_SET_REQUEST_TYPE_FIRST_DATA_BLOCK)
                    {
                        p.SetRequestType(DLMS_SET_REQUEST_TYPE_WITH_DATA_BLOCK);
                    }
                }
            }
            //Change Request type if action request and multiple blocks is needed.
            else if (p.GetCommand() == DLMS_COMMAND_METHOD_REQUEST)
            {
                if (p.IsMultipleBlocks() &&
                    (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) == 0)
                {
                    if (p.GetRequestType() == DLMS_ACTION_REQUEST_TYPE_NORMAL)
                    {
                        //Remove Method Invocation Parameters tag.
                        p.GetAttributeDescriptor()->SetSize(p.GetAttributeDescriptor()->GetSize() - 1);
                        p.SetRequestType(DLMS_ACTION_REQUEST_TYPE_WITH_FIRST_BLOCK);
                    }
                    else if (p.GetRequestType() == DLMS_ACTION_REQUEST_TYPE_WITH_FIRST_BLOCK)
                    {
                        p.SetRequestType(DLMS_ACTION_REQUEST_TYPE_WITH_BLOCK);
                    }
                }
            }
            //Change Request type if action request and multiple blocks is needed.
            else if (p.GetCommand() == DLMS_COMMAND_METHOD_RESPONSE)
            {
                if (p.IsMultipleBlocks() &&
                    (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) == 0)
                {
                    //There is no status fiel in action resonse.
                    p.SetStatus(0xFF);
                    if (p.GetRequestType() == DLMS_ACTION_RESPONSE_TYPE_NORMAL)
                    {
                        //Remove Method Invocation Parameters tag.
                        p.GetData()->SetPosition(p.GetData()->GetPosition() + 2);
                        p.SetRequestType(DLMS_ACTION_RESPONSE_TYPE_WITH_BLOCK);
                    }
                    else if (p.GetRequestType() == DLMS_ACTION_RESPONSE_TYPE_WITH_BLOCK && p.GetData()->Available() == 0)
                    {
                        //If server asks next part of PDU.
                        p.SetRequestType(DLMS_ACTION_RESPONSE_TYPE_NEXT_BLOCK);
                    }
                }
            }
            // Change request type If get response and multiple blocks is needed.
            else if (p.GetCommand() == DLMS_COMMAND_GET_RESPONSE)
            {
                if (p.IsMultipleBlocks() &&
                    (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) == 0)
                {
                    if (p.GetRequestType() == 1)
                    {
                        p.SetRequestType(2);
                    }
                }
            }
            if (p.GetCommand() != DLMS_COMMAND_GENERAL_BLOCK_TRANSFER)
            {
                reply.SetUInt8(p.GetRequestType());
                // Add Invoke Id And Priority.
                if (p.GetInvokeId() != 0)
                {
                    reply.SetUInt8((unsigned char)p.GetInvokeId());
                }
                else
                {
                    reply.SetUInt8(GetInvokeIDPriority(*p.GetSettings(), p.GetSettings()->GetAutoIncreaseInvokeID()));
                }
            }
        }

        // Add attribute descriptor.
        if (p.GetAttributeDescriptor() != NULL)
        {
            reply.Set(p.GetAttributeDescriptor(), p.GetAttributeDescriptor()->GetPosition());
        }
        // If multiple blocks.
        if (p.IsMultipleBlocks() && (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) == 0)
        {
            if (p.GetCommand() != DLMS_COMMAND_SET_RESPONSE)
            {
                // Is last block.
                if (p.IsLastBlock())
                {
                    reply.SetUInt8(1);
                    p.GetSettings()->SetCount(0);
                    p.GetSettings()->SetIndex(0);
                }
                else
                {
                    reply.SetUInt8(0);
                }
            }
            // Block index.
            reply.SetUInt32(p.GetBlockIndex());
            p.SetBlockIndex(p.GetBlockIndex() + 1);
            // Add status if reply.
            if (p.GetStatus() != 0xFF)
            {
                if (p.GetStatus() != 0 && p.GetCommand() == DLMS_COMMAND_GET_RESPONSE)
                {
                    reply.SetUInt8(1);
                }
                reply.SetUInt8(p.GetStatus());
            }
            // Block size.
            if (p.GetData() != NULL)
            {
                len = p.GetData()->GetSize() - p.GetData()->GetPosition();
            }
            else
            {
                len = 0;
            }
            int totalLength = len + reply.GetSize();
            if (ciphering)
            {
                totalLength += CIPHERING_HEADER_SIZE;
            }

            if (totalLength > p.GetSettings()->GetMaxPduSize())
            {
                len = p.GetSettings()->GetMaxPduSize() - reply.GetSize();
                if (ciphering)
                {
                    len -= CIPHERING_HEADER_SIZE;
                }
                len -= GXHelpers::GetObjectCountSizeInBytes(len);
            }
            GXHelpers::SetObjectCount(len, reply);
            reply.Set(p.GetData(), p.GetData()->GetPosition(), len);
        }
        // Add data that fits to one block.
        if (len == 0)
        {
            // Add status if reply.
            if (p.GetStatus() != 0xFF && p.GetCommand() != DLMS_COMMAND_GENERAL_BLOCK_TRANSFER)
            {
                if (p.GetStatus() != 0 && p.GetCommand() == DLMS_COMMAND_GET_RESPONSE)
                {
                    reply.SetUInt8(1);
                }
                reply.SetUInt8(p.GetStatus());
            }
            if (p.GetData() != NULL && p.GetData()->GetSize() != 0)
            {
                len = p.GetData()->GetSize() - p.GetData()->GetPosition();
                //Get request size can be bigger than PDU size.
                if ((p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) != 0)
                {
                    if (7 + len + reply.GetSize() > p.GetSettings()->GetMaxPduSize())
                    {
                        len = p.GetSettings()->GetMaxPduSize() - reply.GetSize() - 7;
                    }
                    //Cipher data only once.
                    if (ciphering && p.GetCommand() != DLMS_COMMAND_GENERAL_BLOCK_TRANSFER)
                    {
                        reply.Set(p.GetData());
                        p.GetData()->SetPosition(0);
                        if ((ret = Cipher0(p, reply)) != 0)
                        {
                            return ret;
                        }
                    }
                    ciphering = false;
                }
                // Get request size can be bigger than PDU size.
                if (p.GetCommand() != DLMS_COMMAND_GET_REQUEST && 
                    len + reply.GetSize() > p.GetSettings()->GetMaxPduSize())
                {
                    len = p.GetSettings()->GetMaxPduSize() - reply.GetSize()
                        - p.GetData()->GetPosition();
                }
                reply.Set(p.GetData(), p.GetData()->GetPosition(), len);
            }
        }

        if (ciphering && reply.GetSize() != 0 && p.GetCommand() != DLMS_COMMAND_RELEASE_REQUEST &&
            (!p.IsMultipleBlocks() || (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) == 0))
        {
            if ((ret = Cipher0(p, reply)) != 0)
            {
                return ret;
            }
        }

        if (p.GetCommand() == DLMS_COMMAND_GENERAL_BLOCK_TRANSFER || 
            (p.IsMultipleBlocks() && 
             (p.GetSettings()->GetNegotiatedConformance() & DLMS_CONFORMANCE_GENERAL_BLOCK_TRANSFER) != 0))
        {
            CGXByteBuffer bb;
            bb.Set(&reply);
            reply.Clear();
            reply.SetUInt8(DLMS_COMMAND_GENERAL_BLOCK_TRANSFER);
            unsigned char value = 0;
            // Is last block
            if (p.IsLastBlock())
            {
                value = 0x80;
            }
            else if (p.GetStreaming())
            {
                value |= 0x40;
            }
            value |= p.GetWindowSize();
            reply.SetUInt8(value);
            // Set block number sent.
            reply.SetUInt16((unsigned short)p.GetBlockIndex());
            p.SetBlockIndex(p.GetBlockIndex() + 1);
            // Set block number acknowledged
            if (p.GetCommand() != DLMS_COMMAND_DATA_NOTIFICATION && p.GetBlockNumberAck() != 0)
            {
                // Set block number acknowledged
                reply.SetUInt16(p.GetBlockNumberAck());
                p.SetBlockNumberAck(p.GetBlockNumberAck() + 1);
            }
            else
            {
                p.SetBlockNumberAck(-1);
                reply.SetUInt16(0);
            }
            //Add data length.
            GXHelpers::SetObjectCount(bb.GetSize(), reply);
            reply.Set(&bb);
            if (p.GetCommand() != DLMS_COMMAND_GENERAL_BLOCK_TRANSFER)
            {
                p.SetCommand(DLMS_COMMAND_GENERAL_BLOCK_TRANSFER);
                p.SetBlockNumberAck(p.GetBlockNumberAck() + 1);
            }
        }
    }
    if (UseHdlc(p.GetSettings()->GetInterfaceType()))
    {
        AddLLCBytes(p.GetSettings(), reply);
    }
    return 0;
}

int CGXDLMS::GetLnMessages(
    CGXDLMSLNParameters& p,
    std::vector<CGXByteBuffer>& messages)
{
    int ret;
    messages.clear();
    CGXByteBuffer reply, tmp;
    unsigned char frame = 0;
    if (p.GetCommand() == DLMS_COMMAND_DATA_NOTIFICATION ||
        p.GetCommand() == DLMS_COMMAND_EVENT_NOTIFICATION)
    {
        frame = 0x13;
    }
    do
    {
        if ((ret = GetLNPdu(p, reply)) != 0)
        {
            return ret;
        }
        p.SetLastBlock(true);
        if (p.GetAttributeDescriptor() == NULL)
        {
            p.GetSettings()->IncreaseBlockIndex();
        }
        while (reply.GetPosition() != reply.GetSize())
        {
            switch (p.GetSettings()->GetInterfaceType())
            {
            case DLMS_INTERFACE_TYPE_WRAPPER:
                ret = GetWrapperFrame(*p.GetSettings(), p.GetCommand(), reply, tmp);
                break;
            case DLMS_INTERFACE_TYPE_HDLC:
            case DLMS_INTERFACE_TYPE_HDLC_WITH_MODE_E:
                ret = GetHdlcFrame(*p.GetSettings(), frame, &reply, tmp);
                if (ret == 0 && reply.GetPosition() != reply.GetSize())
                {
                    frame = p.GetSettings()->GetNextSend(0);
                }
                break;
            case DLMS_INTERFACE_TYPE_PDU:
                tmp = reply;
                reply.SetPosition(reply.GetSize());
                break;
            case DLMS_INTERFACE_TYPE_PLC:
                ret = GetPlcFrame(*p.GetSettings(), 0x90, &reply, tmp);
                break;
            case DLMS_INTERFACE_TYPE_PLC_HDLC:
                ret = GetMacHdlcFrame(*p.GetSettings(), frame, 0, &reply, tmp);
                break;
            default:
                ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
            }
            if (ret != 0)
            {
                break;
            }
            messages.push_back(tmp);
            tmp.Clear();
        }
        reply.Clear();
        frame = 0;
    } while (ret == 0 && p.GetData() != NULL && p.GetData()->GetPosition() != p.GetData()->GetSize());
    return ret;
}

int CGXDLMS::AppendMultipleSNBlocks(
    CGXDLMSSNParameters& p,
    CGXByteBuffer& reply)
{
    bool ciphering = p.GetSettings()->GetCipher() != NULL && p.GetSettings()->GetCipher()->GetSecurity() != DLMS_SECURITY_NONE;
    unsigned long hSize = reply.GetSize() + 3;
    // Add LLC bytes.
    if (p.GetCommand() == DLMS_COMMAND_WRITE_REQUEST
        || p.GetCommand() == DLMS_COMMAND_READ_REQUEST)
    {
        hSize += 1 + GXHelpers::GetObjectCountSizeInBytes(p.GetCount());
    }
    unsigned long maxSize = p.GetSettings()->GetMaxPduSize() - hSize;
    if (ciphering)
    {
        maxSize -= CIPHERING_HEADER_SIZE;
        if (UseHdlc(p.GetSettings()->GetInterfaceType()))
        {
            maxSize -= 3;
        }
    }
    maxSize -= GXHelpers::GetObjectCountSizeInBytes(maxSize);
    if (p.GetData()->GetSize() - p.GetData()->GetPosition() > maxSize)
    {
        // More blocks.
        reply.SetUInt8(0);
    }
    else
    {
        // Last block.
        reply.SetUInt8(1);
        maxSize = p.GetData()->GetSize() - p.GetData()->GetPosition();
    }
    // Add block index.
    reply.SetUInt16(p.GetBlockIndex());
    if (p.GetCommand() == DLMS_COMMAND_WRITE_REQUEST)
    {
        p.SetBlockIndex(p.GetBlockIndex() + 1);
        GXHelpers::SetObjectCount(p.GetCount(), reply);
        reply.SetUInt8(DLMS_DATA_TYPE_OCTET_STRING);
    }
    else if (p.GetCommand() == DLMS_COMMAND_READ_REQUEST)
    {
        p.SetBlockIndex(p.GetBlockIndex() + 1);
    }

    GXHelpers::SetObjectCount(maxSize, reply);
    return maxSize;
}

int CGXDLMS::GetSNPdu(
    CGXDLMSSNParameters& p,
    CGXByteBuffer& reply)
{
    int ret;
    unsigned char ciphering = p.GetCommand() != DLMS_COMMAND_AARQ && p.GetCommand() != DLMS_COMMAND_AARE
        && p.GetSettings()->GetCipher() != NULL
        && p.GetSettings()->GetCipher()->GetSecurity() != DLMS_SECURITY_NONE;
    if (!ciphering && UseHdlc(p.GetSettings()->GetInterfaceType()))
    {
        AddLLCBytes(p.GetSettings(), reply);
    }
    int cnt = 0, cipherSize = 0;
    if (ciphering)
    {
        cipherSize = CIPHERING_HEADER_SIZE;
    }
    if (p.GetData() != NULL)
    {
        cnt = p.GetData()->GetSize() - p.GetData()->GetPosition();
    }
    // Add DLMS command.
    if (p.GetCommand() == DLMS_COMMAND_INFORMATION_REPORT)
    {
        reply.SetUInt8(p.GetCommand());
        // Add date time.
        if (p.GetTime() == NULL)
        {
            reply.SetUInt8(DLMS_DATA_TYPE_NONE);
        }
        else
        {
            // Data is send in octet string. Remove data type.
            int pos = reply.GetSize();
            CGXDLMSVariant tmp = *p.GetTime();
            if ((ret = GXHelpers::SetData(p.GetSettings(), reply, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
            {
                return ret;
            }
            reply.Move(pos + 1, pos, reply.GetSize() - pos - 1);
        }
        GXHelpers::SetObjectCount(p.GetCount(), reply);
        reply.Set(p.GetAttributeDescriptor());
    }
    else if (p.GetCommand() != DLMS_COMMAND_AARQ && p.GetCommand() != DLMS_COMMAND_AARE)
    {
        reply.SetUInt8((unsigned char)p.GetCommand());
        if (p.GetCount() != 0xFF)
        {
            GXHelpers::SetObjectCount(p.GetCount(), reply);
        }
        if (p.GetRequestType() != 0xFF)
        {
            reply.SetUInt8(p.GetRequestType());
        }
        reply.Set(p.GetAttributeDescriptor());

        if (!p.IsMultipleBlocks())
        {
            p.SetMultipleBlocks(reply.GetSize() + cipherSize + cnt > p.GetSettings()->GetMaxPduSize());
            // If reply data is not fit to one PDU.
            if (p.IsMultipleBlocks())
            {
                reply.SetSize(0);
                if (!ciphering && UseHdlc(p.GetSettings()->GetInterfaceType()))
                {
                    AddLLCBytes(p.GetSettings(), reply);
                }
                if (p.GetCommand() == DLMS_COMMAND_WRITE_REQUEST)
                {
                    p.SetRequestType(
                        DLMS_VARIABLE_ACCESS_SPECIFICATION_WRITE_DATA_BLOCK_ACCESS);
                }
                else if (p.GetCommand() == DLMS_COMMAND_READ_REQUEST)
                {
                    p.SetRequestType(DLMS_VARIABLE_ACCESS_SPECIFICATION_READ_DATA_BLOCK_ACCESS);
                }
                else if (p.GetCommand() == DLMS_COMMAND_READ_RESPONSE)
                {
                    p.SetRequestType(DLMS_SINGLE_READ_RESPONSE_DATA_BLOCK_RESULT);
                }
                else
                {
                    //Invalid DLMS_COMMAND_
                    return DLMS_ERROR_CODE_INVALID_COMMAND;
                }
                reply.SetUInt8((unsigned char)p.GetCommand());
                // Set object count.
                reply.SetUInt8(1);
                if (p.GetRequestType() != 0xFF)
                {
                    reply.SetUInt8(p.GetRequestType());
                }
                cnt = AppendMultipleSNBlocks(p, reply);
            }
        }
        else
        {
            cnt = AppendMultipleSNBlocks(p, reply);
        }
    }
    // Add data.
    if (p.GetData() != NULL)
    {
        reply.Set(p.GetData(), p.GetData()->GetPosition(), cnt);
    }
    // If all data is transfered.
    if (p.GetData() != NULL && p.GetData()->GetPosition() == p.GetData()->GetSize())
    {
        p.GetSettings()->SetIndex(0);
        p.GetSettings()->SetCount(0);
    }
    // If Ciphering is used.
    if (ciphering && p.GetCommand() != DLMS_COMMAND_AARQ
        && p.GetCommand() != DLMS_COMMAND_AARE)
    {
        CGXByteBuffer tmp;
        ret = p.GetSettings()->GetCipher()->Encrypt(
            p.GetSettings()->GetCipher()->GetSecuritySuite(),
            p.GetSettings()->GetCipher()->GetSecurity(),
            DLMS_COUNT_TYPE_PACKET,
            p.GetSettings()->GetCipher()->GetFrameCounter(),
            GetGloMessage(p.GetCommand()),
            p.GetSettings()->GetCipher()->GetSystemTitle(),
            p.GetSettings()->GetCipher()->GetAuthenticationKey(),
            reply,
            true);
        if (ret != 0)
        {
            return ret;
        }
        if (UseHdlc(p.GetSettings()->GetInterfaceType()))
        {
            AddLLCBytes(p.GetSettings(), reply);
        }
    }
    return 0;
}

int CGXDLMS::GetSnMessages(
    CGXDLMSSNParameters& p,
    std::vector<CGXByteBuffer>& messages)
{
    int ret;
    CGXByteBuffer data, reply;
    unsigned char frame = 0x0;
    if (p.GetCommand() == DLMS_COMMAND_INFORMATION_REPORT ||
        p.GetCommand() == DLMS_COMMAND_DATA_NOTIFICATION)
    {
        frame = 0x13;
    }
    do
    {
        ret = GetSNPdu(p, data);
        // Command is not add to next PDUs.
        while (data.GetPosition() != data.GetSize())
        {
            if (p.GetSettings()->GetInterfaceType() == DLMS_INTERFACE_TYPE_WRAPPER)
            {
                ret = GetWrapperFrame(*p.GetSettings(), p.GetCommand(), data, reply);
            }
            else
            {
                ret = GetHdlcFrame(*p.GetSettings(), frame, &data, reply);
                if (data.GetPosition() != data.GetSize())
                {
                    frame = p.GetSettings()->GetNextSend(0);
                }
            }
            if (ret != 0)
            {
                break;
            }
            messages.push_back(reply);
            reply.Clear();
        }
        reply.Clear();
        frame = 0;
    } while (ret == 0 && p.GetData() != NULL && p.GetData()->GetPosition() != p.GetData()->GetSize());
    return 0;
}

int CGXDLMS::GetHdlcData(
    bool server,
    CGXDLMSSettings& settings,
    CGXByteBuffer& reply,
    CGXReplyData& data,
    unsigned char& frame,
    CGXReplyData* notify)
{
    unsigned long packetStartID = reply.GetPosition(), frameLen = 0;
    unsigned long pos;
    unsigned char ch;
    int ret;
    unsigned short crc, crcRead;
    bool isNotify = false;
    // If whole frame is not received yet.
    if (reply.GetSize() - reply.GetPosition() < 9)
    {
        data.SetComplete(false);
        return 0;
    }
    data.SetComplete(true);
    if (notify != NULL)
    {
        notify->SetComplete(true);
    }
    // Find start of HDLC frame.
    for (pos = reply.GetPosition(); pos < reply.GetSize(); ++pos)
    {
        if ((ret = reply.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        if (ch == HDLC_FRAME_START_END)
        {
            packetStartID = pos;
            break;
        }
    }
    // Not a HDLC frame.
    // Sometimes meters can send some strange data between DLMS frames.
    if (reply.GetPosition() == reply.GetSize())
    {
        data.SetComplete(false);
        if (notify != NULL)
        {
            notify->SetComplete(false);
        }
        // Not enough data to parse;
        return 0;
    }
    if ((ret = reply.GetUInt8(&frame)) != 0)
    {
        return ret;
    }
    if ((frame & 0xF0) != 0xA0)
    {
        reply.SetPosition(reply.GetPosition() - 1);
        return GetHdlcData(server, settings, reply, data, frame, notify);
    }
    // Check frame length.
    if ((frame & 0x7) != 0)
    {
        frameLen = ((frame & 0x7) << 8);
    }
    if ((ret = reply.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    // If not enough data.
    frameLen += ch;
    if (reply.GetSize() - reply.GetPosition() + 1 < frameLen)
    {
        data.SetComplete(false);
        reply.SetPosition(packetStartID);
        // Not enough data to parse;
        return 0;
    }
    int eopPos = frameLen + packetStartID + 1;
    if ((ret = reply.GetUInt8(eopPos, &ch)) != 0)
    {
        return ret;
    }
    if (ch != HDLC_FRAME_START_END)
    {
        reply.SetPosition(reply.GetPosition() - 2);
        return GetHdlcData(server, settings, reply, data, frame, notify);
    }

    // Check addresses.
    unsigned long source, target;
    ret = CheckHdlcAddress(server, settings, reply, eopPos, source, target);
    if (ret != 0)
    {
        if (ret != DLMS_ERROR_CODE_FALSE)
        {
            return ret;
        }
        //If not notify.
        if (!(reply.GetPosition() < reply.GetSize() && reply.GetUInt8(reply.GetPosition(), &ch) == 0 && ch == 0x13))
        {
            //If echo.
            reply.SetPosition(1 + eopPos);
            return GetHdlcData(server, settings, reply, data, frame, notify);
        }
        else if (notify != NULL)
        {
            isNotify = true;
            notify->SetClientAddress((unsigned short)target);
            notify->SetServerAddress((int)source);
        }
    }
    // Is there more data available.
    bool moreData = (frame & 0x8) != 0;
    // Get frame type.
    if ((ret = reply.GetUInt8(&frame)) != 0)
    {
        return ret;
    }
    //If server is using same client and server address for notifications.
    if (frame == 0x13 && !isNotify && notify != NULL)
    {
        isNotify = true;
        notify->SetClientAddress((unsigned short)target);
        notify->SetServerAddress((int)source);
    }
    if (moreData)
    {
        if (isNotify)
        {
            notify->SetMoreData((DLMS_DATA_REQUEST_TYPES)(notify->GetMoreData() | DLMS_DATA_REQUEST_TYPES_FRAME));
        }
        else
        {
            data.SetMoreData((DLMS_DATA_REQUEST_TYPES)(data.GetMoreData() | DLMS_DATA_REQUEST_TYPES_FRAME));
        }
    }
    else
    {
        if (isNotify)
        {
            notify->SetMoreData((DLMS_DATA_REQUEST_TYPES)(notify->GetMoreData() & ~DLMS_DATA_REQUEST_TYPES_FRAME));
        }
        else
        {
            data.SetMoreData((DLMS_DATA_REQUEST_TYPES)(data.GetMoreData() & ~DLMS_DATA_REQUEST_TYPES_FRAME));
        }
    }
    if (!settings.CheckFrame(frame))
    {
        reply.SetPosition(eopPos + 1);
        return GetHdlcData(server, settings, reply, data, frame, notify);
    }
    // Check that header CRC is correct.
    crc = CountFCS16(reply, packetStartID + 1,
        reply.GetPosition() - packetStartID - 1);

    if ((ret = reply.GetUInt16(&crcRead)) != 0)
    {
        return ret;
    }
    if (crc != crcRead)
    {
        if (reply.GetSize() - reply.GetPosition() > 8)
        {
            return GetHdlcData(server, settings, reply, data, frame, notify);
        }
        return DLMS_ERROR_CODE_WRONG_CRC;
    }
    // Check that packet CRC match only if there is a data part.
    if (reply.GetPosition() != packetStartID + frameLen + 1)
    {
        crc = CountFCS16(reply, packetStartID + 1,
            frameLen - 2);
        if ((ret = reply.GetUInt16(packetStartID + frameLen - 1, &crcRead)) != 0)
        {
            return ret;
        }
        if (crc != crcRead)
        {
            return DLMS_ERROR_CODE_WRONG_CRC;
        }
        // Remove CRC and EOP from packet length.
        if (isNotify)
        {
            notify->SetPacketLength(eopPos - 2);
        }
        else
        {
            data.SetPacketLength(eopPos - 2);
        }
    }
    else
    {
        if (isNotify)
        {
            notify->SetPacketLength(reply.GetPosition() + 1);
        }
        else
        {
            data.SetPacketLength(reply.GetPosition() + 1);
        }
    }

    if (frame != 0x3 && frame != 0x13 && (frame & HDLC_FRAME_TYPE_U_FRAME) == HDLC_FRAME_TYPE_U_FRAME)
    {
        // Get Eop if there is no data.
        if (reply.GetPosition() == packetStartID + frameLen + 1)
        {
            // Get EOP.
            if ((ret = reply.GetUInt8(&ch)) != 0)
            {
                return ret;
            }
        }
        if (frame == 0x97)
        {
            return DLMS_ERROR_CODE_UNACCEPTABLE_FRAME;
        }
        data.SetCommand((DLMS_COMMAND)frame);
    }
    else if (frame != 0x3 && frame != 0x13 && frame != 0x13 && (frame & HDLC_FRAME_TYPE_S_FRAME) == HDLC_FRAME_TYPE_S_FRAME)
    {
        // If S-frame
        int tmp = (frame >> 2) & 0x3;
        // If frame is rejected.
        if (tmp == HDLC_CONTROL_FRAME_REJECT)
        {
            return DLMS_ERROR_CODE_REJECTED;
        }
        else if (tmp == HDLC_CONTROL_FRAME_RECEIVE_NOT_READY)
        {
            return DLMS_ERROR_CODE_REJECTED;
        }
        else if (tmp == HDLC_CONTROL_FRAME_RECEIVE_READY)
        {
            // Get next frame.
            //Return error if there is already reply data and meter returns RR.
            if (settings.GetCommand() == DLMS_COMMAND_GET_REQUEST ||
                settings.GetCommand() == DLMS_COMMAND_GLO_GET_REQUEST)
            {
                return DLMS_ERROR_CODE_INVALID_FRAME_NUMBER;
            }
        }
        // Get Eop if there is no data.
        if (reply.GetPosition() == packetStartID + frameLen + 1)
        {
            // Get EOP.
            if ((ret = reply.GetUInt8(&ch)) != 0)
            {
                return ret;
            }
        }
    }
    else
    {
        // I-frame
        // Get Eop if there is no data.
        if (reply.GetPosition() == packetStartID + frameLen + 1)
        {
            // Get EOP.
            if ((ret = reply.GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            if ((frame & 0x1) == 0x1)
            {
                data.SetMoreData(DLMS_DATA_REQUEST_TYPES_FRAME);
            }
        }
        else
        {
            GetLLCBytes(server, reply);
        }
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::GetHDLCAddress(
    CGXByteBuffer& buff,
    unsigned long& address)
{
    unsigned char ch;
    unsigned short s;
    unsigned long l;
    int ret, size = 0;
    address = 0;
    for (unsigned long pos = buff.GetPosition(); pos != buff.GetSize(); ++pos)
    {
        ++size;
        if ((ret = buff.GetUInt8(pos, &ch)) != 0)
        {
            return ret;
        }
        if ((ch & 0x1) == 1)
        {
            break;
        }
    }
    if (size == 1)
    {
        if ((ret = buff.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        address = ((ch & 0xFE) >> 1);
    }
    else if (size == 2)
    {
        if ((ret = buff.GetUInt16(&s)) != 0)
        {
            return ret;
        }
        address = ((s & 0xFE) >> 1) | ((s & 0xFE00) >> 2);
    }
    else if (size == 4)
    {
        if ((ret = buff.GetUInt32(&l)) != 0)
        {
            return ret;
        }
        address = ((l & 0xFE) >> 1) | ((l & 0xFE00) >> 2)
            | ((l & 0xFE0000) >> 3) | ((l & 0xFE000000) >> 4);
    }
    else
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    return DLMS_ERROR_CODE_OK;
}

static void GetServerAddress(int address, int& logical, int& physical)
{
    if (address < 0x4000)
    {
        logical = address >> 7;
        physical = address & 0x7F;
    }
    else
    {
        logical = address >> 14;
        physical = address & 0x3FFF;
    }
}

int CGXDLMS::CheckHdlcAddress(
    bool server,
    CGXDLMSSettings& settings,
    CGXByteBuffer& reply,
    int index,
    unsigned long& source,
    unsigned long& target)
{
    unsigned char ch;
    int ret;
    // Get destination and source addresses.
    if ((ret = GetHDLCAddress(reply, target)) != 0)
    {
        return ret;
    }
    if ((ret = GetHDLCAddress(reply, source)) != 0)
    {
        return ret;
    }
    if (server)
    {
        // Check that server addresses match.
        if (settings.GetServerAddress() != 0 && settings.GetServerAddress() != target)
        {
            // Get frame DLMS_COMMAND_
            if (reply.GetUInt8(reply.GetPosition(), &ch) != 0)
            {
                return DLMS_ERROR_CODE_INVALID_SERVER_ADDRESS;
            }
            //If SNRM and client has not call disconnect and changes client ID.
            if (ch == DLMS_COMMAND_SNRM)
            {
                settings.SetServerAddress(target);
            }
            else
            {
                return DLMS_ERROR_CODE_INVALID_SERVER_ADDRESS;
            }
        }
        else
        {
            settings.SetServerAddress(target);
        }

        // Check that client addresses match.
        if (settings.GetClientAddress() != 0 && settings.GetClientAddress() != source)
        {
            // Get frame DLMS_COMMAND_
            if (reply.GetUInt8(reply.GetPosition(), &ch) != 0)
            {
                return DLMS_ERROR_CODE_INVALID_CLIENT_ADDRESS;
            }
            //If SNRM and client has not call disconnect and changes client ID.
            if (ch == DLMS_COMMAND_SNRM)
            {
                settings.SetClientAddress(source);
            }
            else
            {
                return DLMS_ERROR_CODE_INVALID_CLIENT_ADDRESS;
            }
        }
        else
        {
            settings.SetClientAddress(source);
        }
    }
    else
    {
        // Check that client addresses match.
        if (settings.GetClientAddress() != target)
        {
            // If echo.
            if (settings.GetClientAddress() == source && settings.GetServerAddress() == target)
            {
                reply.SetPosition(index + 1);
            }
            return DLMS_ERROR_CODE_FALSE;
        }
        // Check that server addresses match.
        if (settings.GetServerAddress() != source &&
            //If All-station (Broadcast).
            (settings.GetServerAddress() & 0x7F) != 0x7F &&
            (settings.GetServerAddress() & 0x3FFF) != 0x3FFF)
        {
            //Check logical and physical address separately.
            //This is done because some meters might send four bytes
            //when only two bytes is needed.
            int readLogical, readPhysical, logical, physical;
            GetServerAddress(source, readLogical, readPhysical);
            GetServerAddress(settings.GetServerAddress(), logical, physical);
            if (readLogical != logical || readPhysical != physical)
            {
                return DLMS_ERROR_CODE_FALSE;
            }
        }
    }
    return DLMS_ERROR_CODE_OK;
}


int CGXDLMS::AddInvokeId(CGXDLMSTranslatorStructure* xml, DLMS_COMMAND command, uint8_t type, uint32_t invokeId)
{
    if (xml != NULL)
    {
        xml->AppendStartTag(command);
        xml->AppendStartTag(command, type);
        std::string tmp2;
        if (xml->GetComments())
        {
            std::string sb;
            if ((invokeId & 0x80) != 0)
            {
                sb.append("Priority: High, ");
            }
            else
            {
                sb.append("Priority: Normal, ");
            }
            if ((invokeId & 0x40) != 0)
            {
                sb.append("ServiceClass: Confirmed, ");
            }
            else
            {
                sb.append("ServiceClass: UnConfirmed, ");
            }
            xml->IntegerToHex((long)invokeId & 0xF, 2, tmp2);
            sb.append("Invoke ID: " + tmp2);
            xml->AppendComment(sb);
        }
        xml->IntegerToHex((long)invokeId, 2, tmp2);
        xml->AppendLine(DLMS_TRANSLATOR_TAGS_INVOKE_ID, "", tmp2);
    }
    return 0;
}

int HandleActionResponseNormal(
    CGXDLMSSettings& settings,
    CGXReplyData& data)
{
    int ret;
    unsigned char ch, type;
    if ((ret = data.GetData().GetUInt8(&ch)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        if (data.GetXml()->GetOutputType() == DLMS_TRANSLATOR_OUTPUT_TYPE_STANDARD_XML)
        {
            data.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_SINGLE_RESPONSE);
        }
        std::string str;
        CGXDLMSTranslator::ErrorCodeToString(data.GetXml()->GetOutputType(), (DLMS_ERROR_CODE)ch, str);
        data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_RESULT, "", str);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    if (ch != 0)
    {
        return ch;
    }
    settings.ResetBlockIndex();
    // Response normal. Get data if exists.
    if (data.GetData().GetPosition() < data.GetData().GetSize())
    {
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        if (ch == 0)
        {
            GetDataFromBlock(data.GetData(), 0);
        }
        else if (ch == 1)
        {
            //Get Data-Access-Result
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            if (ch != 0)
            {

                if ((ret = data.GetData().GetUInt8(&type)) != 0)
                {
                    return ret;
                }
                //Handle Texas Instrument missing byte here.
                if (ch == 9 && type == 16)
                {
                    data.GetData().SetPosition(data.GetData().GetPosition() - 2);
                    GetDataFromBlock(data.GetData(), 0);
                }
                else
                {
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                    if (data.GetXml() == NULL)
                    {
                        return type;
                    }
#else
                    return type;
#endif //DLMS_IGNORE_XML_TRANSLATOR
                }
            }
            else
            {
                GetDataFromBlock(data.GetData(), 0);
            }
        }
        else
        {
            //Invalid tag.
            return DLMS_ERROR_CODE_INVALID_TAG;
        }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        if (data.GetXml() != NULL && (ch != 0 || data.GetData().GetPosition() < data.GetData().GetSize()))
        {
            data.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_RETURN_PARAMETERS);
            if (ch != 0)
            {
                std::string str;
                CGXDLMSTranslator::ErrorCodeToString(data.GetXml()->GetOutputType(), (DLMS_ERROR_CODE)type, str);
                data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_DATA_ACCESS_ERROR, "", str);
            }
            else
            {
                CGXDataInfo di;
                CGXDLMSVariant value;
                data.GetXml()->AppendStartTag(DLMS_COMMAND_READ_RESPONSE, DLMS_SINGLE_READ_RESPONSE_DATA);
                di.SetXml(data.GetXml());
                if ((ret = GXHelpers::GetData(&settings, data.GetData(), di, value)) != 0)
                {
                    return ret;
                }
                data.GetXml()->AppendEndTag(DLMS_COMMAND_READ_RESPONSE, (unsigned long)DLMS_SINGLE_READ_RESPONSE_DATA);
            }
            data.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_RETURN_PARAMETERS);
            if (data.GetXml()->GetOutputType() == DLMS_TRANSLATOR_OUTPUT_TYPE_STANDARD_XML)
            {
                data.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_SINGLE_RESPONSE);
            }
        }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    }
    return 0;
}

int HandleActionResponseWithBlock(
    CGXDLMSSettings& settings,
    CGXReplyData& reply,
    unsigned long index)
{
    int ret = 0;
    unsigned char ch;
    unsigned long number;
    std::string str;
    if ((ret = reply.GetData().GetUInt8(&ch)) == 0)
    {
        if (reply.GetXml() != NULL)
        {
            //Result start tag.
            reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_PBLOCK);
            //LastBlock
            reply.GetXml()->IntegerToHex((long)ch, 2, str);
            reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_LAST_BLOCK, "Value", str);
        }
        if (ch == 0)
        {
            reply.SetMoreData((DLMS_DATA_REQUEST_TYPES)(reply.GetMoreData() | DLMS_DATA_REQUEST_TYPES_BLOCK));
        }
        else
        {
            reply.SetMoreData((DLMS_DATA_REQUEST_TYPES)(reply.GetMoreData() & ~DLMS_DATA_REQUEST_TYPES_BLOCK));
        }
        // Get Block number.
        reply.GetData().GetUInt32(&number);
        if (reply.GetXml() != NULL)
        {
            //BlockNumber
            reply.GetXml()->IntegerToHex(number, 8, str);
            reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_NUMBER, "Value", str);
        }
        else
        {
            //Update  initial block index. This is critical if message is send and received in multiple blocks.
            if (number == 1)
            {
                settings.ResetBlockIndex();
            }
            if (number != settings.GetBlockIndex())
            {
                return DLMS_ERROR_CODE_INVALID_BLOCK_NUMBER;
            }
        }
        //Note! There is no status!!
        if (reply.GetXml() != NULL)
        {
            if (reply.GetData().Available() != 0)
            {
                // Get data size.
                unsigned long blockLength;
                GXHelpers::GetObjectCount(reply.GetData(), blockLength);
                // if whole block is read.
                if ((reply.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0)
                {
                    // Check Block length.
                    if (blockLength > reply.GetData().GetSize() - reply.GetData().GetPosition())
                    {
                        str = "Block is not complete.";
                        str += std::to_string(reply.GetData().Available());
                        str += "/";
                        str += std::to_string(blockLength);
                        str += ".";
                        reply.GetXml()->AppendComment(str);
                    }
                }
                str = reply.GetData().ToHexString(reply.GetData().GetPosition(), reply.GetData().Available(), true);
                reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_RAW_DATA, "Value", str);
            }
            reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_PBLOCK);
        }
        else if (reply.GetData().Available() != 0)
        {
            // Get data size.
            unsigned long blockLength;
            GXHelpers::GetObjectCount(reply.GetData(), blockLength);
            // if whole block is read.
            if ((reply.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0)
            {
                // Check Block length.
                if (blockLength > reply.GetData().Available())
                {
                    return DLMS_ERROR_CODE_OUTOFMEMORY;
                }
                //Keep command if this is last block for XML Client.
                if ((reply.GetMoreData() & DLMS_DATA_REQUEST_TYPES_BLOCK) != 0)
                {
                    reply.SetCommand(DLMS_COMMAND_NONE);
                }
            }
            if (blockLength == 0)
            {
                //If meter sends empty data block.
                reply.GetData().SetSize(index);
            }
            else
            {
                GetDataFromBlock(reply.GetData(), index);
            }
            // If last packet and data is not try to peek.
            if (reply.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE)
            {
                reply.GetData().SetPosition(0);
                settings.ResetBlockIndex();
            }
        }
        if (reply.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE && settings.GetCommand() == DLMS_COMMAND_METHOD_REQUEST &&
            settings.GetCommandType() == DLMS_ACTION_RESPONSE_TYPE_WITH_LIST)
        {
            return DLMS_ERROR_CODE_NOT_IMPLEMENTED;
        }
    }
    return ret;
}


int VerifyInvokeId(CGXDLMSSettings& settings, CGXReplyData& reply)
{
    if (
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        reply.GetXml() == NULL &&
#endif //DLMS_IGNORE_XML_TRANSLATOR
        settings.GetAutoIncreaseInvokeID() && reply.GetInvokeId() != GetInvokeIDPriority(settings, false))
    {
        //Invalid invoke ID.
        return DLMS_ERROR_CODE_INVALID_INVOKE_ID;
    }
    return 0;
}

int CGXDLMS::HandleMethodResponse(
    CGXDLMSSettings& settings,
    CGXReplyData& data,
    unsigned long index)
{
    int ret;
    unsigned char invoke, type;
    // Get type.
    if ((ret = data.GetData().GetUInt8(&type)) != 0)
    {
        return ret;
    }
    // Get invoke ID and priority.
    if ((ret = data.GetData().GetUInt8(&invoke)) != 0)
    {
        return ret;
    }
    data.SetInvokeId(invoke);
    if ((ret = VerifyInvokeId(settings, data)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        std::string str;
        data.GetXml()->AppendStartTag(DLMS_COMMAND_METHOD_RESPONSE);
        data.GetXml()->AppendStartTag(DLMS_COMMAND_METHOD_RESPONSE, type);
        //InvokeIdAndPriority
        data.GetXml()->IntegerToHex((long)invoke, 2, str);
        data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_INVOKE_ID, "", str);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    //Action-Response-Normal
    if (type == DLMS_ACTION_RESPONSE_TYPE_NORMAL)
    {
        ret = HandleActionResponseNormal(settings, data);
    }
    else if (type == DLMS_ACTION_RESPONSE_TYPE_WITH_BLOCK)
    {
        ret = HandleActionResponseWithBlock(settings, data, index);
    }
    else if (type == DLMS_ACTION_RESPONSE_TYPE_WITH_LIST)
    {
        // Action-Response-With-List.
        ret = DLMS_ERROR_CODE_INVALID_COMMAND;
    }
    else if (type == DLMS_ACTION_RESPONSE_TYPE_NEXT_BLOCK)
    {
        unsigned long number;
        if ((ret = data.GetData().GetUInt32(&number)) == 0)
        {
            if (data.GetXml() != NULL)
            {
                std::string value;
                data.GetXml()->IntegerToHex(number, 8, value);
                data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_NUMBER, "Value", value);
            }
            else if (number != settings.GetBlockIndex())
            {
                ret = DLMS_ERROR_CODE_INVALID_BLOCK_NUMBER;
            }
            else
            {
                settings.IncreaseBlockIndex();
            }
        }
    }
    else
    {
        ret = DLMS_ERROR_CODE_INVALID_COMMAND;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        data.GetXml()->AppendEndTag(DLMS_COMMAND_METHOD_RESPONSE, (unsigned long)type);
        data.GetXml()->AppendEndTag(DLMS_COMMAND_METHOD_RESPONSE);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    return ret;
}

int CGXDLMS::HandleAccessResponse(
    CGXDLMSSettings& settings,
    CGXReplyData& reply)
{
    int ret;
    std::string str;
    unsigned char ch;
    unsigned long invokeId;
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    unsigned long len;
#endif //DLMS_IGNORE_XML_TRANSLATOR
    //Get invoke id.
    if ((ret = reply.GetData().GetUInt32(&invokeId)) != 0)
    {
        return ret;
    }
    reply.SetTime(NULL);
    if ((ret = reply.GetData().GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    CGXByteBuffer tmp;
    // If date time is given.
    if (ch != 0)
    {
        tmp.Set(&reply.GetData(), reply.GetData().GetPosition(), ch);
        CGXDLMSVariant val;
        if ((ret = CGXDLMSClient::ChangeType(tmp, DLMS_DATA_TYPE_DATETIME, settings.GetUseUtc2NormalTime(), val)) != 0)
        {
            return ret;
        }
        struct tm p = val.dateTime.GetValue();
        reply.SetTime(&p);
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        reply.GetXml()->AppendStartTag(DLMS_COMMAND_ACCESS_RESPONSE);
        reply.GetXml()->IntegerToHex(invokeId, 8, str);
        reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_LONG_INVOKE_ID, "", str);
        if (reply.GetTime() != NULL)
        {
            CGXDateTime dt(reply.GetTime());
            reply.GetXml()->AppendComment(dt.ToString());
        }
        str = tmp.ToHexString(false);
        reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_DATE_TIME, "", str);
        //access-request-specification OPTIONAL
        if ((ret = reply.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        if ((ret = GXHelpers::GetObjectCount(reply.GetData(), len)) != 0)
        {
            return ret;
        }
        reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_ACCESS_RESPONSE_BODY);
        reply.GetXml()->IntegerToHex(len, 2, str);
        reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_ACCESS_RESPONSE_LIST_OF_DATA, "Qty", str);
        for (unsigned long pos = 0; pos != len; ++pos)
        {
            if (reply.GetXml()->GetOutputType() == DLMS_TRANSLATOR_OUTPUT_TYPE_STANDARD_XML)
            {
                reply.GetXml()->AppendStartTag(DLMS_COMMAND_WRITE_REQUEST, DLMS_SINGLE_READ_RESPONSE_DATA);
            }
            CGXDataInfo di;
            di.SetXml(reply.GetXml());
            CGXDLMSVariant value;
            if ((ret = GXHelpers::GetData(&settings, reply.GetData(), di, value)) != 0)
            {
                return ret;
            }
            if (reply.GetXml()->GetOutputType() == DLMS_TRANSLATOR_OUTPUT_TYPE_STANDARD_XML)
            {
                reply.GetXml()->AppendEndTag(DLMS_COMMAND_WRITE_REQUEST, (unsigned long)DLMS_SINGLE_READ_RESPONSE_DATA);
            }
        }
        reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_ACCESS_RESPONSE_LIST_OF_DATA);
        //access-response-specification
        unsigned char err;
        if ((ret = GXHelpers::GetObjectCount(reply.GetData(), len)) != 0)
        {
            return ret;
        }
        reply.GetXml()->IntegerToHex(len, 2, str);
        reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_LIST_OF_ACCESS_RESPONSE_SPECIFICATION, "Qty", str);
        for (unsigned long pos = 0; pos != len; ++pos)
        {
            if ((ret = reply.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            DLMS_ACCESS_SERVICE_COMMAND_TYPE type = (DLMS_ACCESS_SERVICE_COMMAND_TYPE)ch;
            if ((ret = reply.GetData().GetUInt8(&err)) != 0)
            {
                return ret;
            }
            if (err != 0)
            {
                if ((ret = reply.GetData().GetUInt8(&err)) != 0)
                {
                    return ret;
                }
            }
            reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_ACCESS_RESPONSE_SPECIFICATION);
            reply.GetXml()->AppendStartTag(DLMS_COMMAND_ACCESS_RESPONSE, type);
            CGXDLMSTranslator::ErrorCodeToString(reply.GetXml()->GetOutputType(), (DLMS_ERROR_CODE)err, str);
            reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_RESULT, "", str);
            reply.GetXml()->AppendEndTag(DLMS_COMMAND_ACCESS_RESPONSE, (unsigned long)type);
            reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_ACCESS_RESPONSE_SPECIFICATION);
        }
        reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_LIST_OF_ACCESS_RESPONSE_SPECIFICATION);
        reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_ACCESS_RESPONSE_BODY);
        reply.GetXml()->AppendEndTag(DLMS_COMMAND_ACCESS_RESPONSE);
    }
    else
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        //Skip access-request-specification
        ret = reply.GetData().GetUInt8(&ch);
    }
    return ret;
}

/**
    * Handle data notification get data from block and/or update error status.
    *
    * @param settings
    *            DLMS settings.
    * @param reply
    *            Received data from the client.
    */
int CGXDLMS::HandleDataNotification(
    CGXDLMSSettings& settings,
    CGXReplyData& reply)
{
    unsigned long invokeId;
    int ret;
    int start = reply.GetData().GetPosition() - 1;
    // Get invoke id.
    if ((ret = reply.GetData().GetUInt32(&invokeId)) != 0)
    {
        return ret;
    }
    // Get date time.
    CGXDataInfo info;
    reply.SetTime(NULL);
    unsigned char len;
    if ((ret = reply.GetData().GetUInt8(&len)) != 0)
    {
        return ret;
    }
    CGXByteBuffer tmp;
    if (len != 0)
    {
        CGXDLMSVariant t;
        tmp.Set(&reply.GetData(), reply.GetData().GetPosition(), len);
        if ((ret = CGXDLMSClient::ChangeType(tmp, DLMS_DATA_TYPE_DATETIME, t)) != 0)
        {
            return ret;
        }
        reply.SetTime(&t.dateTime.GetValue());
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        std::string str;
        reply.GetXml()->IntegerToHex(invokeId, 8, str);
        reply.GetXml()->AppendStartTag(DLMS_COMMAND_DATA_NOTIFICATION);
        reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_LONG_INVOKE_ID, "", str);
        if (reply.GetTime() != NULL)
        {
            CGXDateTime dt(reply.GetTime());
            reply.GetXml()->AppendComment(dt.ToString());
        }
        str = tmp.ToHexString();
        reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_DATE_TIME, "", str);
        reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_NOTIFICATION_BODY);
        reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_DATA_VALUE);
        CGXDataInfo di;
        di.SetXml(reply.GetXml());
        CGXDLMSVariant value;
        if ((ret = GXHelpers::GetData(&settings, reply.GetData(), di, value)) != 0)
        {
            return ret;
        }
        reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_DATA_VALUE);
        reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_NOTIFICATION_BODY);
        reply.GetXml()->AppendEndTag(DLMS_COMMAND_DATA_NOTIFICATION);
    }
    else
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        if ((ret = GetDataFromBlock(reply.GetData(), start)) != 0)
        {
            return ret;
        }
        return GetValueFromData(settings, reply);
    }
    return 0;
}

int CGXDLMS::HandleSetResponse(
    CGXDLMSSettings& settings,
    CGXReplyData& data)
{
    std::string str;
    unsigned char ch, type, invokeId;
    int ret;
    if ((ret = data.GetData().GetUInt8(&type)) != 0)
    {
        return ret;
    }
    //Invoke ID and priority.
    if ((ret = data.GetData().GetUInt8(&invokeId)) != 0)
    {
        return ret;
    }
    data.SetInvokeId(invokeId);
    if ((ret = VerifyInvokeId(settings, data)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        data.GetXml()->AppendStartTag(DLMS_COMMAND_SET_RESPONSE);
        data.GetXml()->AppendStartTag(DLMS_COMMAND_SET_RESPONSE, type);
        //InvokeIdAndPriority
        data.GetXml()->IntegerToHex((long)invokeId, 2, str);
        data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_INVOKE_ID, "", str);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR

    // SetResponseNormal
    if (type == DLMS_SET_RESPONSE_TYPE_NORMAL)
    {
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        if (data.GetXml() != NULL)
        {
            // Result start tag.
            CGXDLMSTranslator::ErrorCodeToString(data.GetXml()->GetOutputType(), (DLMS_ERROR_CODE)ch, str);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_RESULT, "", str);
        }
        else
#endif //DLMS_IGNORE_XML_TRANSLATOR
            if (ch != 0)
            {
                return ch;
            }
    }
    else if (type == DLMS_SET_RESPONSE_TYPE_DATA_BLOCK)
    {
        unsigned long number;
        if ((ret = data.GetData().GetUInt32(&number)) != 0)
        {
            return ret;
        }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        if (data.GetXml() != NULL)
        {
            data.GetXml()->IntegerToHex(number, 8, str);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_NUMBER, "", str);
        }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    }
    else if (type == DLMS_SET_RESPONSE_TYPE_LAST_DATA_BLOCK)
    {
        unsigned long number;
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        if ((ret = data.GetData().GetUInt32(&number)) != 0)
        {
            return ret;
        }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        if (data.GetXml() != NULL)
        {
            // Result start tag.
            CGXDLMSTranslator::ErrorCodeToString(data.GetXml()->GetOutputType(),
                (DLMS_ERROR_CODE)ch, str);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_RESULT, "", str);
            data.GetXml()->IntegerToHex(number, 8, str);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_NUMBER, "Value", str);
        }
        else
#endif //DLMS_IGNORE_XML_TRANSLATOR
            if (ch != 0)
            {
                return ch;
            }
    }
    else if (type == DLMS_SET_RESPONSE_TYPE_WITH_LIST)
    {
        unsigned long cnt;
        if ((ret = GXHelpers::GetObjectCount(data.GetData(), cnt)) != 0)
        {
            return ret;
        }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        if (data.GetXml() != NULL)
        {
            data.GetXml()->IntegerToHex(cnt, str);
            data.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_RESULT, "Qty", str);
            for (unsigned long pos = 0; pos != cnt; ++pos)
            {
                if ((ret = data.GetData().GetUInt8(&ch)) != 0)
                {
                    return ret;
                }
                CGXDLMSTranslator::ErrorCodeToString(data.GetXml()->GetOutputType(), (DLMS_ERROR_CODE)ch, str);
                data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_DATA_ACCESS_RESULT, "", str);
            }
            data.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_RESULT);
        }
        else
#endif //DLMS_IGNORE_XML_TRANSLATOR
        {
            int error = 0;
            for (unsigned long pos = 0; pos != cnt; ++pos)
            {
                if ((ret = data.GetData().GetUInt8(&ch)) != 0)
                {
                    return ret;
                }
                if (error == 0 && ch != 0)
                {
                    error = ch;
                }
            }
            return error;
        }
    }
    else
    {
        //Invalid data type.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        data.GetXml()->AppendEndTag(DLMS_COMMAND_SET_RESPONSE, (unsigned long)type);
        data.GetXml()->AppendEndTag(DLMS_COMMAND_SET_RESPONSE);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::HandleGbt(CGXDLMSSettings& settings, CGXReplyData& data)
{
    int ret;
    unsigned char bc;
    unsigned long len;
    unsigned short bn, bna;
    int index = data.GetData().GetPosition() - 1;
    data.SetGbtWindowSize(settings.GetGbtWindowSize());
    // BlockControl
    if ((ret = data.GetData().GetUInt8(&bc)) != 0)
    {
        return ret;
    }
    // Is streaming active.
    data.SetStreaming((bc & 0x40) != 0);
    // GBT Window size.
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    unsigned char     windowSize = (unsigned char)(bc & 0x3F);
#endif //DLMS_IGNORE_XML_TRANSLATOR
    // Block number.
    if ((ret = data.GetData().GetUInt16(&bn)) != 0)
    {
        return ret;
    }
    // Block number acknowledged.
    if ((ret = data.GetData().GetUInt16(&bna)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() == NULL)
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        // Remove existing data when first block is received.
        if (bn == 1)
        {
            index = 0;
        }
        else if (bna != settings.GetBlockIndex() - 1)
        {
            // If this block is already received.
            data.GetData().SetSize(index);
            data.SetCommand(DLMS_COMMAND_NONE);
            return 0;
        }
    }
    data.SetBlockNumber(bn);
    data.SetBlockNumberAck(bna);
    settings.SetBlockNumberAck(data.GetBlockNumber());
    data.SetCommand(DLMS_COMMAND_NONE);
    if ((ret = GXHelpers::GetObjectCount(data.GetData(), len)) != 0)
    {
        return ret;
    }
    if (len > (unsigned long)(data.GetData().GetSize() - data.GetData().GetPosition()))
    {
        data.SetComplete(false);
        return 0;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        if ((data.GetData().GetSize() - data.GetData().GetPosition()) != len)
        {
            std::string str;
            str.append("Data length is ");
            str.append(GXHelpers::IntToString(len));
            str.append("and there are ");
            str.append(GXHelpers::IntToString(data.GetData().GetSize() - data.GetData().GetPosition()));
            str.append(" bytes.");
            data.GetXml()->AppendComment(str);
        }
        data.GetXml()->AppendStartTag(DLMS_COMMAND_GENERAL_BLOCK_TRANSFER);
        if (data.GetXml()->GetComments())
        {
            data.GetXml()->AppendComment("Last block: " + GXHelpers::IntToString(((bc & 0x80) != 0)));
            data.GetXml()->AppendComment("Streaming: " + GXHelpers::IntToString(data.GetStreaming()));
            data.GetXml()->AppendComment("Window size: " + GXHelpers::IntToString(windowSize));
        }
        std::string str;
        data.GetXml()->IntegerToHex((long)bc, 2, str);
        data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_CONTROL, "", str);
        data.GetXml()->IntegerToHex((long)data.GetBlockNumber(), 4, str);
        data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_NUMBER, "", str);
        data.GetXml()->IntegerToHex((long)data.GetBlockNumberAck(), 4, str);
        data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_NUMBER_ACK, "", str);

        // If last block and comments.
        if ((bc & 0x80) != 0 && data.GetXml()->GetComments())
        {
            int pos = data.GetData().GetPosition();
            int len2 = data.GetXml()->GetXmlLength();
            CGXReplyData reply;
            reply.SetData(data.GetData());
            reply.SetXml(data.GetXml());
            reply.GetXml()->StartComment("");
            if (GetPdu(settings, reply) != 0)
            {
                // It's ok if this fails.
                data.GetXml()->SetXmlLength(len2);
            }
            else
            {
                reply.GetXml()->EndComment();
            }
            data.GetData().SetPosition(pos);
        }
        str = data.GetData().ToHexString(data.GetData().GetPosition(), len, false);
        data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_DATA, "", str);
        data.GetXml()->AppendEndTag(DLMS_COMMAND_GENERAL_BLOCK_TRANSFER);
        return 0;
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    if ((ret = GetDataFromBlock(data.GetData(), index)) != 0)
    {
        return ret;
    }
    // Is Last block,
    if ((bc & 0x80) == 0)
    {
        data.SetMoreData((DLMS_DATA_REQUEST_TYPES)(data.GetMoreData() | DLMS_DATA_REQUEST_TYPES_GBT));
    }
    else
    {
        data.SetMoreData((DLMS_DATA_REQUEST_TYPES)(data.GetMoreData() & ~DLMS_DATA_REQUEST_TYPES_GBT));
        if (data.GetData().GetSize() != 0)
        {
            data.GetData().SetPosition(0);
            GetPdu(settings, data);
        }
        // Get data if all data is read or we want to peek data.
        if (data.GetData().GetPosition() != data.GetData().GetSize()
            && (data.GetCommand() == DLMS_COMMAND_READ_RESPONSE
                || data.GetCommand() == DLMS_COMMAND_GET_RESPONSE)
            && (data.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE || data.GetPeek()))
        {
            data.GetData().SetPosition(0);
            GetValueFromData(settings, data);
        }
    }
    return ret;
}

int CGXDLMS::HandleGloDedRequest(CGXDLMSSettings& settings,
    CGXReplyData& data)
{
    if (settings.GetCipher() == NULL)
    {
        //Secure connection is not supported.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        data.GetData().SetPosition(data.GetData().GetPosition() - 1);
    }
    else
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        DLMS_SECURITY_SUITE suite;
        DLMS_SECURITY security;
        //If all frames are read.
        if ((data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0)
        {
            int ret;
            unsigned char ch;
            uint64_t InvocationCounter;
            data.GetData().SetPosition(data.GetData().GetPosition() - 1);
            if (settings.GetCipher()->GetDedicatedKey().GetSize() != 0 &&
                (settings.GetConnected() & DLMS_CONNECTION_STATE_DLMS) != 0)
            {
                if ((ret = settings.GetCipher()->Decrypt(settings.GetSourceSystemTitle(),
                    settings.GetCipher()->GetDedicatedKey(), data.GetData(), security, suite, InvocationCounter)) != 0)
                {
                    return ret;
                }
            }
            //If pre-set connection is made.
            else if (settings.GetSourceSystemTitle().GetSize() == 0)
            {

            }
            else
            {
                if ((ret = settings.GetCipher()->Decrypt(settings.GetSourceSystemTitle(),
                    settings.GetCipher()->GetBlockCipherKey(), data.GetData(), security, suite, InvocationCounter)) != 0)
                {
                    return ret;
                }
            }
            settings.GetCipher()->SetSecuritySuite(suite);
            settings.GetCipher()->SetSecurity(security);
            // Get command.
            data.SetCipheredCommand(data.GetCommand());
            data.GetData().GetUInt8(&ch);
            data.SetCommand((DLMS_COMMAND)ch);
            if (data.GetCommand() == DLMS_COMMAND_DATA_NOTIFICATION ||
                data.GetCommand() == DLMS_COMMAND_INFORMATION_REPORT)
            {
                data.SetCommand(DLMS_COMMAND_NONE);
                data.GetData().SetPosition(data.GetData().GetPosition() - 1);
                GetPdu(settings, data);
            }
        }
        else
        {
            data.GetData().SetPosition(data.GetData().GetPosition() - 1);
        }
    }
    return 0;
}

int CGXDLMS::HandleGloDedResponse(
    CGXDLMSSettings& settings,
    CGXReplyData& data, int index)
{
    if (settings.GetCipher() == NULL)
    {
        //Secure connection is not supported.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        data.GetData().SetPosition(data.GetData().GetPosition() - 1);
    }
    else
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        //If all frames are read.
        if ((data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0)
        {
            int ret;
            DLMS_SECURITY security;
            DLMS_SECURITY_SUITE suite;
            data.GetData().SetPosition(data.GetData().GetPosition() - 1);
            CGXByteBuffer bb;
            CGXByteBuffer& tmp = data.GetData();
            CGXByteBuffer* key;
            uint64_t invocationCounter;
            bb.Set(&tmp, data.GetData().GetPosition(), data.GetData().GetSize() - data.GetData().GetPosition());
            data.GetData().SetPosition(index);
            data.GetData().SetSize(index);
            if (settings.GetCipher()->GetDedicatedKey().GetSize() != 0 && (settings.GetConnected() & DLMS_CONNECTION_STATE_DLMS) != 0)
            {
                key = &settings.GetCipher()->GetDedicatedKey();
            }
            else
            {
                key = &settings.GetCipher()->GetBlockCipherKey();
            }
            if ((ret = settings.GetCipher()->Decrypt(settings.GetSourceSystemTitle(),
                *key, bb, security, suite, invocationCounter)) != 0)
            {
                return ret;
            }
            //If target is sending data ciphered using different security policy.
            if (settings.GetCipher()->GetSecurity() != security)
            {
                return DLMS_ERROR_CODE_INVALID_DECIPHERING_ERROR;
            }
            /*TODO:
            //If target is sending data ciphered using different security policy.
            if (settings.Cipher.Security1 != p.Security1)
            {
                return DLMS_ERROR_CODE_INVALID_DECIPHERING_ERROR;
            }
            */
            if (settings.GetExpectedInvocationCounter() != 0)
            {
                //If data is ciphered using invalid invocation counter value.
                if (invocationCounter != settings.GetExpectedInvocationCounter())
                {
                    return DLMS_ERROR_CODE_INVOCATION_COUNTER_TOO_SMALL;
                }
                settings.SetExpectedInvocationCounter(1 + invocationCounter);
            }
            data.GetData().Set(&bb, bb.GetPosition());
            data.SetCipheredCommand(data.GetCommand());
            data.SetCommand(DLMS_COMMAND_NONE);
            if ((ret = GetPdu(settings, data)) != 0)
            {
                return ret;
            }
            data.SetCipherIndex(data.GetData().GetSize());
        }
    }
    return 0;
}

int CGXDLMS::HandleGeneralCiphering(
    CGXDLMSSettings& settings,
    CGXReplyData& data)
{
    unsigned char ch;
    int ret;
    if (settings.GetCipher() == NULL)
    {
        //Secure connection is not supported.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    // If all frames are read.
    if ((data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0)
    {
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        int origPos = 0;
        if (data.GetXml() != NULL)
        {
            origPos = data.GetXml()->GetXmlLength();
        }
#endif //DLMS_IGNORE_XML_TRANSLATOR
        data.GetData().SetPosition(data.GetData().GetPosition() - 1);
        DLMS_SECURITY security;
        DLMS_SECURITY_SUITE suite;
        uint64_t invocationCounter;
        if ((ret = settings.GetCipher()->Decrypt(settings.GetSourceSystemTitle(),
            settings.GetCipher()->GetBlockCipherKey(), data.GetData(), security, suite, invocationCounter)) != 0)
        {
            return ret;
        }
        // Get command
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        data.SetCipheredCommand(DLMS_COMMAND_GENERAL_CIPHERING);
        data.SetCommand(DLMS_COMMAND_NONE);
        if (security != DLMS_SECURITY_NONE)
        {
            if ((ret = GetPdu(settings, data)) != 0)
            {
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                if (data.GetXml() != NULL)
                {
                    data.GetXml()->SetXmlLength(origPos);
                }
                else
#endif //DLMS_IGNORE_XML_TRANSLATOR
                {
                    return ret;
                }
            }
        }
        //TODO:
        /*
        if (data.GetXml() != NULL && p != NULL)
        {
            std::string str;
            data.GetXml()->AppendStartTag(DLMS_COMMAND_GENERAL_CIPHERING);
            data.GetXml()->IntegerToHex(p.GetInvocationCounter(), 16, true, str);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_TRANSACTION_ID, "", str);
            str = p.GetSystemTitle()->ToHexString(false);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_ORIGINATOR_SYSTEM_TITLE, "", str);
            str = p.GetRecipientSystemTitle()->ToHexString(false);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_RECIPIENT_SYSTEM_TITLE, "", str);
            //CGXDateTime dt(p.GetDateTime());
            //data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_DATE_TIME, "", GXCommon.ToHex(, false));
            str = p.GetOtherInformation()->ToHexString(false);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_OTHER_INFORMATION, "", str);
            data.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_KEY_INFO);
            data.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_AGREED_KEY);
            str = data.GetXml()->IntegerToHex(p.GetKeyParameters(), 2, true);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_KEY_PARAMETERS, "", str);
            str = p.GetKeyCipheredData()->ToHexString(false);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_KEY_CIPHERED_DATA, "", str);
            data.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_AGREED_KEY);
            data.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_KEY_INFO);
            str = p.GetCipheredContent()->ToHexString(false);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_CIPHERED_CONTENT, "", str);
            data.GetXml()->AppendEndTag(DLMS_COMMAND_GENERAL_CIPHERING);
        }
        */
    }
    return 0;
}

int CGXDLMS::GetPdu(
    CGXDLMSSettings& settings,
    CGXReplyData& data)
{
    int ret = DLMS_ERROR_CODE_OK;
    unsigned char ch;
    DLMS_COMMAND cmd = data.GetCommand();
    // If header is not read yet or GBT message.
    if (cmd == DLMS_COMMAND_NONE)
    {
        // If PDU is missing.
        if (data.GetData().GetSize() - data.GetData().GetPosition() == 0)
        {
            // Invalid PDU.
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        int index = data.GetData().GetPosition();
        // Get DLMS_COMMAND_
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        cmd = (DLMS_COMMAND)ch;
        data.SetCommand(cmd);
        switch (cmd)
        {
        case DLMS_COMMAND_READ_RESPONSE:
            if ((ret = HandleReadResponse(settings, data, index)) != 0)
            {
                if (ret == DLMS_ERROR_CODE_FALSE)
                {
                    return 0;
                }
                return ret;
            }
            break;
        case DLMS_COMMAND_GET_RESPONSE:
            if ((ret = HandleGetResponse(settings, data, index)) != 0)
            {
                if (ret == DLMS_ERROR_CODE_FALSE)
                {
                    return 0;
                }
                return ret;
            }
            break;
        case DLMS_COMMAND_SET_RESPONSE:
            ret = HandleSetResponse(settings, data);
            break;
        case DLMS_COMMAND_WRITE_RESPONSE:
            ret = HandleWriteResponse(data);
            break;
        case DLMS_COMMAND_METHOD_RESPONSE:
            ret = HandleMethodResponse(settings, data, index);
            break;
        case DLMS_COMMAND_ACCESS_REQUEST:
            if (
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                data.GetXml() != NULL ||
#endif //DLMS_IGNORE_XML_TRANSLATOR
                (!settings.IsServer() &&
                    (data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0))
            {
                ret = CGXDLMSLNCommandHandler::HandleAccessRequest(settings, NULL, data.GetData(), NULL, data.GetXml(), DLMS_COMMAND_NONE);
            }
            break;
        case DLMS_COMMAND_ACCESS_RESPONSE:
            ret = HandleAccessResponse(settings, data);
            break;
        case DLMS_COMMAND_GENERAL_BLOCK_TRANSFER:
            if (
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                data.GetXml() != NULL ||
#endif //DLMS_IGNORE_XML_TRANSLATOR
                (!settings.IsServer() &&
                    (data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0))
            {
                ret = HandleGbt(settings, data);
            }
            break;
        case DLMS_COMMAND_AARQ:
        case DLMS_COMMAND_AARE:
            // This is parsed later.
            data.GetData().SetPosition(data.GetData().GetPosition() - 1);
            break;
        case DLMS_COMMAND_RELEASE_RESPONSE:
            break;
        case DLMS_COMMAND_CONFIRMED_SERVICE_ERROR:
            ret = HandleConfirmedServiceError(data);
            break;
        case DLMS_COMMAND_EXCEPTION_RESPONSE:
            ret = HandleExceptionResponse(data);
            break;
        case DLMS_COMMAND_GET_REQUEST:
        case DLMS_COMMAND_READ_REQUEST:
        case DLMS_COMMAND_WRITE_REQUEST:
        case DLMS_COMMAND_SET_REQUEST:
        case DLMS_COMMAND_METHOD_REQUEST:
        case DLMS_COMMAND_RELEASE_REQUEST:
            // Server handles this.
            if ((data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) != 0)
            {
                break;
            }
            break;
        case DLMS_COMMAND_GLO_READ_REQUEST:
        case DLMS_COMMAND_GLO_WRITE_REQUEST:
        case DLMS_COMMAND_GLO_GET_REQUEST:
        case DLMS_COMMAND_GLO_SET_REQUEST:
        case DLMS_COMMAND_GLO_METHOD_REQUEST:
        case DLMS_COMMAND_DED_GET_REQUEST:
        case DLMS_COMMAND_DED_SET_REQUEST:
        case DLMS_COMMAND_DED_METHOD_REQUEST:
            ret = HandleGloDedRequest(settings, data);
            // Server handles this.
            break;
        case DLMS_COMMAND_GLO_READ_RESPONSE:
        case DLMS_COMMAND_GLO_WRITE_RESPONSE:
        case DLMS_COMMAND_GLO_GET_RESPONSE:
        case DLMS_COMMAND_GLO_SET_RESPONSE:
        case DLMS_COMMAND_GLO_METHOD_RESPONSE:
        case DLMS_COMMAND_DED_GET_RESPONSE:
        case DLMS_COMMAND_DED_SET_RESPONSE:
        case DLMS_COMMAND_DED_METHOD_RESPONSE:
        case DLMS_COMMAND_DED_EVENT_NOTIFICATION:
            ret = HandleGloDedResponse(settings, data, index);
            break;
        case DLMS_COMMAND_GLO_GENERAL_CIPHERING:
        case DLMS_COMMAND_GENERAL_DED_CIPHERING:
            if (settings.IsServer())
            {
                ret = HandleGloDedRequest(settings, data);
            }
            else
            {
                ret = HandleGloDedResponse(settings, data, index);
            }
            break;
        case DLMS_COMMAND_DATA_NOTIFICATION:
            ret = HandleDataNotification(settings, data);
            // Client handles this.
            break;
        case DLMS_COMMAND_EVENT_NOTIFICATION:
            // Client handles this.
            break;
        case DLMS_COMMAND_INFORMATION_REPORT:
            // Client handles this.
            break;
        case DLMS_COMMAND_GENERAL_CIPHERING:
            ret = HandleGeneralCiphering(settings, data);
            break;
        default:
            // Invalid DLMS command.
            data.SetCommand(DLMS_COMMAND_NONE);
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
    }
    else if ((data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0)
    {
        // Is whole block is read and if last packet and data is not try to
        // peek.
        if (!data.GetPeek() && data.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE)
        {
            if (data.GetCommand() == DLMS_COMMAND_AARE
                || data.GetCommand() == DLMS_COMMAND_AARQ)
            {
                data.GetData().SetPosition(0);
            }
            else
            {
                data.GetData().SetPosition(1);
            }
        }
        if (cmd == DLMS_COMMAND_GENERAL_BLOCK_TRANSFER)
        {
            data.GetData().SetPosition(data.GetCipherIndex() + 1);
            ret = HandleGbt(settings, data);
            data.SetCipherIndex(data.GetData().GetSize());
            data.SetCommand(DLMS_COMMAND_NONE);
        }
        // Get command if operating as a server.
        if (settings.IsServer())
        {
            // Ciphered messages are handled after whole PDU is received.
            switch (cmd)
            {
            case DLMS_COMMAND_GLO_READ_REQUEST:
            case DLMS_COMMAND_GLO_WRITE_REQUEST:
            case DLMS_COMMAND_GLO_GET_REQUEST:
            case DLMS_COMMAND_GLO_SET_REQUEST:
            case DLMS_COMMAND_GLO_METHOD_REQUEST:
                data.SetCommand(DLMS_COMMAND_NONE);
                data.GetData().SetPosition(data.GetCipherIndex());
                ret = GetPdu(settings, data);
                break;
            default:
                break;
            }
        }
        else
        {
            // Client do not need a command any more.
            if (data.IsMoreData())
            {
                data.SetCommand(DLMS_COMMAND_NONE);
            }
            // Ciphered messages are handled after whole PDU is received.
            switch (cmd)
            {
            case DLMS_COMMAND_GLO_READ_RESPONSE:
            case DLMS_COMMAND_GLO_WRITE_RESPONSE:
            case DLMS_COMMAND_GLO_GET_RESPONSE:
            case DLMS_COMMAND_GLO_SET_RESPONSE:
            case DLMS_COMMAND_GLO_METHOD_RESPONSE:
            case DLMS_COMMAND_GLO_GENERAL_CIPHERING:
            case DLMS_COMMAND_DED_READ_RESPONSE:
            case DLMS_COMMAND_DED_WRITE_RESPONSE:
            case DLMS_COMMAND_DED_GET_RESPONSE:
            case DLMS_COMMAND_DED_SET_RESPONSE:
            case DLMS_COMMAND_DED_METHOD_RESPONSE:
            case DLMS_COMMAND_GENERAL_DED_CIPHERING:
            case DLMS_COMMAND_GENERAL_CIPHERING:
            case DLMS_COMMAND_ACCESS_RESPONSE:
                data.SetCommand(DLMS_COMMAND_NONE);
                data.GetData().SetPosition(data.GetCipherIndex());
                ret = GetPdu(settings, data);
                break;
            default:
                break;
            }
            if (cmd == DLMS_COMMAND_READ_RESPONSE && data.GetTotalCount() > 1)
            {
                if ((ret = HandleReadResponse(settings, data, 0)) != 0)
                {
                    if (ret == DLMS_ERROR_CODE_FALSE)
                    {
                        ret = 0;
                    }
                    return ret;
                }
            }
        }
    }
    if (ret != 0)
    {
        return ret;
    }

    // Get data only blocks if SN is used. This is faster.
    if (cmd == DLMS_COMMAND_READ_RESPONSE
        && data.GetCommandType() == DLMS_SINGLE_READ_RESPONSE_DATA_BLOCK_RESULT
        && (data.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) != 0)
    {
        return 0;
    }

    // Get data if all data is read or we want to peek data.
    if (ret == 0 && data.GetXml() == NULL && data.GetData().GetPosition() != data.GetData().GetSize()
        && (cmd == DLMS_COMMAND_READ_RESPONSE || cmd == DLMS_COMMAND_GET_RESPONSE || cmd == DLMS_COMMAND_METHOD_RESPONSE)
        && (data.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE
            || data.GetPeek()))
    {
        ret = GetValueFromData(settings, data);
    }
    return ret;
}

int CGXDLMS::GetData(CGXDLMSSettings& settings,
    CGXByteBuffer& reply,
    CGXReplyData& data,
    CGXReplyData* notify)
{
    CGXReplyData* target = &data;
    int ret;
    unsigned char frame = 0;
    bool isLast = true;
    bool isNotify = false;
    // If DLMS frame is generated.
    switch (settings.GetInterfaceType())
    {
    case DLMS_INTERFACE_TYPE_HDLC:
    case DLMS_INTERFACE_TYPE_HDLC_WITH_MODE_E:
        if ((ret = GetHdlcData(settings.IsServer(), settings, reply, data, frame, notify)) != 0)
        {
            return ret;
        }
        isLast = (frame & 0x10) != 0;
        if (notify != NULL && frame == 0x13)
        {
            target = notify;
            isNotify = true;
        }
        break;
    case DLMS_INTERFACE_TYPE_WRAPPER:
    {
        if ((ret = GetTcpData(settings, reply, data, notify)) != 0 && ret != DLMS_ERROR_CODE_FALSE)
        {
            return ret;
        }
        if (notify != NULL && ret == DLMS_ERROR_CODE_FALSE)
        {
            if (notify != NULL)
            {
                target = notify;
            }
            isNotify = true;
        }
    }
    break;
    case DLMS_INTERFACE_TYPE_WIRELESS_MBUS:
        ret = GetMBusData(settings, reply, data);
        break;
    case DLMS_INTERFACE_TYPE_PDU:
    {
        data.SetPacketLength(reply.GetSize());
        data.SetComplete(reply.GetSize() != 0);
    }
    break;
    case DLMS_INTERFACE_TYPE_PLC:
        ret = GetPlcData(settings, reply, data);
        break;
    case DLMS_INTERFACE_TYPE_PLC_HDLC:
    {
        ret = GetPlcHdlcData(settings, reply, data, &frame);
    }
    break;
    default:
        // Invalid Interface type.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    // If all data is not read yet.
    if (!target->IsComplete())
    {
        return DLMS_ERROR_CODE_FALSE;
    }
    if (settings.GetInterfaceType() != DLMS_INTERFACE_TYPE_PLC_HDLC)
    {
        GetDataFromFrame(reply, *target, UseHdlc(settings.GetInterfaceType()));
    }
    // If keepalive or get next frame request.
    if (frame != 0x13 && (frame & 0x1) != 0)
    {
        if (data.GetCommand() == DLMS_COMMAND_UNACCEPTABLE_FRAME)
        {
            return DLMS_ERROR_CODE_REJECTED;
        }
        return DLMS_ERROR_CODE_OK;
    }
    ret = GetPdu(settings, *target);

    if (notify != NULL && ret == 0 && !isNotify)
    {
        CGXByteBuffer& d = data.GetData();
        //Check command to make sure it's not notify message.
        switch (target->GetCommand())
        {
        case DLMS_COMMAND_DATA_NOTIFICATION:
        case DLMS_COMMAND_GLO_EVENT_NOTIFICATION_REQUEST:
        case DLMS_COMMAND_INFORMATION_REPORT:
        case DLMS_COMMAND_EVENT_NOTIFICATION:
        case DLMS_COMMAND_DED_EVENT_NOTIFICATION:
            isNotify = true;
            notify->SetCommand(data.GetCommand());
            data.SetCommand(DLMS_COMMAND_NONE);
            notify->SetTime(data.GetTime());
            data.SetTime(0);
            notify->GetData().Set(&d, d.GetPosition(), d.GetSize() - d.GetPosition());
            data.GetData().Trim();
            break;
        default:
            break;
        }
    }
    if (ret == 0 && (!isLast || (data.GetMoreData() == DLMS_DATA_REQUEST_TYPES_GBT && reply.Available() != 0)))
    {
        return GetData(settings, reply, data, notify);
    }
    if (ret == 0 && isNotify)
    {
        return DLMS_ERROR_CODE_FALSE;
    }
    return ret;
}

int CGXDLMS::HandleGetResponseWithList(
    CGXDLMSSettings& settings,
    CGXReplyData& reply)
{
    int ret;
    unsigned char ch;
    unsigned long count;
    CGXDLMSVariant values;
    values.vt = DLMS_DATA_TYPE_ARRAY;
    CGXByteBuffer& data = reply.GetData();
    // Get response with list.
    //Get count.
    if ((ret = GXHelpers::GetObjectCount(data, count)) != 0)
    {
        return ret;
    }
    for (unsigned short pos = 0; pos != (unsigned short)count; ++pos)
    {
        // Result
        if ((ret = data.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        if (ch != 0)
        {
            if ((ret = data.GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            return ch;
        }
        else
        {
            reply.SetReadPosition(reply.GetData().GetPosition());
            GetValueFromData(settings, reply);
            if (reply.GetValue().vt == DLMS_DATA_TYPE_NONE)
            {
                // Increase read position if data is NULL. This is a special case.
                reply.SetReadPosition(1 + reply.GetReadPosition());
            }
            reply.GetData().SetPosition(reply.GetReadPosition());
            values.Arr.push_back(reply.GetValue());
            reply.GetValue().Clear();
        }
    }
    reply.SetValue(values);
    return 0;
}
int CGXDLMS::HandleGetResponseNormal(
    CGXDLMSSettings& settings,
    CGXReplyData& reply,
    bool& empty)
{
    int ret = 0;
    unsigned char ch;
    CGXByteBuffer& data = reply.GetData();
    if (data.Available() == 0)
    {
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        empty = true;
#endif //DLMS_IGNORE_XML_TRANSLATOR
        GetDataFromBlock(data, 0);
    }
    else
    {
        // Result
        if ((ret = data.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        if (ch != 0)
        {
            if ((ret = data.GetUInt8(&ch)) != 0)
            {
                return ret;
            }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
            if (reply.GetXml() == NULL)
#endif //DLMS_IGNORE_XML_TRANSLATOR
            {
                return ch;
            }
        }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
        if (reply.GetXml() != NULL)
        {
            // Result start tag.
            reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_RESULT);
            if (ch != 0)
            {
                std::string str;
                CGXDLMSTranslator::ErrorCodeToString(reply.GetXml()->GetOutputType(), (DLMS_ERROR_CODE)ch, str);
                reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_DATA_ACCESS_ERROR, "", str);
            }
            else
            {
                reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_DATA);
                CGXDataInfo di;
                di.SetXml(reply.GetXml());
                CGXDLMSVariant value;
                if ((ret = GXHelpers::GetData(&settings, reply.GetData(), di, value)) != 0)
                {
                    return ret;
                }
                reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_DATA);
            }
        }
        else
#endif //DLMS_IGNORE_XML_TRANSLATOR
        {
            ret = GetDataFromBlock(data, 0);
        }
    }
    return ret;
}

int CGXDLMS::HandleGetResponseNextDataBlock(
    CGXDLMSSettings& settings,
    CGXReplyData& reply,
    int index)
{
    int ret = 0;
    unsigned long number;
    unsigned long count;
    unsigned char ch;
    CGXByteBuffer& data = reply.GetData();
    // Is Last block.
    if ((ret = data.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        //Result start tag.
        reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_RESULT);
        //LastBlock
        std::string str;
        reply.GetXml()->IntegerToHex((unsigned long)ch, 2, str);
        reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_LAST_BLOCK, "Value", str);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR

    if (ch == 0)
    {
        reply.SetMoreData(
            (DLMS_DATA_REQUEST_TYPES)(reply.GetMoreData() | DLMS_DATA_REQUEST_TYPES_BLOCK));
    }
    else
    {
        reply.SetMoreData(
            (DLMS_DATA_REQUEST_TYPES)(reply.GetMoreData() & ~DLMS_DATA_REQUEST_TYPES_BLOCK));
    }
    // Get Block number.
    if ((ret = data.GetUInt32(&number)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        //BlockNumber
        std::string str;
        reply.GetXml()->IntegerToHex(number, 8, str);
        reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_BLOCK_NUMBER, "Value", str);
    }
    else
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        // If meter's block index is zero based or Actaris is read.
        // Actaris SL7000 might return wrong block index sometimes.
        // It's not reseted to 1.
        if (number != 1 && settings.GetBlockIndex() == 1)
        {
            settings.SetBlockIndex(number);
        }
        if (number != settings.GetBlockIndex())
        {
            return DLMS_ERROR_CODE_DATA_BLOCK_NUMBER_INVALID;
        }
    }
    // Get status.
    if ((ret = data.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    if (ch != 0)
    {
        if ((ret = data.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        return ch;
    }
    // Get data size.
    GXHelpers::GetObjectCount(data, count);
    // if whole block is read.
    if ((reply.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) == 0)
    {
        // Check Block length.
        if (count > (unsigned long)(data.Available()))
        {
            return DLMS_ERROR_CODE_OUTOFMEMORY;
        }
        reply.SetCommand(DLMS_COMMAND_NONE);
    }
    if (count == 0)
    {
        // If meter sends empty data block.
        data.SetSize(index);
    }
    else
    {
        if ((ret = GetDataFromBlock(data, index)) != 0)
        {
            return ret;
        }
    }
    // If last packet and data is not try to peek.
    if (reply.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE)
    {
        if (!reply.GetPeek())
        {
            data.SetPosition(0);
        }
        settings.ResetBlockIndex();
    }
    if (reply.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE &&
        settings.GetCommand() == DLMS_COMMAND_GET_REQUEST
        && settings.GetCommandType() == DLMS_GET_COMMAND_TYPE_WITH_LIST)
    {
        if ((ret = HandleGetResponseWithList(settings, reply)) != 0)
        {
            return ret;
        }
        ret = DLMS_ERROR_CODE_FALSE;
    }
    return ret;
}

int CGXDLMS::HandleGetResponse(
    CGXDLMSSettings& settings,
    CGXReplyData& reply,
    int index)
{
    int ret;
    unsigned char ch;
    short type;
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    bool empty = false;
#endif //DLMS_IGNORE_XML_TRANSLATOR
    CGXByteBuffer& data = reply.GetData();
    std::string str;

    // Get type.
    if ((ret = data.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    type = ch;
    // Get invoke ID and priority.
    if ((ret = data.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    // Get invoke ID and priority.
    reply.SetInvokeId(ch);
    if ((ret = VerifyInvokeId(settings, reply)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        reply.GetXml()->AppendStartTag(DLMS_COMMAND_GET_RESPONSE);
        reply.GetXml()->AppendStartTag(DLMS_COMMAND_GET_RESPONSE, type);
        //InvokeIdAndPriority
        reply.GetXml()->IntegerToHex((long)ch, 2, str);
        reply.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_INVOKE_ID, "", str);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR

    switch (type)
    {
    case DLMS_GET_COMMAND_TYPE_NORMAL:
        ret = HandleGetResponseNormal(settings, reply, empty);
        break;
    case DLMS_GET_COMMAND_TYPE_NEXT_DATA_BLOCK:
        // Is Last block.
        ret = HandleGetResponseNextDataBlock(settings, reply, index);
        break;
    case DLMS_GET_COMMAND_TYPE_WITH_LIST:
        HandleGetResponseWithList(settings, reply);
        ret = DLMS_ERROR_CODE_FALSE;
        break;
    default:
        //Invalid Get response.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        if (!empty)
        {
            reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_RESULT);
        }
        reply.GetXml()->AppendEndTag(DLMS_COMMAND_GET_RESPONSE, (unsigned long)type);
        reply.GetXml()->AppendEndTag(DLMS_COMMAND_GET_RESPONSE);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    return ret;
}

int CGXDLMS::HandleWriteResponse(CGXReplyData& data)
{
    unsigned char ch;
    int ret;
    unsigned long count;
    if ((ret = GXHelpers::GetObjectCount(data.GetData(), count)) != 0)
    {
        return ret;
    }
    for (unsigned long pos = 0; pos != count; ++pos)
    {
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        if (ch != 0)
        {
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            return ch;
        }
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::ReadResponseDataBlockResult(
    CGXDLMSSettings& settings,
    CGXReplyData& reply,
    int index)
{
    int ret;
    unsigned short number;
    unsigned long blockLength;
    unsigned char lastBlock;
    if ((ret = reply.GetData().GetUInt8(&lastBlock)) != 0)
    {
        return ret;
    }
    // Get Block number.
    if ((ret = reply.GetData().GetUInt16(&number)) != 0)
    {
        return ret;
    }
    if ((ret = GXHelpers::GetObjectCount(reply.GetData(), blockLength)) != 0)
    {
        return ret;
    }
    // Is Last block.
    if (!lastBlock)
    {
        reply.SetMoreData((DLMS_DATA_REQUEST_TYPES)(reply.GetMoreData() | DLMS_DATA_REQUEST_TYPES_BLOCK));
    }
    else
    {
        reply.SetMoreData((DLMS_DATA_REQUEST_TYPES)(reply.GetMoreData() & ~DLMS_DATA_REQUEST_TYPES_BLOCK));
    }
    // If meter's block index is zero based.
    if (number != 1 && settings.GetBlockIndex() == 1)
    {
        settings.SetBlockIndex(number);
    }
    int expectedIndex = settings.GetBlockIndex();
    if (number != expectedIndex)
    {
        //Invalid Block number
        return DLMS_ERROR_CODE_DATA_BLOCK_NUMBER_INVALID;
    }
    // If whole block is not read.
    if ((reply.GetMoreData() & DLMS_DATA_REQUEST_TYPES_FRAME) != 0)
    {
        GetDataFromBlock(reply.GetData(), index);
        return DLMS_ERROR_CODE_FALSE;
    }
    if (blockLength != reply.GetData().Available())
    {
        //Invalid block length.
        return DLMS_ERROR_CODE_DATA_BLOCK_UNAVAILABLE;
    }
    reply.SetCommand(DLMS_COMMAND_NONE);

    GetDataFromBlock(reply.GetData(), index);
    reply.SetTotalCount(0);
    // If last packet and data is not try to peek.
    if (reply.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE)
    {
        settings.ResetBlockIndex();
    }
    return ret;
}


int CGXDLMS::HandleReadResponse(
    CGXDLMSSettings& settings,
    CGXReplyData& reply,
    int index)
{
    std::string str;
    unsigned char ch;
    unsigned long pos, cnt = reply.GetTotalCount();
    int ret;
    // If we are reading value first time or block is handed.
    bool first = reply.GetTotalCount() == 0 || reply.GetCommandType() == DLMS_SINGLE_READ_RESPONSE_DATA_BLOCK_RESULT;
    if (first)
    {
        if ((ret = GXHelpers::GetObjectCount(reply.GetData(), cnt)) != 0)
        {
            return ret;
        }
        reply.SetTotalCount(cnt);
    }

#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        reply.GetXml()->IntegerToHex(cnt, 2, str);
        reply.GetXml()->AppendStartTag(DLMS_COMMAND_READ_RESPONSE, "Qty", str);
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    if (cnt != 1)
    {
        //Parse data after all data is received when readlist is used.
        if (reply.IsMoreData())
        {
            GetDataFromBlock(reply.GetData(), 0);
            return DLMS_ERROR_CODE_FALSE;
        }
        reply.GetData().SetPosition(0);
    }
    DLMS_SINGLE_READ_RESPONSE type;
    CGXDLMSVariant values;
    values.vt = DLMS_DATA_TYPE_ARRAY;
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    bool standardXml = reply.GetXml() != NULL && reply.GetXml()->GetOutputType() == DLMS_TRANSLATOR_OUTPUT_TYPE_STANDARD_XML;
#endif //DLMS_IGNORE_XML_TRANSLATOR
    for (pos = 0; pos != cnt; ++pos)
    {
        // Get response type code.
        if ((ret = reply.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        reply.SetCommandType(ch);
        type = (DLMS_SINGLE_READ_RESPONSE)ch;
        switch (type)
        {
        case DLMS_SINGLE_READ_RESPONSE_DATA:
#ifndef DLMS_IGNORE_XML_TRANSLATOR
            if (reply.GetXml() != NULL)
            {
                if (standardXml)
                {
                    reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_CHOICE);
                }
                reply.GetXml()->AppendStartTag(DLMS_COMMAND_READ_RESPONSE, DLMS_SINGLE_READ_RESPONSE_DATA);
                CGXDataInfo di;
                di.SetXml(reply.GetXml());
                CGXDLMSVariant value;
                if ((ret = GXHelpers::GetData(&settings, reply.GetData(), di, value)) != 0)
                {
                    return ret;
                }
                reply.GetXml()->AppendEndTag(DLMS_COMMAND_READ_RESPONSE, (unsigned long)DLMS_SINGLE_READ_RESPONSE_DATA);
                if (standardXml)
                {
                    reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_CHOICE);
                }
            }
            else
#endif //DLMS_IGNORE_XML_TRANSLATOR
                if (cnt == 1)
                {
                    ret = GetDataFromBlock(reply.GetData(), 0);
                }
                else
                {
                    // If read multiple items.
                    reply.SetReadPosition(reply.GetData().GetPosition());
                    GetValueFromData(settings, reply);
                    reply.GetData().SetPosition(reply.GetReadPosition());
                    values.Arr.push_back(reply.GetValue());
                    reply.GetValue().Clear();
                }
            break;
        case DLMS_SINGLE_READ_RESPONSE_DATA_ACCESS_ERROR:
            // Get error code.
            if ((ret = reply.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
            if (reply.GetXml() == NULL)
            {
                return ch;
            }
            if (standardXml)
            {
                reply.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_CHOICE);
            }
            CGXDLMSTranslator::ErrorCodeToString(
                reply.GetXml()->GetOutputType(),
                (DLMS_ERROR_CODE)ch, str);
            reply.GetXml()->AppendLine(
                DLMS_COMMAND_READ_RESPONSE << 8
                | DLMS_SINGLE_READ_RESPONSE_DATA_ACCESS_ERROR,
                "", str);
            if (standardXml)
            {
                reply.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_CHOICE);
            }
#else
            return ch;
#endif //DLMS_IGNORE_XML_TRANSLATOR
            break;
        case DLMS_SINGLE_READ_RESPONSE_DATA_BLOCK_RESULT:
            if ((ret = ReadResponseDataBlockResult(settings, reply, index)) != 0)
            {
                return ret;
            }
            break;
        case DLMS_SINGLE_READ_RESPONSE_BLOCK_NUMBER:
            // Get Block number.
            unsigned short number;
            if ((ret = reply.GetData().GetUInt16(&number)) != 0)
            {
                return ret;
            }
            if (number != settings.GetBlockIndex())
            {
                //Invalid Block number
                return DLMS_ERROR_CODE_DATA_BLOCK_NUMBER_INVALID;
            }
            settings.IncreaseBlockIndex();
            reply.SetMoreData((DLMS_DATA_REQUEST_TYPES)(reply.GetMoreData() | DLMS_DATA_REQUEST_TYPES_BLOCK));
            break;
        default:
            //HandleReadResponse failed. Invalid tag.
            return DLMS_ERROR_CODE_INVALID_TAG;
        }
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (reply.GetXml() != NULL)
    {
        reply.GetXml()->AppendEndTag(DLMS_COMMAND_READ_RESPONSE);
        return 0;
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    if (values.Arr.size() != 0)
    {
        reply.SetValue(values);
    }
    if (cnt != 1)
    {
        return DLMS_ERROR_CODE_FALSE;
    }
    return 0;
}

int CGXDLMS::GetTcpData(
    CGXDLMSSettings& settings,
    CGXByteBuffer& buff,
    CGXReplyData& data,
    CGXReplyData* notify)
{
    CGXReplyData* target = &data;
    int ret;
    // If whole frame is not received yet.
    if (buff.GetSize() - buff.GetPosition() < 8)
    {
        data.SetComplete(false);
        return DLMS_ERROR_CODE_OK;
    }
    bool isData = true;
    int pos = buff.GetPosition();
    unsigned short value;
    data.SetComplete(false);
    if (notify != NULL)
    {
        notify->SetComplete(false);
    }
    while (buff.GetPosition() < buff.GetSize() - 1)
    {
        // Get version
        if ((ret = buff.GetUInt16(&value)) != 0)
        {
            return DLMS_ERROR_CODE_OK;
        }
        if (value == 1)
        {
            // Check TCP/IP addresses.
            if ((ret = CheckWrapperAddress(settings, buff, notify)) != 0 && ret != DLMS_ERROR_CODE_FALSE)
            {
                return ret;
            }
            if (ret == DLMS_ERROR_CODE_FALSE)
            {
                target = notify;
                isData = false;
            }
            // Get length.
            if ((ret = buff.GetUInt16(&value)) != 0)
            {
                return ret;
            }

            bool complete = !((buff.GetSize() - buff.GetPosition()) < value);
            target->SetComplete(complete);
            if (!complete)
            {
                buff.SetPosition(pos);
                return DLMS_ERROR_CODE_FALSE;
            }
            else
            {
                target->SetPacketLength(buff.GetPosition() + value);
            }
            break;
        }
        else
        {
            buff.SetPosition(buff.GetPosition() - 1);
        }
    }
    if (!isData)
    {
        return DLMS_ERROR_CODE_FALSE;
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::GetAddressBytes(unsigned long value, CGXByteBuffer& bytes)
{
    int ret;
    unsigned long address;
    int size;
    if ((ret = GetAddress(value, address, size)) != 0)
    {
        return ret;
    }
    if (size == 1)
    {
        bytes.Capacity(1);
        bytes.SetUInt8((unsigned char)address);
    }
    else if (size == 2)
    {
        bytes.Capacity(2);
        bytes.SetUInt16((unsigned short)address);
    }
    else if (size == 4)
    {
        bytes.Capacity(4);
        bytes.SetUInt32((unsigned long)address);
    }
    else
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::GetValueFromData(CGXDLMSSettings& settings, CGXReplyData& reply)
{
    int ret;
    CGXDataInfo info;
    if (reply.GetValue().vt == DLMS_DATA_TYPE_ARRAY)
    {
        info.SetType(DLMS_DATA_TYPE_ARRAY);
        info.SetCount(reply.GetTotalCount());
        info.SetIndex(reply.GetCount());
    }
    CGXDLMSVariant value;
    int index = reply.GetData().GetPosition();
    reply.GetData().SetPosition(reply.GetReadPosition());
    if ((ret = GXHelpers::GetData(&settings, reply.GetData(), info, value)) != 0)
    {
        return ret;
    }
    // If new data.
    if (value.vt != DLMS_DATA_TYPE_NONE)
    {
        if (value.vt != DLMS_DATA_TYPE_ARRAY)
        {
            reply.SetValueType(info.GetType());
            reply.SetValue(value);
            reply.SetTotalCount(0);
            reply.SetReadPosition(reply.GetData().GetPosition());
        }
        else
        {
            if (value.Arr.size() != 0)
            {
                if (reply.GetValue().vt == DLMS_DATA_TYPE_NONE)
                {
                    reply.SetValue(value);
                }
                else
                {
                    CGXDLMSVariant tmp = reply.GetValue();
                    tmp.Arr.insert(tmp.Arr.end(), value.Arr.begin(), value.Arr.end());
                    reply.SetValue(tmp);
                }
            }
            reply.SetReadPosition(reply.GetData().GetPosition());
            // Element count.
            reply.SetTotalCount(info.GetCount());
        }
    }
    else if (info.IsComplete()
        && reply.GetCommand() == DLMS_COMMAND_DATA_NOTIFICATION)
    {
        // If last item is NULL. This is a special case.
        reply.SetReadPosition(reply.GetData().GetPosition());
    }
    reply.GetData().SetPosition(index);

    // If last data frame of the data block is read.
    if (reply.GetCommand() != DLMS_COMMAND_DATA_NOTIFICATION
        && info.IsComplete()
        && reply.GetMoreData() == DLMS_DATA_REQUEST_TYPES_NONE)
    {
        // If all blocks are read.
        settings.ResetBlockIndex();
        reply.GetData().SetPosition(0);
    }
    return 0;
}

void CGXDLMS::GetDataFromFrame(CGXByteBuffer& reply, CGXReplyData& info, bool hdlc)
{
    CGXByteBuffer& data = info.GetData();
    int offset = data.GetSize();
    int cnt = info.GetPacketLength() - reply.GetPosition();
    if (cnt != 0)
    {
        data.Capacity(offset + cnt);
        data.Set(&reply, reply.GetPosition(), cnt);
        if (hdlc)
        {
            reply.SetPosition(reply.GetPosition() + 3);
        }

    }
    // Set position to begin of new data.
    data.SetPosition(offset);
}

void CGXDLMS::GetLLCBytes(bool server, CGXByteBuffer& data)
{
    if (server)
    {
        data.Compare((unsigned char*)LLC_SEND_BYTES, 3);
    }
    else
    {
        data.Compare((unsigned char*)LLC_REPLY_BYTES, 3);
    }
}

// Descrypt two bytes to Flag name.
// value: Encrypted Flag name.
// Returns: Flag name.
std::string DecryptManufacturer(uint16_t value)
{
    uint16_t tmp = (uint16_t)(value >> 8 | value << 8);
    char c = (char)((tmp & 0x1f) + 0x40);
    tmp = (uint16_t)(tmp >> 5);
    char c1 = (char)((tmp & 0x1f) + 0x40);
    tmp = (uint16_t)(tmp >> 5);
    char c2 = (char)((tmp & 0x1f) + 0x40);
    std::string str;
    str.push_back(c2);
    str.push_back(c1);
    str.push_back(c);
    return str;
}

int CGXDLMS::GetMBusData(
    CGXDLMSSettings& settings,
    CGXByteBuffer& buff,
    CGXReplyData& data)
{
    int ret;
    unsigned char len, ch;
    //L-field.
    if ((ret = buff.GetUInt8(&len)) != 0)
    {
        return ret;
    }
    //Some meters are counting length to frame size.
    if (buff.GetSize() < (unsigned char)(len - 1))
    {
        data.SetComplete(false);
        buff.SetPosition(buff.GetPosition() - 1);
    }
    else
    {
        //Some meters are counting length to frame size.
        if (buff.GetSize() < len)
        {
            --len;
        }
        data.SetPacketLength(len);
        data.SetComplete(true);
        //C-field.
        if ((ret = buff.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        DLMS_MBUS_COMMAND cmd = (DLMS_MBUS_COMMAND)ch;
        //M-Field.
        uint16_t manufacturerID;
        if ((ret = buff.GetUInt16(&manufacturerID)) != 0)
        {
            return ret;
        }
        //A-Field.
        unsigned long id;
        if ((ret = buff.GetUInt32(&id)) != 0)
        {
            return ret;
        }
        unsigned char meterVersion;
        if ((ret = buff.GetUInt8(&meterVersion)) != 0)
        {
            return ret;
        }
        if ((ret = buff.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        DLMS_MBUS_METER_TYPE type = (DLMS_MBUS_METER_TYPE)ch;
        // CI-Field
        if ((ret = buff.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        DLMS_MBUS_CONTROL_INFO ci = (DLMS_MBUS_CONTROL_INFO)ch;
        //Access number.
        unsigned char frameId;
        if ((ret = buff.GetUInt8(&frameId)) != 0)
        {
            return ret;
        }
        //State of the meter
        unsigned char state;
        if ((ret = buff.GetUInt8(&state)) != 0)
        {
            return ret;
        }
        //Configuration word.
        uint16_t configurationWord;
        if ((ret = buff.GetUInt16(&configurationWord)) != 0)
        {
            return ret;
        }
        //unsigned char encryptedBlocks = (unsigned char)(configurationWord >> 12);
        DLMS_MBUS_ENCRYPTION_MODE encryption = (DLMS_MBUS_ENCRYPTION_MODE)(configurationWord & 7);
        if ((ret = buff.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        settings.SetClientAddress(ch);
        if ((ret = buff.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        settings.SetServerAddress(ch);
        if (data.GetXml() != NULL && data.GetXml()->GetComments())
        {
            std::string man = DecryptManufacturer(manufacturerID);
            data.GetXml()->AppendComment("Command: " + cmd);
            data.GetXml()->AppendComment("Manufacturer: " + man);
            data.GetXml()->AppendComment("Meter Version: " + meterVersion);
            data.GetXml()->AppendComment("Meter Type: " + type);
            data.GetXml()->AppendComment("Control Info: " + ci);
            data.GetXml()->AppendComment("Encryption: " + encryption);
        }
    }
    return ret;
}

int CGXDLMS::GetPlcData(
    CGXDLMSSettings& settings,
    CGXByteBuffer& buff,
    CGXReplyData& data)
{
    if (buff.Available() < 9)
    {
        data.SetComplete(false);
        return 0;
    }
    unsigned char ch;
    int ret;
    unsigned short pos;
    int packetStartID = buff.GetPosition();
    // Find STX.
    unsigned char stx;
    for (pos = (unsigned short)buff.GetPosition(); pos < buff.GetSize(); ++pos)
    {
        if ((ret = buff.GetUInt8(&stx)) != 0)
        {
            return ret;
        }
        if (stx == 2)
        {
            packetStartID = pos;
            break;
        }
    }
    // Not a PLC frame.
    if (buff.GetPosition() == buff.GetSize())
    {
        // Not enough data to parse;
        data.SetComplete(false);
        buff.SetPosition(packetStartID);
        return 0;
    }
    unsigned char len;
    if ((ret = buff.GetUInt8(&len)) != 0)
    {
        return ret;
    }
    int index = buff.GetPosition();
    if (buff.Available() < len)
    {
        data.SetComplete(false);
        buff.SetPosition(buff.GetPosition() - 2);
    }
    else
    {
        if ((ret = buff.GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        //Credit fields.  IC, CC, DC
        unsigned char credit;
        if ((ret = buff.GetUInt8(&credit)) != 0)
        {
            return ret;
        }
        //MAC Addresses.
        unsigned int mac;
        if ((ret = buff.GetUInt24(&mac)) != 0)
        {
            return ret;
        }
        //SA.
        short macSa = (short)(mac >> 12);
        //DA.
        short macDa = (short)(mac & 0xFFF);
        //PAD length.
        unsigned char padLen;
        if ((ret = buff.GetUInt8(&padLen)) != 0)
        {
            return ret;
        }

        if (buff.GetSize() < (unsigned short)(len + padLen + 2))
        {
            data.SetComplete(false);
            buff.SetPosition(buff.GetPosition() - index - 6);
        }
        else
        {
            //DL.Data.request
            if ((ret = buff.GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            if (ch != DLMS_PLC_DATA_LINK_DATA_REQUEST)
            {
                //Parsing MAC LLC data failed. Invalid DataLink data request.
                return DLMS_ERROR_CODE_INVALID_COMMAND;
            }
            unsigned char da, sa;
            if ((ret = buff.GetUInt8(&da)) != 0 ||
                (ret = buff.GetUInt8(&sa)) != 0)
            {
                return ret;
            }
            if (settings.IsServer())
            {
                data.SetComplete(
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                    data.GetXml() != NULL ||
#endif // DLMS_IGNORE_XML_TRANSLATOR
                    ((macDa == DLMS_PLC_DESTINATION_ADDRESS_ALL_PHYSICAL || macDa == settings.GetPlcSettings().GetMacSourceAddress()) &&
                        (macSa == DLMS_PLC_SOURCE_ADDRESS_INITIATOR || macSa == settings.GetPlcSettings().GetMacDestinationAddress())));
                data.SetServerAddress(macDa);
                data.SetClientAddress(macSa);
            }
            else
            {
                data.SetComplete(
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                    data.GetXml() != NULL ||
#endif //DLMS_IGNORE_XML_TRANSLATOR
                    (macDa == DLMS_PLC_DESTINATION_ADDRESS_ALL_PHYSICAL ||
                        macDa == DLMS_PLC_SOURCE_ADDRESS_INITIATOR ||
                        macDa == settings.GetPlcSettings().GetMacDestinationAddress()));
                data.SetClientAddress(macDa);
                data.SetServerAddress(macSa);
            }
            //Skip padding.
            if (data.IsComplete())
            {
                uint16_t crcCount, crc;
                crcCount = CountFCS16(buff, 0, len + padLen);
                if ((ret = buff.GetUInt16(len + padLen, &crc)) != 0)
                {
                    return ret;
                }
                //Check CRC.
                if (crc != crcCount)
                {
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                    if (data.GetXml() == NULL)
                    {
                        //Invalid data checksum.
                        return DLMS_ERROR_CODE_WRONG_CRC;
                    }
                    data.GetXml()->AppendComment("Invalid data checksum.");
#else
                    //Invalid data checksum.
                    return DLMS_ERROR_CODE_WRONG_CRC;
#endif //DLMS_IGNORE_XML_TRANSLATOR
                }
                data.SetPacketLength(len);
            }
        }
    }
    return ret;
}

int CGXDLMS::GetPlcHdlcData(
    CGXDLMSSettings& settings,
    CGXByteBuffer& buff,
    CGXReplyData& data,
    unsigned char* frame)
{
    if (buff.Available() < 2)
    {
        data.SetComplete(false);
        return 0;
    }
    int ret;
    *frame = 0;
    unsigned char frameLen;
    //SN field.
    uint16_t ns;
    if ((ret = buff.GetUInt16(&ns)) != 0)
    {
        return ret;
    }
    switch (ns)
    {
    case DLMS_PLC_MAC_SUB_FRAMES_ONE:
        frameLen = 36;
        break;
    case DLMS_PLC_MAC_SUB_FRAMES_TWO:
        frameLen = 2 * 36;
        break;
    case DLMS_PLC_MAC_SUB_FRAMES_THREE:
        frameLen = 3 * 36;
        break;
    case DLMS_PLC_MAC_SUB_FRAMES_FOUR:
        frameLen = 4 * 36;
        break;
    case DLMS_PLC_MAC_SUB_FRAMES_FIVE:
        frameLen = 5 * 36;
        break;
    case DLMS_PLC_MAC_SUB_FRAMES_SIX:
        frameLen = 6 * 36;
        break;
    case DLMS_PLC_MAC_SUB_FRAMES_SEVEN:
        frameLen = 7 * 36;
        break;
    default:
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    if (buff.Available() < (unsigned char)(frameLen - 2))
    {
        data.SetComplete(false);
    }
    else
    {
        unsigned long index = buff.GetPosition();
        //Credit fields.  IC, CC, DC
        unsigned char credit;
        if ((ret = buff.GetUInt8(&credit)) != 0)
        {
            return ret;
        }
        //MAC Addresses.
        unsigned int mac;
        if ((ret = buff.GetUInt24(&mac)) != 0)
        {
            return ret;
        }
        //SA.
        unsigned short sa = (unsigned short)(mac >> 12);
        //DA.
        unsigned short da = (unsigned short)(mac & 0xFFF);
        if (settings.IsServer())
        {
            data.SetComplete(
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                data.GetXml() != NULL ||
#endif // DLMS_IGNORE_XML_TRANSLATOR

                ((da == DLMS_PLC_DESTINATION_ADDRESS_ALL_PHYSICAL || da == settings.GetPlcSettings().GetMacSourceAddress()) &&
                    (sa == DLMS_PLC_HDLC_SOURCE_ADDRESS_INITIATOR || sa == settings.GetPlcSettings().GetMacDestinationAddress())));
            data.SetServerAddress(da);
            data.SetClientAddress(sa);
        }
        else
        {
            data.SetComplete(
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                data.GetXml() != NULL ||
#endif // DLMS_IGNORE_XML_TRANSLATOR
                (da == DLMS_PLC_HDLC_SOURCE_ADDRESS_INITIATOR || da == settings.GetPlcSettings().GetMacDestinationAddress()));
            data.SetServerAddress(da);
            data.SetClientAddress(sa);
        }
        if (data.IsComplete())
        {
            //PAD length.
            unsigned char padLen;
            if ((ret = buff.GetUInt8(&padLen)) != 0)
            {
                return ret;
            }
            if ((ret = GetHdlcData(settings.IsServer(), settings, buff, data, *frame, NULL)) != 0)
            {
                return ret;
            }
            GetDataFromFrame(buff, data, true);
            buff.SetPosition(buff.GetPosition() + padLen);
            uint32_t crcCount = CountFCS24(buff.GetData(), index, buff.GetPosition() - index);
            unsigned int crc;
            if ((ret = buff.GetUInt24(buff.GetPosition(), &crc)) != 0)
            {
                return ret;
            }
            //Check CRC.
            if (crc != crcCount)
            {
#ifndef DLMS_IGNORE_XML_TRANSLATOR
                if (data.GetXml() == NULL)
                {
                    //Invalid data checksum.
                    return DLMS_ERROR_CODE_WRONG_CRC;
                }
                data.GetXml()->AppendComment("Invalid data checksum.");
#else
                //Invalid data checksum.
                return DLMS_ERROR_CODE_WRONG_CRC;
#endif //DLMS_IGNORE_XML_TRANSLATOR
            }
            data.SetPacketLength(2 + buff.GetPosition() - index);
        }
        else
        {
            buff.SetPosition(buff.GetPosition() + frameLen - index - 4);
        }
    }
    return ret;
}

// Check is this PLC S-FSK message.
// buff: Received data.
// Returns True, if this is PLC message.
bool IsPlcSfskData(CGXByteBuffer& buff)
{
    if (buff.Available() < 2)
    {
        return false;
    }
    uint16_t len;
    if (buff.GetUInt16(buff.GetPosition(), &len) != 0)
    {
        return false;
    }
    switch (len)
    {
    case DLMS_PLC_MAC_SUB_FRAMES_ONE:
    case DLMS_PLC_MAC_SUB_FRAMES_TWO:
    case DLMS_PLC_MAC_SUB_FRAMES_THREE:
    case DLMS_PLC_MAC_SUB_FRAMES_FOUR:
    case DLMS_PLC_MAC_SUB_FRAMES_FIVE:
    case DLMS_PLC_MAC_SUB_FRAMES_SIX:
    case DLMS_PLC_MAC_SUB_FRAMES_SEVEN:
        return true;
    default:
        return false;
    }
}

int CGXDLMS::CheckWrapperAddress(
    CGXDLMSSettings& settings,
    CGXByteBuffer& buff,
    CGXReplyData* notify)
{
    int ret;
    unsigned short value;
    if (settings.IsServer())
    {
        if ((ret = buff.GetUInt16(&value)) != 0)
        {
            return ret;
        }
        // Check that client addresses match.
        if (settings.GetClientAddress() != 0
            && settings.GetClientAddress() != value)
        {
            return DLMS_ERROR_CODE_INVALID_CLIENT_ADDRESS;
        }
        else
        {
            settings.SetClientAddress(value);
        }

        if ((ret = buff.GetUInt16(&value)) != 0)
        {
            return ret;
        }
        // Check that server addresses match.
        if (settings.GetServerAddress() != 0
            && settings.GetServerAddress() != value)
        {
            return DLMS_ERROR_CODE_INVALID_SERVER_ADDRESS;
        }
        else
        {
            settings.SetServerAddress(value);
        }
    }
    else
    {
        if ((ret = buff.GetUInt16(&value)) != 0)
        {
            return ret;
        }
        // Check that server addresses match.
        if (settings.GetServerAddress() != 0
            && settings.GetServerAddress() != value)
        {
            if (notify == NULL)
            {
                return DLMS_ERROR_CODE_INVALID_SERVER_ADDRESS;
            }
            notify->SetServerAddress(value);
        }
        else
        {
            settings.SetServerAddress(value);
        }

        if ((ret = buff.GetUInt16(&value)) != 0)
        {
            return ret;
        }
        // Check that client addresses match.
        if (settings.GetClientAddress() != 0
            && settings.GetClientAddress() != value)
        {
            if (notify != NULL)
            {
                notify->SetClientAddress(value);
                return DLMS_ERROR_CODE_FALSE;
            }
            return DLMS_ERROR_CODE_INVALID_CLIENT_ADDRESS;
        }
        else
        {
            settings.SetClientAddress(value);
        }
    }
    return DLMS_ERROR_CODE_OK;
}

unsigned short CGXDLMS::CountFCS16(CGXByteBuffer& buff, int index, int count)
{
    int ret;
    unsigned char ch;
    unsigned short fcs16 = 0xFFFF;
    for (short pos = 0; pos < count; ++pos)
    {
        if ((ret = buff.GetUInt8(index + pos, &ch)) != 0)
        {
            return ret;
        }
        fcs16 = (fcs16 >> 8) ^ FCS16Table[(fcs16 ^ ch) & 0xFF];
    }
    fcs16 = ~fcs16;
    fcs16 = ((fcs16 >> 8) & 0xFF) | (fcs16 << 8);
    return fcs16;
}

// Reserved for internal use.
const uint32_t CRCPOLY = 0xD3B6BA00;
uint32_t CGXDLMS::CountFCS24(unsigned char* buff, int index, int count)
{
    unsigned char i, j;
    uint32_t crcreg = 0;
    for (j = 0; j < count; ++j)
    {
        unsigned char b = buff[index + j];
        for (i = 0; i < 8; ++i)
        {
            crcreg >>= 1;
            if ((b & 0x80) != 0)
            {
                crcreg |= 0x80000000;
            }
            if ((crcreg & 0x80) != 0)
            {
                crcreg = crcreg ^ CRCPOLY;
            }
            b <<= 1;
        }
    }
    return crcreg >> 8;
}

int CGXDLMS::GetActionInfo(DLMS_OBJECT_TYPE objectType, unsigned char& value, unsigned char& count)
{
    switch (objectType)
    {
    case DLMS_OBJECT_TYPE_DATA:
    case DLMS_OBJECT_TYPE_ACTION_SCHEDULE:
    case DLMS_OBJECT_TYPE_ALL:
    case DLMS_OBJECT_TYPE_AUTO_ANSWER:
    case DLMS_OBJECT_TYPE_AUTO_CONNECT:
    case DLMS_OBJECT_TYPE_MAC_ADDRESS_SETUP:
    case DLMS_OBJECT_TYPE_GPRS_SETUP:
    case DLMS_OBJECT_TYPE_IEC_HDLC_SETUP:
    case DLMS_OBJECT_TYPE_IEC_LOCAL_PORT_SETUP:
    case DLMS_OBJECT_TYPE_IEC_TWISTED_PAIR_SETUP:
    case DLMS_OBJECT_TYPE_MODEM_CONFIGURATION:
    case DLMS_OBJECT_TYPE_PPP_SETUP:
    case DLMS_OBJECT_TYPE_REGISTER_MONITOR:
    case DLMS_OBJECT_TYPE_ZIG_BEE_SAS_STARTUP:
    case DLMS_OBJECT_TYPE_ZIG_BEE_SAS_JOIN:
    case DLMS_OBJECT_TYPE_ZIG_BEE_SAS_APS_FRAGMENTATION:
    case DLMS_OBJECT_TYPE_ZIG_BEE_NETWORK_CONTROL:
    case DLMS_OBJECT_TYPE_SCHEDULE:
    case DLMS_OBJECT_TYPE_SMTP_SETUP:
    case DLMS_OBJECT_TYPE_STATUS_MAPPING:
    case DLMS_OBJECT_TYPE_TCP_UDP_SETUP:
    case DLMS_OBJECT_TYPE_UTILITY_TABLES:
        value = 00;
        count = 0;
        break;
    case DLMS_OBJECT_TYPE_IMAGE_TRANSFER:
        value = 0x40;
        count = 4;
        break;
    case DLMS_OBJECT_TYPE_ACTIVITY_CALENDAR:
        value = 0x50;
        count = 1;
        break;
    case DLMS_OBJECT_TYPE_ASSOCIATION_LOGICAL_NAME:
        value = 0x60;
        count = 4;
        break;
    case DLMS_OBJECT_TYPE_ASSOCIATION_SHORT_NAME:
        value = 0x20;
        count = 8;
        break;
    case DLMS_OBJECT_TYPE_CLOCK:
        value = 0x60;
        count = 6;
        break;
    case DLMS_OBJECT_TYPE_DEMAND_REGISTER:
        value = 0x48;
        count = 2;
        break;
    case DLMS_OBJECT_TYPE_EXTENDED_REGISTER:
        value = 0x38;
        count = 1;
        break;
    case DLMS_OBJECT_TYPE_IP4_SETUP:
        value = 0x60;
        count = 3;
        break;
    case DLMS_OBJECT_TYPE_MBUS_SLAVE_PORT_SETUP:
        value = 0x60;
        count = 8;
        break;
    case DLMS_OBJECT_TYPE_PROFILE_GENERIC:
        value = 0x58;
        count = 4;
        break;
    case DLMS_OBJECT_TYPE_REGISTER:
        value = 0x28;
        count = 1;
        break;
    case DLMS_OBJECT_TYPE_REGISTER_ACTIVATION:
        value = 0x30;
        count = 3;
        break;
    case DLMS_OBJECT_TYPE_REGISTER_TABLE:
        value = 0x28;
        count = 2;
        break;
    case DLMS_OBJECT_TYPE_SAP_ASSIGNMENT:
    case DLMS_OBJECT_TYPE_SCRIPT_TABLE:
        value = 0x20;
        count = 1;
        break;
    case DLMS_OBJECT_TYPE_SPECIAL_DAYS_TABLE:
        value = 0x10;
        count = 2;
        break;
    case DLMS_OBJECT_TYPE_DISCONNECT_CONTROL:
        value = 0x20;
        count = 2;
        break;
    case DLMS_OBJECT_TYPE_PUSH_SETUP:
        value = 0x38;
        count = 1;
        break;
    case DLMS_OBJECT_TYPE_SECURITY_SETUP:
        value = 0x30;
        count = 8;
        break;
    default:
        count = value = 0;
        break;
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMS::AppendData(
    CGXDLMSSettings* settings,
    CGXDLMSObject* obj,
    unsigned char index,
    CGXByteBuffer& bb,
    CGXDLMSVariant& value)
{

    int ret;
    DLMS_DATA_TYPE tp;
    if ((ret = obj->GetDataType(index, tp)) != 0)
    {
        return ret;
    }
    if (tp == DLMS_DATA_TYPE_ARRAY)
    {
        if (value.vt == DLMS_DATA_TYPE_OCTET_STRING)
        {
            bb.Set(value.byteArr, value.GetSize());
            return 0;
        }
    }
    else
    {
        if (tp == DLMS_DATA_TYPE_NONE)
        {
            tp = value.vt;
            // If data type is not defined for Date Time it is write as
            // octet string.
            if (tp == DLMS_DATA_TYPE_DATETIME)
            {
                tp = DLMS_DATA_TYPE_OCTET_STRING;
            }
        }
    }
    return GXHelpers::SetData(settings, bb, tp, value);
}

int CGXDLMS::ParseSnrmUaResponse(
    CGXByteBuffer& data,
    CGXHdlcSettings* limits)
{
    unsigned char ch, id, len;
    unsigned short ui;
    unsigned long ul;
    int ret;
    //If default settings are used.
    if (data.GetSize() == 0)
    {
        limits->SetMaxInfoRX(CGXDLMSLimits::DEFAULT_MAX_INFO_RX);
        limits->SetMaxInfoTX(CGXDLMSLimits::DEFAULT_MAX_INFO_TX);
        limits->SetWindowSizeRX(CGXDLMSLimits::DEFAULT_WINDOWS_SIZE_RX);
        limits->SetWindowSizeTX(CGXDLMSLimits::DEFAULT_WINDOWS_SIZE_TX);
        return 0;
    }
    // Skip FromatID
    if ((ret = data.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    // Skip Group ID.
    if ((ret = data.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    // Skip Group len
    if ((ret = data.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    CGXDLMSVariant value;
    while (data.GetPosition() < data.GetSize())
    {
        if ((ret = data.GetUInt8(&id)) != 0)
        {
            return ret;
        }
        if ((ret = data.GetUInt8(&len)) != 0)
        {
            return ret;
        }
        switch (len)
        {
        case 1:
            if ((ret = data.GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            value = ch;
            break;
        case 2:
            if ((ret = data.GetUInt16(&ui)) != 0)
            {
                return ret;
            }
            value = ui;
            break;
        case 4:
            if ((ret = data.GetUInt32(&ul)) != 0)
            {
                return ret;
            }
            value = ul;
            break;
        default:
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        // RX / TX are delivered from the partner's point of view =>
        // reversed to ours
        switch (id)
        {
        case HDLC_INFO_MAX_INFO_TX:
            limits->SetMaxInfoRX((unsigned short)value.ToInteger());
            break;
        case HDLC_INFO_MAX_INFO_RX:
            limits->SetMaxInfoTX((unsigned short)value.ToInteger());
            break;
        case HDLC_INFO_WINDOW_SIZE_TX:
            limits->SetWindowSizeRX((unsigned char)value.ToInteger());
            break;
        case HDLC_INFO_WINDOW_SIZE_RX:
            limits->SetWindowSizeTX((unsigned char)value.ToInteger());
            break;
        default:
            ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
            break;
        }
    }
    return ret;
}

void CGXDLMS::AppendHdlcParameter(CGXByteBuffer& data, unsigned short value)
{
    if (value < 0x100)
    {
        data.SetUInt8(1);
        data.SetUInt8((unsigned char)value);
    }
    else
    {
        data.SetUInt8(2);
        data.SetUInt16(value);
    }
}

int CGXDLMS::HandleConfirmedServiceError(CGXReplyData& data)
{
    int ret;
    unsigned char ch;
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        data.GetXml()->AppendStartTag(DLMS_COMMAND_CONFIRMED_SERVICE_ERROR);
        if (data.GetXml()->GetOutputType() == DLMS_TRANSLATOR_OUTPUT_TYPE_STANDARD_XML)
        {
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            data.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_INITIATE_ERROR);
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            DLMS_SERVICE_ERROR type = (DLMS_SERVICE_ERROR)ch;
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            std::string tag = CTranslatorStandardTags::ServiceErrorToString(type);
            std::string value = CTranslatorStandardTags::GetServiceErrorValue(type, ch);
            data.GetXml()->AppendLine("x:" + tag, "", value);
            data.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_INITIATE_ERROR);
        }
        else
        {
            std::string str;
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            data.GetXml()->IntegerToHex((long)ch, 2, str);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_SERVICE, "", str);
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            DLMS_SERVICE_ERROR type = (DLMS_SERVICE_ERROR)ch;
            data.GetXml()->AppendStartTag(DLMS_TRANSLATOR_TAGS_SERVICE_ERROR);
            if ((ret = data.GetData().GetUInt8(&ch)) != 0)
            {
                return ret;
            }
            std::string tag = CTranslatorSimpleTags::ServiceErrorToString(type);
            std::string value = CTranslatorSimpleTags::GetServiceErrorValue(type, ch);
            data.GetXml()->AppendLine(tag, "", value);
            data.GetXml()->AppendEndTag(DLMS_TRANSLATOR_TAGS_SERVICE_ERROR);
        }
        data.GetXml()->AppendEndTag(DLMS_COMMAND_CONFIRMED_SERVICE_ERROR);
    }
    else
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        DLMS_CONFIRMED_SERVICE_ERROR service = (DLMS_CONFIRMED_SERVICE_ERROR)ch;
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        DLMS_SERVICE_ERROR type = (DLMS_SERVICE_ERROR)ch;
        if ((ret = data.GetData().GetUInt8(&ch)) != 0)
        {
            return ret;
        }
        return DLMS_ERROR_TYPE_CONFIRMED_SERVICE_ERROR | service << 16 | type << 8 | ch;
    }
    return 0;
}

int CGXDLMS::HandleExceptionResponse(CGXReplyData& data)
{
    int ret;
    unsigned char ch;
    DLMS_EXCEPTION_SERVICE_ERROR error;
    if ((ret = data.GetData().GetUInt8(&ch)) != 0)
    {
        return ret;
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    DLMS_EXCEPTION_STATE_ERROR state = (DLMS_EXCEPTION_STATE_ERROR)ch;
#endif //DLMS_IGNORE_XML_TRANSLATOR
    if ((ret = data.GetData().GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    error = (DLMS_EXCEPTION_SERVICE_ERROR)ch;
    unsigned long value = 0;
    if (error == DLMS_EXCEPTION_SERVICE_ERROR_INVOCATION_COUNTER_ERROR && data.GetData().Available() > 3)
    {
        data.GetData().GetUInt32(&value);
    }
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if (data.GetXml() != NULL)
    {
        std::string str;
        data.GetXml()->AppendStartTag(DLMS_COMMAND_EXCEPTION_RESPONSE);
        if (data.GetXml()->GetOutputType() == DLMS_TRANSLATOR_OUTPUT_TYPE_STANDARD_XML)
        {
            str = CTranslatorStandardTags::StateErrorToString(state);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_STATE_ERROR, "", str);
            str = CTranslatorStandardTags::ExceptionServiceErrorToString(error);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_SERVICE_ERROR, "", str);
        }
        else
        {
            str = CTranslatorSimpleTags::StateErrorToString(state);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_STATE_ERROR, "", str);
            str = CTranslatorSimpleTags::ExceptionServiceErrorToString(error);
            data.GetXml()->AppendLine(DLMS_TRANSLATOR_TAGS_SERVICE_ERROR, "", str);
        }
        data.GetXml()->AppendEndTag(DLMS_COMMAND_EXCEPTION_RESPONSE);
    }
    else
#endif //DLMS_IGNORE_XML_TRANSLATOR
    {
        return DLMS_ERROR_TYPE_EXCEPTION_RESPONSE | value << 8 | error;
    }
    return 0;
}
