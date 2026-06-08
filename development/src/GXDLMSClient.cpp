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

#include "../include/enums.h"
#include "../include/GXDLMSClient.h"
#include "../include/GXHelpers.h"
#include "../include/GXAPDU.h"
#include "../include/GXDLMSObjectFactory.h"
#include "../include/GXSecure.h"
#include "../include/GXSerialNumberCounter.h"
#include "../include/GXDLMSLNParameters.h"
#include "../include/GXDLMSSNParameters.h"
#include "../include/GXEcdsa.h"

CGXDLMSClient::CGXDLMSClient(bool UseLogicalNameReferencing,
    int clientAddress,
    int serverAddress,
    //Authentication type.
    DLMS_AUTHENTICATION authentication,
    //Password if authentication is used.
    const char* password,
    DLMS_INTERFACE_TYPE intefaceType) : m_Settings(false)
{
    m_UseProtectedRelease = false;
    m_IsAuthenticationRequired = false;
    m_Settings.SetUseLogicalNameReferencing(UseLogicalNameReferencing);
    m_Settings.SetClientAddress(clientAddress);
    m_Settings.SetServerAddress(serverAddress);
    m_Settings.SetInterfaceType(intefaceType);
    m_Settings.SetAuthentication(authentication);
    m_Settings.GetPassword().AddString(password);
    if (UseLogicalNameReferencing)
    {
        SetProposedConformance((DLMS_CONFORMANCE)(DLMS_CONFORMANCE_BLOCK_TRANSFER_WITH_ACTION |
            DLMS_CONFORMANCE_BLOCK_TRANSFER_WITH_SET_OR_WRITE |
            DLMS_CONFORMANCE_BLOCK_TRANSFER_WITH_GET_OR_READ |
            DLMS_CONFORMANCE_SET | DLMS_CONFORMANCE_SELECTIVE_ACCESS |
            DLMS_CONFORMANCE_ACTION | DLMS_CONFORMANCE_MULTIPLE_REFERENCES |
            DLMS_CONFORMANCE_GET | DLMS_CONFORMANCE_ACCESS));
    }
    else
    {
        SetProposedConformance((DLMS_CONFORMANCE)(DLMS_CONFORMANCE_INFORMATION_REPORT |
            DLMS_CONFORMANCE_READ | DLMS_CONFORMANCE_UN_CONFIRMED_WRITE |
            DLMS_CONFORMANCE_WRITE | DLMS_CONFORMANCE_PARAMETERIZED_ACCESS |
            DLMS_CONFORMANCE_MULTIPLE_REFERENCES));
    }
    m_Settings.GetPlcSettings().Reset();
    SetManufacturerId(NULL);
}

CGXDLMSClient::~CGXDLMSClient()
{
}

unsigned short CGXDLMSClient::GetMaxPduSize()
{
    return m_Settings.GetMaxPduSize();
}


bool CGXDLMSClient::GetUseUtc2NormalTime()
{
    return m_Settings.GetUseUtc2NormalTime();
}

void CGXDLMSClient::SetUseUtc2NormalTime(bool value)
{
    m_Settings.SetUseUtc2NormalTime(value);
}

uint64_t CGXDLMSClient::GetExpectedInvocationCounter()
{
    return m_Settings.GetExpectedInvocationCounter();
}

void CGXDLMSClient::SetExpectedInvocationCounter(uint64_t value)
{
    m_Settings.SetExpectedInvocationCounter(value);
}

DATETIME_SKIPS CGXDLMSClient::GetDateTimeSkips()
{
    return m_Settings.GetDateTimeSkips();
}

void CGXDLMSClient::SetDateTimeSkips(DATETIME_SKIPS value)
{
    m_Settings.SetDateTimeSkips(value);
}

unsigned char CGXDLMSClient::GetUserID()
{
    return m_Settings.GetUserID();
}

void CGXDLMSClient::SetUserID(unsigned char value)
{
    m_Settings.SetUserID(value);
}

unsigned char CGXDLMSClient::GetQualityOfService()
{
    return m_Settings.GetQualityOfService();
}

void CGXDLMSClient::SetQualityOfService(unsigned char value)
{
    m_Settings.SetQualityOfService(value);
}

CGXByteBuffer& CGXDLMSClient::GetSourceSystemTitle()
{
    return m_Settings.GetSourceSystemTitle();
}

int CGXDLMSClient::SetMaxReceivePDUSize(unsigned short value)
{
    return m_Settings.SetMaxReceivePDUSize(value);
}

unsigned short CGXDLMSClient::GetMaxReceivePDUSize()
{
    return m_Settings.GetMaxPduSize();
}

int CGXDLMSClient::SetGbtWindowSize(unsigned char value)
{
    m_Settings.SetGbtWindowSize(value);
    return 0;
}

unsigned char CGXDLMSClient::GetGbtWindowSize()
{
    return m_Settings.GetGbtWindowSize();
}

DLMS_CONFORMANCE CGXDLMSClient::GetNegotiatedConformance()
{
    return (DLMS_CONFORMANCE)m_Settings.GetNegotiatedConformance();
}

void CGXDLMSClient::SetNegotiatedConformance(DLMS_CONFORMANCE value)
{
    m_Settings.SetNegotiatedConformance(value);
}

DLMS_CONFORMANCE CGXDLMSClient::GetProposedConformance()
{
    return (DLMS_CONFORMANCE)m_Settings.GetProposedConformance();
}

void CGXDLMSClient::SetProposedConformance(DLMS_CONFORMANCE value)
{
    m_Settings.SetProposedConformance(value);
}

bool CGXDLMSClient::GetUseLogicalNameReferencing()
{
    return m_Settings.GetUseLogicalNameReferencing();
}

DLMS_INTERFACE_TYPE CGXDLMSClient::GetInterfaceType()
{
    return m_Settings.GetInterfaceType();
}

DLMS_PRIORITY CGXDLMSClient::GetPriority()
{
    return m_Settings.GetPriority();
}

void CGXDLMSClient::SetPriority(DLMS_PRIORITY value)
{
    m_Settings.SetPriority(value);
}

DLMS_SERVICE_CLASS CGXDLMSClient::GetServiceClass()
{
    return m_Settings.GetServiceClass();
}

DLMS_AUTHENTICATION CGXDLMSClient::GetAuthentication()
{
    return m_Settings.GetAuthentication();
}

void CGXDLMSClient::SetAuthentication(DLMS_AUTHENTICATION value)
{
    m_Settings.SetAuthentication(value);
}


unsigned long CGXDLMSClient::GetClientAddress()
{
    return m_Settings.GetClientAddress();
}

void CGXDLMSClient::SetClientAddress(unsigned long value)
{
    m_Settings.SetClientAddress(value);
}

unsigned long CGXDLMSClient::GetServerAddress()
{
    return m_Settings.GetServerAddress();
}

// Server address.
void CGXDLMSClient::SetServerAddress(unsigned long value)
{
    m_Settings.SetServerAddress(value);
}

void CGXDLMSClient::SetServiceClass(DLMS_SERVICE_CLASS value)
{
    m_Settings.SetServiceClass(value);
}

bool CGXDLMSClient::GetUseProtectedRelease()
{
    return m_UseProtectedRelease;
}

void CGXDLMSClient::SetUseProtectedRelease(bool value)
{
    m_UseProtectedRelease = value;
}

/**
   * @return Invoke ID.
   */
unsigned char CGXDLMSClient::GetInvokeID()
{
    return m_Settings.GetInvokeID();
}

/**
 * @param value
 *            Invoke ID.
 */
void CGXDLMSClient::SetInvokeID(unsigned char value) {
    m_Settings.SetInvokeID(value);
}

/**
 * @return Auto increase Invoke ID.
 */
bool CGXDLMSClient::GetAutoIncreaseInvokeID() {
    return m_Settings.GetAutoIncreaseInvokeID();
}

/**
 * @param value
 *            Auto increase Invoke ID.
 */
void CGXDLMSClient::SetAutoIncreaseInvokeID(bool value) {
    m_Settings.SetAutoIncreaseInvokeID(value);
}

CGXDLMSLimits& CGXDLMSClient::GetLimits()
{
    return m_Settings.GetHdlcSettings();
}

CGXHdlcSettings& CGXDLMSClient::GetHdlcSettings()
{
    return m_Settings.GetHdlcSettings();
}


CGXPlcSettings& CGXDLMSClient::GetPlcSettings()
{
    return m_Settings.GetPlcSettings();
}

// Collection of the objects.
CGXDLMSObjectCollection& CGXDLMSClient::GetObjects()
{
    return m_Settings.GetObjects();
}

int CGXDLMSClient::SNRMRequest(std::vector<CGXByteBuffer>& packets)
{
    int ret;
    //Save default values.
    m_InitializeMaxInfoTX = GetHdlcSettings().GetMaxInfoTX();
    m_InitializeMaxInfoRX = GetHdlcSettings().GetMaxInfoRX();
    m_InitializeWindowSizeTX = GetHdlcSettings().GetWindowSizeTX();
    m_InitializeWindowSizeRX = GetHdlcSettings().GetWindowSizeRX();
    m_Settings.SetConnected(DLMS_CONNECTION_STATE_NONE);
    packets.clear();
    m_IsAuthenticationRequired = false;
    // SNRM request is not used for all communication channels.
    if (m_Settings.GetInterfaceType() == DLMS_INTERFACE_TYPE_PLC_HDLC)
    {
        CGXByteBuffer tmp;
        ret = CGXDLMS::GetMacHdlcFrame(m_Settings, DLMS_COMMAND_SNRM, 0, NULL, tmp);
        if (ret == 0)
        {
            packets.push_back(tmp);
        }
        return ret;
    }
    if (m_Settings.GetInterfaceType() != DLMS_INTERFACE_TYPE_HDLC && m_Settings.GetInterfaceType() != DLMS_INTERFACE_TYPE_HDLC_WITH_MODE_E)
    {
        return 0;
    }
    CGXByteBuffer data(25);
    // If custom HDLC parameters are used.
    if (CGXHdlcSettings::DEFAULT_MAX_INFO_TX != GetLimits().GetMaxInfoTX() ||
        CGXHdlcSettings::DEFAULT_MAX_INFO_RX != GetLimits().GetMaxInfoRX() ||
        CGXHdlcSettings::DEFAULT_WINDOWS_SIZE_TX != GetLimits().GetWindowSizeTX() ||
        CGXHdlcSettings::DEFAULT_WINDOWS_SIZE_RX != GetLimits().GetWindowSizeRX())
    {
        // FromatID
        if ((ret = data.SetUInt8(0x81)) != 0 ||
        // GroupID
        (ret = data.SetUInt8(0x80)) != 0 ||
        // Length is updated later.
        (ret = data.SetUInt8(0)) != 0 ||
        (ret = data.SetUInt8(HDLC_INFO_MAX_INFO_TX)) != 0 ||
        (ret = CGXDLMS::AppendHdlcParameter(data, GetLimits().GetMaxInfoTX())) != 0 ||
        (ret = data.SetUInt8(HDLC_INFO_MAX_INFO_RX)) != 0 ||
        (ret = CGXDLMS::AppendHdlcParameter(data, GetLimits().GetMaxInfoRX())) != 0 ||
        (ret = data.SetUInt8(HDLC_INFO_WINDOW_SIZE_TX)) != 0 ||
        (ret = data.SetUInt8(4)) != 0 ||
        (ret = data.SetUInt32(GetLimits().GetWindowSizeTX())) != 0 ||
        (ret = data.SetUInt8(HDLC_INFO_WINDOW_SIZE_RX)) != 0 ||
        (ret = data.SetUInt8(4)) != 0 ||
        (ret = data.SetUInt32(GetLimits().GetWindowSizeRX())) != 0 ||
        // Length.
        (ret = data.SetUInt8(2, (unsigned char)(data.GetSize() - 3))) != 0)
        {
            return ret;
        }
    }
    m_Settings.ResetFrameSequence();
    CGXByteBuffer reply;
    ret = CGXDLMS::GetHdlcFrame(m_Settings, DLMS_COMMAND_SNRM, &data, reply);
    packets.push_back(reply);
    return ret;
}

int CGXDLMSClient::ParseSNObjectItem(
    CGXDLMSVariant& value,
    bool ignoreInactiveObjects)
{
    if (value.vt != DLMS_DATA_TYPE_STRUCTURE || value.Arr.size() != 4)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    if (value.Arr[0].vt != DLMS_DATA_TYPE_INT16 ||
        value.Arr[1].vt != DLMS_DATA_TYPE_UINT16 ||
        value.Arr[2].vt != DLMS_DATA_TYPE_UINT8 ||
        value.Arr[3].vt != DLMS_DATA_TYPE_OCTET_STRING)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    short sn = value.Arr[0].ToInteger() & 0xFFFF;
    unsigned short class_id = (unsigned short)value.Arr[1].ToInteger();
    unsigned char version = (unsigned char)value.Arr[2].ToInteger();
    CGXDLMSVariant ln = value.Arr[3];
    CGXDLMSObject* pObj = CGXDLMSObjectFactory::CreateObject((DLMS_OBJECT_TYPE)class_id);
    if (pObj != NULL)
    {
        pObj->SetShortName(sn);
        pObj->SetVersion(version);
        int cnt = ln.GetSize();
        assert(cnt == 6);
        CGXDLMSObject::SetLogicalName(pObj, ln);
        std::string ln2;
        pObj->GetLogicalName(ln2);
        if (ignoreInactiveObjects && ln2.compare("0.0.127.0.0.0") == 0)
        {
            delete pObj;
            return 0;
        }
        m_Settings.GetObjects().push_back(pObj);
    }
    return 0;
}

// SN referencing
int CGXDLMSClient::ParseSNObjects(
    CGXByteBuffer& buff,
    bool onlyKnownObjects,
    bool ignoreInactiveObjects)
{
    int ret;
    CGXDataInfo info;
    //Get array tag.
    unsigned char ch;
    unsigned long cnt;
    //Check that data is in the array
    // Get array tag.
    if ((ret = buff.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    if (ch != 1)
    {
        return DLMS_ERROR_CODE_INVALID_RESPONSE;
    }
    //get object count
    CGXDLMSVariant value;
    if ((ret = GXHelpers::GetObjectCount(buff, cnt)) != 0)
    {
        return ret;
    }
    for (unsigned long objPos = 0; objPos != cnt; ++objPos)
    {
        info.Clear();
        if ((ret = GXHelpers::GetData(&m_Settings, buff, info, value)) != 0 ||
            (ret = ParseSNObjectItem(value, ignoreInactiveObjects)) != 0)
        {
            return ret;
        }
    }
    return 0;
}

int CGXDLMSClient::ParseLNObjectItem(
    CGXDLMSVariant& value,
    bool ignoreInactiveObjects)
{
    int ret;
    if (value.Arr.size() != 4)
    {
        //Invalid structure format.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    int classID = value.Arr[0].ToInteger() & 0xFFFF;
    if (classID > 0)
    {
        CGXDLMSObject* pObj = CGXDLMSObjectFactory::CreateObject((DLMS_OBJECT_TYPE)classID);
        if (pObj != NULL)
        {
            if (value.vt != DLMS_DATA_TYPE_STRUCTURE || value.Arr.size() != 4 ||
                value.Arr[0].vt != DLMS_DATA_TYPE_UINT16 ||
                value.Arr[1].vt != DLMS_DATA_TYPE_UINT8 ||
                value.Arr[2].vt != DLMS_DATA_TYPE_OCTET_STRING)
            {
                delete pObj;
                return DLMS_ERROR_CODE_INVALID_PARAMETER;
            }
            unsigned char version = value.Arr[1].ToInteger();
            CGXDLMSVariant ln = value.Arr[2];
            if ((ret = CGXDLMSObject::SetLogicalName(pObj, ln)) != 0)
            {
                delete pObj;
                return ret;
            }
            std::string ln2;
            pObj->GetLogicalName(ln2);
            if (ignoreInactiveObjects && ln2.compare("0.0.127.0.0.0") == 0)
            {
                delete pObj;
                return 0;
            }
            //Get Access rights...
            if (value.Arr[3].vt != DLMS_DATA_TYPE_STRUCTURE || value.Arr[3].Arr.size() != 2)
            {
                delete pObj;
                return DLMS_ERROR_CODE_INVALID_PARAMETER;
            }
            pObj->SetVersion(version);
            int cnt;
            // attribute_access_descriptor Start
            if (value.Arr[3].Arr[0].vt != DLMS_DATA_TYPE_ARRAY)
            {
                delete pObj;
                return DLMS_ERROR_CODE_INVALID_PARAMETER;
            }
            if (value.Arr[3].Arr.size() == 2)
            {
                for (unsigned int pos = 0; pos != value.Arr[3].Arr[0].Arr.size(); ++pos)
                {
                    if (value.Arr[3].Arr[0].Arr[pos].vt != DLMS_DATA_TYPE_STRUCTURE ||
                        value.Arr[3].Arr[0].Arr[pos].Arr.size() != 3)
                    {
                        delete pObj;
                        return DLMS_ERROR_CODE_INVALID_PARAMETER;
                    }
                    int id = value.Arr[3].Arr[0].Arr[pos].Arr[0].ToInteger();
                    //Get access_mode
                    DLMS_DATA_TYPE tp = value.Arr[3].Arr[0].Arr[pos].Arr[1].vt;
                    if (tp != DLMS_DATA_TYPE_ENUM)
                    {
                        delete pObj;
                        return DLMS_ERROR_CODE_INVALID_PARAMETER;
                    }
                    pObj->SetAccess(id, (DLMS_ACCESS_MODE)value.Arr[3].Arr[0].Arr[pos].Arr[1].ToInteger());
                    //Get access_selectors
                    if (value.Arr[3].Arr[0].Arr[pos].Arr[2].vt == DLMS_DATA_TYPE_ARRAY)
                    {
                        int cnt2 = (unsigned long)value.Arr[3].Arr[0].Arr[pos].Arr[2].Arr.size();
                        for (int pos2 = 0; pos2 != cnt2; ++pos2)
                        {
                            //Get access_mode
                        }
                    }
                    else if (value.Arr[3].Arr[0].Arr[pos].Arr[2].vt != DLMS_DATA_TYPE_NONE)
                    {
                        delete pObj;
                        return DLMS_ERROR_CODE_INVALID_PARAMETER;
                    }
                }
                // attribute_access_descriptor End
                // method_access_item Start
                if (value.Arr[3].Arr[1].vt != DLMS_DATA_TYPE_ARRAY)
                {
                    delete pObj;
                    return DLMS_ERROR_CODE_INVALID_PARAMETER;
                }
                for (unsigned int pos = 0; pos != value.Arr[3].Arr[1].Arr.size(); ++pos)
                {
                    CGXDLMSVariant tmp = value.Arr[3].Arr[1].Arr[pos];
                    if (tmp.vt != DLMS_DATA_TYPE_STRUCTURE ||
                        tmp.Arr.size() != 2)
                    {
                        delete pObj;
                        return DLMS_ERROR_CODE_INVALID_PARAMETER;
                    }
                    int id = tmp.Arr[0].ToInteger();
                    //Get access_mode
                    //In version 0 data type is boolean.
                    if (tmp.Arr[1].vt != DLMS_DATA_TYPE_ENUM && tmp.Arr[1].vt != DLMS_DATA_TYPE_BOOLEAN)
                    {
                        delete pObj;
                        return DLMS_ERROR_CODE_INVALID_PARAMETER;
                    }
                    pObj->SetMethodAccess(id, (DLMS_METHOD_ACCESS_MODE)tmp.Arr[1].ToInteger());
                }
            }
            // method_access_item End
            cnt = ln.GetSize();
            assert(cnt == 6);
            m_Settings.GetObjects().push_back(pObj);
        }
    }
    return 0;
}

int CGXDLMSClient::ParseLNObjects(CGXByteBuffer& buff, bool onlyKnownObjects, bool ignoreInactiveObjects)
{
    int ret;
    unsigned long cnt;
    unsigned char ch;
    CGXDataInfo info;
    // Get array tag.
    if ((ret = buff.GetUInt8(&ch)) != 0)
    {
        return ret;
    }
    // Check that data is in the array
    if (ch != 0x01)
    {
        //Invalid response.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    CGXDLMSVariant value;
    if ((ret = GXHelpers::GetObjectCount(buff, cnt)) != 0)
    {
        return ret;
    }
    for (unsigned long pos = 0; pos != cnt; ++pos)
    {
        // Some meters give wrong item count.
        // This fix Iskraemeco (MT-880) bug.
        if (buff.GetPosition() == buff.GetSize())
        {
            break;
        }
        info.SetType(DLMS_DATA_TYPE_NONE);
        info.SetIndex(0);
        info.SetCount(0);
        if ((ret = GXHelpers::GetData(&m_Settings, buff, info, value)) != 0 ||
            (ret = ParseLNObjectItem(value, ignoreInactiveObjects)) != 0)
        {
            return ret;
        }
    }
    return 0;
}

int CGXDLMSClient::ParseObjects(CGXByteBuffer& data, bool onlyKnownObjects)
{
    return ParseObjects(data, onlyKnownObjects, true);
}

int CGXDLMSClient::ParseObjects(CGXByteBuffer& data, bool onlyKnownObjects, bool ignoreInactiveObjects)
{
    int ret;
    m_Settings.GetObjects().Free();
    if (GetUseLogicalNameReferencing())
    {
        if ((ret = ParseLNObjects(data, onlyKnownObjects, ignoreInactiveObjects)) != 0)
        {
            return ret;
        }
    }
    else
    {
        if ((ret = ParseSNObjects(data, onlyKnownObjects, ignoreInactiveObjects)) != 0)
        {
            return ret;
        }
    }
    return 0;
}

int CGXDLMSClient::ParseObjects(std::vector<CGXDLMSVariant>& objects, bool onlyKnownObjects)
{
    return ParseObjects(objects, onlyKnownObjects, true);
}

int CGXDLMSClient::ParseObjects(std::vector<CGXDLMSVariant>& objects, bool onlyKnownObjects, bool ignoreInactiveObjects)
{
    int ret;
    m_Settings.GetObjects().Free();
    if (GetUseLogicalNameReferencing())
    {
        for (std::vector< CGXDLMSVariant >::iterator it = objects.begin(); it != objects.end(); ++it)
        {
            if ((ret = ParseLNObjectItem(*it, ignoreInactiveObjects)) != 0)
            {
                return ret;
            }
        }
    }
    else
    {
        for (std::vector< CGXDLMSVariant >::iterator it = objects.begin(); it != objects.end(); ++it)
        {
            if ((ret = ParseSNObjectItem(*it, ignoreInactiveObjects)) != 0)
            {
                return ret;
            }
        }
    }
    return 0;
}

int CGXDLMSClient::UpdateValue(CGXDLMSObject& target, int attributeIndex, CGXDLMSVariant& value)
{
    int ret;
    if (value.vt == DLMS_DATA_TYPE_OCTET_STRING)
    {
        DLMS_DATA_TYPE type;
        if ((ret = target.GetDataType(attributeIndex, type)) == 0 && type == DLMS_DATA_TYPE_NONE)
        {
            if ((ret = target.SetDataType(attributeIndex, value.vt)) != 0)
            {
                return ret;
            }
        }
        if ((ret = target.GetUIDataType(attributeIndex, type)) != 0)
        {
            return ret;
        }
        if (type == DLMS_DATA_TYPE_DATETIME && value.GetSize() == 5)
        {
            type = DLMS_DATA_TYPE_DATE;
            target.SetUIDataType(attributeIndex, type);
        }
        if (type != DLMS_DATA_TYPE_NONE)
        {
            if ((ret = ChangeType(value, type, value)) != 0)
            {
                return ret;
            }
        }
    }
    CGXDLMSValueEventArg e(NULL, &target, attributeIndex);
    e.SetValue(value);
    return target.SetValue(m_Settings, e);
}

int CGXDLMSClient::GetValue(CGXByteBuffer& data, CGXDLMSVariant& value)
{
    CGXDataInfo info;
    return GXHelpers::GetData(&m_Settings, data, info, value);
}


int CGXDLMSClient::ChangeType(CGXDLMSVariant& value, DLMS_DATA_TYPE type, CGXDLMSVariant& newValue)
{
    if (value.vt == DLMS_DATA_TYPE_OCTET_STRING)
    {
        CGXByteBuffer tmp;
        tmp.Set(value.byteArr, value.GetSize());
        return ChangeType(tmp, type, newValue);
    }
    else
    {
        newValue = value;
    }
    return 0;
}

int CGXDLMSClient::ChangeType(CGXByteBuffer& value, DLMS_DATA_TYPE type, CGXDLMSVariant& newValue)
{
    return ChangeType(value, type, false, newValue);
}

int CGXDLMSClient::ChangeType(CGXByteBuffer& value, DLMS_DATA_TYPE type, bool useUtc, CGXDLMSVariant& newValue)
{
    int ret;
    CGXDataInfo info;
    newValue.Clear();
    if (value.GetSize() == 0)
    {
        return 0;
    }
    if (type == DLMS_DATA_TYPE_NONE)
    {
        newValue = value.ToHexString();
    }
    if (value.GetSize() == 0 && (type == DLMS_DATA_TYPE_STRING || type == DLMS_DATA_TYPE_OCTET_STRING))
    {
        newValue = "";
        return 0;
    }
    info.SetType(type);
    CGXDLMSSettings settings(false);
    settings.SetUseUtc2NormalTime(useUtc);
    if ((ret = GXHelpers::GetData(&settings, value, info, newValue)) != 0)
    {
        return ret;
    }
    if (!info.IsComplete())
    {
        return DLMS_ERROR_CODE_OUTOFMEMORY;
    }
    if (type == DLMS_DATA_TYPE_OCTET_STRING && newValue.vt == DLMS_DATA_TYPE_OCTET_STRING)
    {
        int size = newValue.size;
        std::string str;
        if (size == 0)
        {
            str = "";
        }
        else
        {
            CGXByteBuffer bcd(size * 4);
            for (int pos = 0; pos != size; ++pos)
            {
                bcd.AddIntAsString(newValue.byteArr[pos]);
                bcd.SetUInt8('.');
            }
            //Remove last dot.
            if (bcd.GetSize() != 0)
            {
                bcd.SetSize(bcd.GetSize() - 1);
            }
            str = bcd.ToString();
        }
        newValue = str;
    }
    return ret;
}

int CGXDLMSClient::ParseUAResponse(CGXByteBuffer& data)
{
    int ret = CGXDLMS::ParseSnrmUaResponse(data, &m_Settings.GetHdlcSettings());
    if (ret == 0)
    {
        m_Settings.SetConnected(DLMS_CONNECTION_STATE_HDLC);
    }
    return ret;
}

int CGXDLMSClient::AARQRequest(std::vector<CGXByteBuffer>& packets)
{
    //Save default values.
    m_InitializePduSize = GetMaxReceivePDUSize();
    CGXByteBuffer buff(20);
    m_Settings.ResetBlockIndex();
    m_Settings.SetNegotiatedConformance((DLMS_CONFORMANCE)0);
    packets.clear();
    int ret = CGXDLMS::CheckInit(m_Settings);
    if (ret != 0)
    {
        return ret;
    }
    m_Settings.GetStoCChallenge().Clear();
    if (GetAutoIncreaseInvokeID())
    {
        m_Settings.SetInvokeID(0);
    }
    else
    {
        m_Settings.SetInvokeID(1);
    }
    // If authentication or ciphering is used.
    if (m_Settings.GetAuthentication() > DLMS_AUTHENTICATION_LOW)
    {
        if (!m_Settings.GetUseCustomChallenge())
        {
            CGXByteBuffer challenge;
            if ((ret = CGXSecure::GenerateChallenge(m_Settings.GetAuthentication(), challenge)) != 0)
            {
                return ret;
            }
            m_Settings.SetCtoSChallenge(challenge);
        }
    }
    else
    {
        m_Settings.GetCtoSChallenge().Clear();
    }
    if ((ret = CGXAPDU::GenerateAarq(m_Settings, m_Settings.GetCipher(), NULL, buff)) != 0)
    {
        return ret;
    }
    if (GetUseLogicalNameReferencing())
    {
        CGXDLMSLNParameters p(&m_Settings, 0, DLMS_COMMAND_AARQ, 0, &buff, NULL, 0xff, DLMS_COMMAND_NONE);
        ret = CGXDLMS::GetLnMessages(p, packets);
    }
    else
    {
        CGXDLMSSNParameters p(&m_Settings, DLMS_COMMAND_AARQ, 0, 0, NULL, &buff);
        ret = CGXDLMS::GetSnMessages(p, packets);
    }
    return ret;
}

int CGXDLMSClient::ParseAAREResponse(CGXByteBuffer& reply)
{
    int ret;
    DLMS_SOURCE_DIAGNOSTIC sd;
    DLMS_ASSOCIATION_RESULT result;
#ifndef DLMS_IGNORE_XML_TRANSLATOR
    if ((ret = CGXAPDU::ParsePDU(m_Settings, m_Settings.GetCipher(),
        reply, result, sd, NULL)) != 0)
    {
        return ret;
    }
#else
    if ((ret = CGXAPDU::ParsePDU(m_Settings, m_Settings.GetCipher(),
        reply, result, sd)) != 0)
    {
        return ret;
    }
#endif //DLMS_IGNORE_XML_TRANSLATOR
    if (result != DLMS_ASSOCIATION_RESULT_ACCEPTED)
    {
        if (result == DLMS_ASSOCIATION_RESULT_TRANSIENT_REJECTED)
        {
            return DLMS_ERROR_CODE_REJECTED_TRANSIENT;
        }
        return DLMS_ERROR_CODE_REJECTED_PERMAMENT;
    }
    m_IsAuthenticationRequired = (DLMS_SOURCE_DIAGNOSTIC_AUTHENTICATION_REQUIRED == sd);
    if (m_Settings.GetDLMSVersion() != 6)
    {
        //Invalid DLMS version number.
        return DLMS_ERROR_CODE_INVALID_VERSION_NUMBER;
    }
    if (m_Settings.GetAuthentication() < DLMS_AUTHENTICATION_HIGH)
    {
        m_Settings.SetConnected((DLMS_CONNECTION_STATE)(m_Settings.GetConnected() | DLMS_CONNECTION_STATE_DLMS));
    }
    return 0;
}

bool CGXDLMSClient::IsAuthenticationRequired()
{
    return m_IsAuthenticationRequired;
}

int CGXDLMSClient::GetApplicationAssociationRequest(
    std::vector<CGXByteBuffer>& packets)
{
    int ret;
    CGXCipher* c = m_Settings.GetCipher();
    CGXDLMSVariant name;
    packets.clear();
    if (m_Settings.GetAuthentication() != DLMS_AUTHENTICATION_HIGH_ECDSA &&
        m_Settings.GetAuthentication() != DLMS_AUTHENTICATION_HIGH_GMAC &&
        m_Settings.GetPassword().GetSize() == 0)
    {
        //Password is invalid.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    m_Settings.ResetBlockIndex();
    CGXByteBuffer pw, challenge;

    //Count challenge for Landis+Gyr. L+G is using custom way to count the challenge.
    if (memcmp(m_ManufacturerId, "LGZ", 3) == 0 && m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH)
    {
        if ((ret = EncryptLandisGyrHighLevelAuthentication(m_Settings.GetPassword(), m_Settings.GetStoCChallenge(), challenge)) != 0)
        {
            return ret;
        }
        CGXDLMSVariant data = challenge;
        if (GetUseLogicalNameReferencing())
        {
            name = "0.0.40.0.0.255";
            return Method(name, DLMS_OBJECT_TYPE_ASSOCIATION_LOGICAL_NAME,
                1, data, packets);
        }
        name = 0xFA00;
        return Method(name, DLMS_OBJECT_TYPE_ASSOCIATION_SHORT_NAME, 8, data, packets);
    }

    if (m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH_GMAC)
    {
        pw = c->GetSystemTitle();
    }
    else if (m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH_SHA256)
    {
        pw.Set(m_Settings.GetPassword().GetData(),
            m_Settings.GetPassword().GetSize());
        pw.Set(c->GetSystemTitle().GetData(),
            c->GetSystemTitle().GetSize());
        pw.Set(m_Settings.GetSourceSystemTitle().GetData(),
            m_Settings.GetSourceSystemTitle().GetSize());
        pw.Set(m_Settings.GetStoCChallenge().GetData(),
            m_Settings.GetStoCChallenge().GetSize());
        pw.Set(m_Settings.GetCtoSChallenge().GetData(),
            m_Settings.GetCtoSChallenge().GetSize());
    }
    else if (m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH_ECDSA)
    {
        std::pair<CGXPublicKey, CGXPrivateKey>& kp =
            c->GetSigningKeyPair();
        if (kp.first.GetRawValue().GetSize() == 0 ||
            kp.second.GetRawValue().GetSize() == 0)
        {
#ifdef _DEBUG
            printf("Invalid signing key pair\n");
#endif //_DEBUG
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        pw.Set(c->GetSystemTitle().GetData(),
            c->GetSystemTitle().GetSize());
        pw.Set(m_Settings.GetSourceSystemTitle().GetData(),
            m_Settings.GetSourceSystemTitle().GetSize());
        pw.Set(m_Settings.GetStoCChallenge().GetData(),
            m_Settings.GetStoCChallenge().GetSize());
        pw.Set(m_Settings.GetCtoSChallenge().GetData(),
            m_Settings.GetCtoSChallenge().GetSize());
    }
    else
    {
        pw = m_Settings.GetPassword();
    }
    long ic = 0;
    if (m_Settings.GetCipher() != NULL)
    {
        ic = m_Settings.GetCipher()->GetFrameCounter();
    }
    if ((ret = CGXSecure::Secure(m_Settings, m_Settings.GetCipher(), ic,
        m_Settings.GetStoCChallenge(), pw, challenge)) != 0)
    {
        return ret;
    }
    CGXDLMSVariant data = challenge;
    if (GetUseLogicalNameReferencing())
    {
        name = "0.0.40.0.0.255";
        return Method(name, DLMS_OBJECT_TYPE_ASSOCIATION_LOGICAL_NAME,
            1, data, packets);
    }
    name = 0xFA00;
    return Method(name, DLMS_OBJECT_TYPE_ASSOCIATION_SHORT_NAME, 8, data,
        packets);
}

int CGXDLMSClient::ParseApplicationAssociationResponse(
    CGXByteBuffer& reply)
{
    //Landis+Gyr is not returning StoC.
    if (memcmp(m_ManufacturerId, "LGZ", 3) == 0 && m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH)
    {
        m_Settings.SetConnected((DLMS_CONNECTION_STATE)(m_Settings.GetConnected() | DLMS_CONNECTION_STATE_DLMS));
    }
    else
    {
        CGXDataInfo info;
        unsigned char ch;
        bool equals = false;
        CGXByteBuffer secret;
        int ret;
        unsigned long ic = 0;
        CGXDLMSVariant value;
        if ((ret = GXHelpers::GetData(&m_Settings, reply, info, value)) != 0)
        {
            return ret;
        }
        if (value.vt != DLMS_DATA_TYPE_NONE)
        {
            if (m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH_ECDSA)
            {
                CGXByteBuffer tmp2;
                tmp2.Set(m_Settings.GetSourceSystemTitle().GetData(),
                    m_Settings.GetSourceSystemTitle().GetSize());
                tmp2.Set(m_Settings.GetCipher()->GetSystemTitle().GetData(),
                    m_Settings.GetCipher()->GetSystemTitle().GetSize());
                tmp2.Set(m_Settings.GetCtoSChallenge().GetData(),
                    m_Settings.GetCtoSChallenge().GetSize());
                tmp2.Set(m_Settings.GetStoCChallenge().GetData(),
                    m_Settings.GetStoCChallenge().GetSize());
                CGXEcdsa sig(m_Settings.GetCipher()->GetSigningKeyPair().first);
                CGXByteBuffer bb;
                bb.Set(value.byteArr, value.GetSize());
                ret = sig.Verify(bb, tmp2, equals);
                m_Settings.SetConnected((DLMS_CONNECTION_STATE)(m_Settings.GetConnected() | DLMS_CONNECTION_STATE_DLMS));
            }
            else
            {
                if (m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH_GMAC)
                {
                    secret = m_Settings.GetSourceSystemTitle();
                    CGXByteBuffer bb;
                    bb.Set(value.byteArr, value.GetSize());
                    if ((ret = bb.GetUInt8(&ch)) != 0)
                    {
                        return ret;
                    }
                    if ((ret = bb.GetUInt32(&ic)) != 0)
                    {
                        return ret;
                    }
                }
                else if (m_Settings.GetAuthentication() == DLMS_AUTHENTICATION_HIGH_SHA256)
                {
                    secret.Set(&m_Settings.GetPassword());
                    secret.Set(&m_Settings.GetSourceSystemTitle());
                    secret.Set(&m_Settings.GetCipher()->GetSystemTitle());
                    secret.Set(&m_Settings.GetCtoSChallenge());
                    secret.Set(&m_Settings.GetStoCChallenge());
                }
                else
                {
                    secret = m_Settings.GetPassword();
                }
                CGXByteBuffer challenge, cToS = m_Settings.GetCtoSChallenge();
                if ((ret = CGXSecure::Secure(
                    m_Settings,
                    m_Settings.GetCipher(),
                    ic,
                    cToS,
                    secret,
                    challenge)) != 0)
                {
                    return ret;
                }
                equals = challenge.Compare(value.byteArr, value.GetSize());
                m_Settings.SetConnected((DLMS_CONNECTION_STATE)(m_Settings.GetConnected() | DLMS_CONNECTION_STATE_DLMS));
            }
        }
        else
        {
            // Server did not accept CtoS.
        }

        if (!equals)
        {
            m_Settings.SetConnected((DLMS_CONNECTION_STATE)(m_Settings.GetConnected() & ~DLMS_CONNECTION_STATE_DLMS));
            //ParseApplicationAssociationResponse failed. Server to Client do not match.
            return DLMS_ERROR_CODE_AUTHENTICATION_FAILURE;
        }
    }
    return 0;
}

int CGXDLMSClient::ReceiverReady(
    CGXReplyData& reply,
    CGXByteBuffer& packets)
{
    return CGXDLMS::ReceiverReady(m_Settings, reply, NULL, packets);
}

int CGXDLMSClient::ReceiverReady(DLMS_DATA_REQUEST_TYPES type, CGXByteBuffer& packets)
{
    return CGXDLMS::ReceiverReady(m_Settings, type, NULL, packets);
}

int CGXDLMSClient::ReleaseRequest(std::vector<CGXByteBuffer>& packets)
{
    int ret = 0;
    CGXByteBuffer buff;
    packets.clear();
    // If connection is not established, there is no need to send DisconnectRequest.
    if ((m_Settings.GetConnected() & DLMS_CONNECTION_STATE_DLMS) == 0)
    {
        return 0;
    }
    //Restore default valuess.
    SetMaxReceivePDUSize(m_InitializePduSize);
    if (!m_UseProtectedRelease)
    {
        if ((ret = buff.SetUInt8(3)) != 0 ||
            (ret = buff.SetUInt8(0x80)) != 0 ||
            (ret = buff.SetUInt8(1)) != 0 ||
            (ret = buff.SetUInt8(0)) != 0)
        {
            return ret;
        }
    }
    else
    {
        //Length.
        if ((ret = buff.SetUInt8(0)) != 0 ||
            (ret = buff.SetUInt8(0x80)) != 0 ||
            (ret = buff.SetUInt8(01)) != 0 ||
            (ret = buff.SetUInt8(00)) != 0)
        {
            return ret;
        }
        if ((ret = CGXAPDU::GenerateUserInformation(m_Settings, m_Settings.GetCipher(), NULL, buff)) != 0)
        {
            return ret;
        }
        //Increase IC.
        if (m_Settings.GetCipher() != NULL && m_Settings.GetCipher()->IsCiphered())
        {
            m_Settings.GetCipher()->SetInvocationCounter(1 + m_Settings.GetCipher()->GetInvocationCounter());
        }
        if ((ret = buff.SetUInt8(0, (unsigned char)(buff.GetSize() - 1))) != 0)
        {
            return ret;
        }
    }
    if (GetUseLogicalNameReferencing())
    {
        CGXDLMSLNParameters p(&m_Settings, 0, DLMS_COMMAND_RELEASE_REQUEST, 0, NULL, &buff, 0xff, DLMS_COMMAND_NONE);
        ret = CGXDLMS::GetLnMessages(p, packets);
    }
    else
    {
        CGXDLMSSNParameters p(&m_Settings, DLMS_COMMAND_RELEASE_REQUEST, 0xFF, 0xFF, NULL, &buff);
        ret = CGXDLMS::GetSnMessages(p, packets);
    }
    m_Settings.SetConnected((DLMS_CONNECTION_STATE)(m_Settings.GetConnected() & ~DLMS_CONNECTION_STATE_DLMS));
    return ret;
}

int CGXDLMSClient::DisconnectRequest(std::vector<CGXByteBuffer>& packets)
{
    int ret;
    CGXByteBuffer reply;
    packets.clear();
    if (CGXDLMS::UseHdlc(GetInterfaceType()) && (m_Settings.GetConnected() & DLMS_CONNECTION_STATE_HDLC) != 0)
    {
        if (GetInterfaceType() == DLMS_INTERFACE_TYPE_PLC_HDLC)
        {
            ret = CGXDLMS::GetMacHdlcFrame(m_Settings, DLMS_COMMAND_DISCONNECT_REQUEST, 0, NULL, reply);
        }
        else
        {
            ret = CGXDLMS::GetHdlcFrame(m_Settings, DLMS_COMMAND_DISCONNECT_REQUEST, NULL, reply);
        }
        packets.push_back(reply);
    }
    else
    {
        ret = ReleaseRequest(packets);
    }
    if (CGXDLMS::UseHdlc(m_Settings.GetInterfaceType()))
    {
        //Restore default HDLC values.
        GetHdlcSettings().SetMaxInfoTX(m_InitializeMaxInfoTX);
        GetHdlcSettings().SetMaxInfoRX(m_InitializeMaxInfoRX);
        GetHdlcSettings().SetWindowSizeTX(m_InitializeWindowSizeTX);
        GetHdlcSettings().SetWindowSizeRX(m_InitializeWindowSizeRX);
    }
    m_Settings.SetConnected(DLMS_CONNECTION_STATE_NONE);
    m_Settings.ResetFrameSequence();
    //Restore default valuess.
    SetMaxReceivePDUSize(m_InitializePduSize);
    return ret;
}

int CGXDLMSClient::GetData(CGXByteBuffer& reply, CGXReplyData& data)
{
    return CGXDLMS::GetData(m_Settings, reply, data, NULL);
}

int CGXDLMSClient::GetData(CGXByteBuffer& reply, CGXReplyData& data, CGXReplyData& notify)
{
    return CGXDLMS::GetData(m_Settings, reply, data, &notify);
}

int CGXDLMSClient::GetObjectsRequest(std::vector<CGXByteBuffer>& reply)
{
    CGXDLMSVariant name;
    if (GetUseLogicalNameReferencing())
    {
        name = "0.0.40.0.0.255";
        return Read(name, DLMS_OBJECT_TYPE_ASSOCIATION_LOGICAL_NAME, 2, reply);
    }
    name = (short)0xFA00;
    return Read(name, DLMS_OBJECT_TYPE_ASSOCIATION_SHORT_NAME, 2, reply);
}

int CGXDLMSClient::GetKeepAlive(std::vector<CGXByteBuffer>& reply)
{
    CGXDLMSVariant name;
    if (GetUseLogicalNameReferencing())
    {
        name = "0.0.40.0.0.255";
        return Read(name, DLMS_OBJECT_TYPE_ASSOCIATION_LOGICAL_NAME, 1, reply);
    }
    name = (short)0xFA00;
    return Read(name, DLMS_OBJECT_TYPE_ASSOCIATION_SHORT_NAME, 1, reply);
}

int CGXDLMSClient::Read(CGXDLMSObject* pObject, int attributeOrdinal, std::vector<CGXByteBuffer>& reply)
{
    CGXDLMSVariant name = pObject->GetName();
    return Read(name, pObject->GetObjectType(), attributeOrdinal, NULL, reply);
}

int CGXDLMSClient::Read(CGXDLMSVariant& name, DLMS_OBJECT_TYPE objectType, int attributeOrdinal, std::vector<CGXByteBuffer>& reply)
{
    return Read(name, objectType, attributeOrdinal, NULL, reply);
}

int CGXDLMSClient::Read(CGXDLMSVariant& name, 
    DLMS_OBJECT_TYPE objectType, 
    int attributeOrdinal, 
    CGXByteBuffer* parameters,
    std::vector<CGXByteBuffer>& reply)
{
    int ret;
    if ((attributeOrdinal < 1))
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    m_Settings.ResetBlockIndex();
    CGXByteBuffer attributeDescriptor;
    if (GetUseLogicalNameReferencing())
    {
        // CI
        attributeDescriptor.SetUInt16(objectType);
        // Add LN
        unsigned char ln[6];
        GXHelpers::SetLogicalName(name.strVal.c_str(), ln);
        attributeDescriptor.Set(ln, 6);
        // Attribute ID.
        attributeDescriptor.SetUInt8(attributeOrdinal);
        if (parameters == NULL || parameters->GetSize() == 0)
        {
            // Access selection is not used.
            attributeDescriptor.SetUInt8(0);
        }
        else
        {
            // Access selection is used.
            attributeDescriptor.SetUInt8(1);
            // Add data.
            attributeDescriptor.Set(parameters, 0, parameters->GetSize());
        }
        CGXDLMSLNParameters p(&m_Settings, 0,
            DLMS_COMMAND_GET_REQUEST, DLMS_GET_COMMAND_TYPE_NORMAL,
            &attributeDescriptor, parameters, 0xFF, DLMS_COMMAND_NONE);
        ret = CGXDLMS::GetLnMessages(p, reply);
    }
    else
    {
        DLMS_VARIABLE_ACCESS_SPECIFICATION requestType;
        int sn = name.ToInteger();
        sn += (attributeOrdinal - 1) * 8;
        attributeDescriptor.SetUInt16(sn);
        // Add Selector.
        if (parameters != NULL && parameters->GetSize() != 0)
        {
            requestType = DLMS_VARIABLE_ACCESS_SPECIFICATION_PARAMETERISED_ACCESS;
        }
        else
        {
            requestType = DLMS_VARIABLE_ACCESS_SPECIFICATION_VARIABLE_NAME;
        }
        CGXDLMSSNParameters p(&m_Settings, DLMS_COMMAND_READ_REQUEST, 1,
            requestType, &attributeDescriptor, parameters);
        ret = CGXDLMS::GetSnMessages(p, reply);
    }
    return ret;
}

int CGXDLMSClient::ReadList(
    std::vector<std::pair<CGXDLMSObject*, unsigned char> >& list,
    std::vector<CGXByteBuffer>& reply)
{
    if (list.size() == 0)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    if ((GetNegotiatedConformance() & DLMS_CONFORMANCE_MULTIPLE_REFERENCES) == 0) {
        //Meter doesn't support multiple objects reading with one request.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }

    int ret;
    m_Settings.ResetBlockIndex();
    CGXByteBuffer bb;
    if (GetUseLogicalNameReferencing())
    {
        CGXDLMSLNParameters p(&m_Settings, 0,
            DLMS_COMMAND_GET_REQUEST, DLMS_GET_COMMAND_TYPE_WITH_LIST,
            &bb, NULL, 0xff, DLMS_COMMAND_NONE);
        //Request service primitive shall always fit in a single APDU.
        unsigned short pos = 0, count = (m_Settings.GetMaxPduSize() - 12) / 10;
        if (list.size() < count)
        {
            count = (unsigned short)list.size();
        }
        //All meters can handle 10 items.
        if (count > 10)
        {
            count = 10;
        }
        // Add length.
        GXHelpers::SetObjectCount(count, bb);
        for (std::vector<std::pair<CGXDLMSObject*, unsigned char> >::iterator it = list.begin(); it != list.end(); ++it)
        {
            // CI.
            bb.SetUInt16(it->first->GetObjectType());
            bb.Set(it->first->m_LN, 6);
            // Attribute ID.
            bb.SetUInt8(it->second);
            // Attribute selector is not used.
            bb.SetUInt8(0);
            ++pos;
            if (pos % count == 0 && list.size() != pos)
            {
                if ((ret = CGXDLMS::GetLnMessages(p, reply)) != 0)
                {
                    return ret;
                }
                bb.Clear();
                if (list.size() - pos < count)
                {
                    GXHelpers::SetObjectCount((unsigned long)(list.size() - pos), bb);
                }
                else
                {
                    GXHelpers::SetObjectCount(count, bb);
                }
            }
        }
        if ((ret = CGXDLMS::GetLnMessages(p, reply)) != 0)
        {
            return ret;
        }
    }
    else
    {
        int sn;
        for (std::vector<std::pair<CGXDLMSObject*, unsigned char> >::iterator it = list.begin(); it != list.end(); ++it)
        {
            // Add variable type.
            bb.SetUInt8(DLMS_VARIABLE_ACCESS_SPECIFICATION_VARIABLE_NAME);
            sn = it->first->GetShortName();
            sn += (it->second - 1) * 8;
            bb.SetUInt16(sn);
        }
        CGXDLMSSNParameters p(&m_Settings, DLMS_COMMAND_READ_REQUEST,
            (unsigned long)list.size(), 0xFF, &bb, NULL);
        ret = CGXDLMS::GetSnMessages(p, reply);
    }
    return ret;
}

int CGXDLMSClient::WriteList(
    std::vector<std::pair<CGXDLMSObject*, unsigned char> >& list,
    std::vector<CGXByteBuffer>& reply)
{
    if ((GetNegotiatedConformance() & DLMS_CONFORMANCE_MULTIPLE_REFERENCES) == 0) {
        //Meter doesn't support multiple objects reading with one request.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }

    if (list.size() == 0)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }

    int ret = 0;
    m_Settings.ResetBlockIndex();
    CGXByteBuffer bb;
    if (GetUseLogicalNameReferencing())
    {
        CGXDLMSLNParameters p(&m_Settings, 0,
            DLMS_COMMAND_SET_REQUEST, DLMS_SET_COMMAND_TYPE_WITH_LIST,
            &bb, NULL, 0xff, DLMS_COMMAND_NONE);
        // Add length.
        GXHelpers::SetObjectCount((unsigned long)list.size(), bb);
        for (std::vector<std::pair<CGXDLMSObject*, unsigned char> >::iterator it = list.begin(); it != list.end(); ++it)
        {
            // CI.
            bb.SetUInt16(it->first->GetObjectType());
            bb.Set(it->first->m_LN, 6);
            // Attribute ID.
            bb.SetUInt8(it->second);
            // Attribute selector is not used.
            bb.SetUInt8(0);
        }
        // Add length.
        GXHelpers::SetObjectCount((unsigned long)list.size(), bb);
        for (std::vector<std::pair<CGXDLMSObject*, unsigned char> >::iterator it = list.begin(); it != list.end(); ++it)
        {
            CGXDLMSValueEventArg e(it->first, it->second);
            int ret = it->first->GetValue(m_Settings, e);
            if (ret != 0)
            {
                break;
            }
            CGXDLMSVariant value = e.GetValue();
            if (e.IsByteArray())
            {
                bb.Set(value.byteArr, value.GetSize());
            }
            else
            {
                DLMS_DATA_TYPE type = DLMS_DATA_TYPE_NONE;
                if ((ret = it->first->GetDataType(it->second, type)) != 0)
                {
                    break;
                }
                if ((ret = GXHelpers::SetData(&m_Settings, bb, type, value)) != 0)
                {
                    break;
                }
            }
        }
        if (ret == 0)
        {
            if ((ret = CGXDLMS::GetLnMessages(p, reply)) != 0)
            {
                return ret;
            }
        }
    }
    else
    {
        int sn;
        for (std::vector<std::pair<CGXDLMSObject*, unsigned char> >::iterator it = list.begin(); it != list.end(); ++it)
        {
            // Add variable type.
            bb.SetUInt8(DLMS_VARIABLE_ACCESS_SPECIFICATION_VARIABLE_NAME);
            sn = it->first->GetShortName();
            sn += (it->second - 1) * 8;
            bb.SetUInt16(sn);
        }
        // Add length.
        GXHelpers::SetObjectCount((unsigned long)list.size(), bb);
        for (std::vector<std::pair<CGXDLMSObject*, unsigned char> >::iterator it = list.begin(); it != list.end(); ++it)
        {
            CGXDLMSValueEventArg e(it->first, it->second);
            int ret = it->first->GetValue(m_Settings, e);
            if (ret != 0)
            {
                break;
            }
            CGXDLMSVariant value = e.GetValue();
            if (e.IsByteArray())
            {
                bb.Set(value.byteArr, value.GetSize());
            }
            else
            {
                DLMS_DATA_TYPE type = DLMS_DATA_TYPE_NONE;
                if ((ret = it->first->GetDataType(it->second, type)) != 0)
                {
                    break;
                }
                if ((ret = GXHelpers::SetData(&m_Settings, bb, type, value)) != 0)
                {
                    break;
                }
            }
        }
        if (ret == 0)
        {
            CGXDLMSSNParameters p(&m_Settings, DLMS_COMMAND_WRITE_REQUEST,
                (unsigned long)list.size(), 0xFF, &bb, NULL);
            ret = CGXDLMS::GetSnMessages(p, reply);
        }
    }
    return ret;
}

/**
     * Update list of values.
     *
     * @param list
     *            read objects.
     * @param values
     *            Received values.
     */
int CGXDLMSClient::UpdateValues(
    std::vector<std::pair<CGXDLMSObject*, unsigned char> >& list,
    std::vector<CGXDLMSVariant>& values)
{
    int ret, pos = 0;
    for (std::vector<std::pair<CGXDLMSObject*, unsigned char> >::iterator it = list.begin(); it != list.end(); ++it)
    {
        CGXDLMSValueEventArg e(NULL, it->first, it->second);
        e.SetValue(values.at(pos));
        if ((ret = it->first->SetValue(m_Settings, e)) != 0)
        {
            return ret;
        }
        ++pos;
    }
    return 0;
}

int CGXDLMSClient::Write(
    CGXDLMSObject* pObject,
    int index,
    std::vector<CGXByteBuffer>& reply)
{
    if (index < 1)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    CGXDLMSValueEventArg e(pObject, index);
    int ret = pObject->GetValue(m_Settings, e);
    if (ret == 0)
    {
        CGXDLMSVariant name = pObject->GetName();
        CGXDLMSVariant value = e.GetValue();
        int ret;
        m_Settings.ResetBlockIndex();
        CGXByteBuffer bb, data;
        if (e.IsByteArray())
        {
            data.Set(value.byteArr, value.GetSize());
        }
        else
        {
            DLMS_DATA_TYPE type = DLMS_DATA_TYPE_NONE;
            if ((ret = pObject->GetDataType(index, type)) != 0)
            {
                return ret;
            }
            if (type == DLMS_DATA_TYPE_NONE)
            {
                type = value.vt;
            }
            if ((ret = GXHelpers::SetData(&m_Settings, data, type, value)) != 0)
            {
                return ret;
            }
        }
        if (GetUseLogicalNameReferencing())
        {
            // Add CI.
            bb.SetUInt16(pObject->GetObjectType());
            // Add LN.
            unsigned char ln[6];
            GXHelpers::SetLogicalName(name.strVal.c_str(), ln);
            bb.Set(ln, 6);
            // Attribute ID.
            bb.SetUInt8(index);
            // Access selection is not used.
            bb.SetUInt8(0);
            CGXDLMSLNParameters p(&m_Settings, 0,
                DLMS_COMMAND_SET_REQUEST, DLMS_SET_COMMAND_TYPE_NORMAL,
                &bb, &data, 0xff, DLMS_COMMAND_NONE);
            ret = CGXDLMS::GetLnMessages(p, reply);
        }
        else
        {
            // Add name.
            int sn = name.ToInteger();
            sn += (index - 1) * 8;
            bb.SetUInt16(sn);
            // Add data count.
            bb.SetUInt8(1);
            CGXDLMSSNParameters p(&m_Settings,
                DLMS_COMMAND_WRITE_REQUEST, 1,
                DLMS_VARIABLE_ACCESS_SPECIFICATION_VARIABLE_NAME,
                &bb, &data);
            ret = CGXDLMS::GetSnMessages(p, reply);
        }
        return ret;
    }
    return ret;
}

int CGXDLMSClient::Write(CGXDLMSObject* pObject,
    int index,
    CGXDLMSVariant& data,
    std::vector<CGXByteBuffer>& reply)
{
    CGXDLMSVariant name = pObject->GetName();
    return Write(name, pObject->GetObjectType(), index, data, reply);
}

int CGXDLMSClient::Write(CGXDLMSVariant& name,
    DLMS_OBJECT_TYPE objectType,
    int index,
    CGXDLMSVariant& value,
    std::vector<CGXByteBuffer>& reply)
{
    return Write(name, objectType, index, value, NULL, reply);
}

int CGXDLMSClient::Write(CGXDLMSVariant& name,
    DLMS_OBJECT_TYPE objectType,
    int index,
    CGXDLMSVariant& value,
    CGXByteBuffer* parameters,
    std::vector<CGXByteBuffer>& reply)
{
    int ret;
    CGXByteBuffer data;
    if ((ret = GXHelpers::SetData(&m_Settings, data, value.vt, value)) != 0)
    {
        return ret;
    }
    return Write(name, objectType, index, data, parameters, reply);
}

int CGXDLMSClient::Write(CGXDLMSVariant& name,
    DLMS_OBJECT_TYPE objectType,
    int index,
    CGXDLMSVariant& value,
    CGXDLMSVariant& parameters,
    std::vector<CGXByteBuffer>& reply)
{
    int ret;
    CGXByteBuffer data, param;
    if ((ret = GXHelpers::SetData(&m_Settings, data, value.vt, value)) != 0)
    {
        return ret;
    }
    if ((ret = GXHelpers::SetData(&m_Settings, param, parameters.vt, parameters)) != 0)
    {
        return ret;
    }
    return Write(name, objectType, index, data, &param, reply);
}

int CGXDLMSClient::Write(CGXDLMSVariant& name, 
    DLMS_OBJECT_TYPE objectType,
    int index, 
    CGXByteBuffer& value,
    CGXByteBuffer* parameters,
    std::vector<CGXByteBuffer>& reply)
{
    int ret;
    CGXByteBuffer bb;
    if (index < 1)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    m_Settings.ResetBlockIndex();
    if (GetUseLogicalNameReferencing())
    {
        // Add CI.
        bb.SetUInt16(objectType);
        // Add LN.
        unsigned char ln[6];
        GXHelpers::SetLogicalName(name.strVal.c_str(), ln);
        bb.Set(ln, 6);
        // Attribute ID.
        bb.SetUInt8(index);
        if (parameters == NULL || parameters->GetSize() == 0)
        {
            // Access selection is not used.
            bb.SetUInt8(0);
        }
        else
        {
            // Access selection is used.
            bb.SetUInt8(1);
            // Add data.
            bb.Set(parameters->GetData(), parameters->GetSize());
        }
        CGXDLMSLNParameters p(&m_Settings, 0,
            DLMS_COMMAND_SET_REQUEST, DLMS_SET_COMMAND_TYPE_NORMAL,
            &bb, &value, 0xff, DLMS_COMMAND_NONE);
        ret = CGXDLMS::GetLnMessages(p, reply);
    }
    else
    {
        // Add name.
        int sn = name.ToInteger();
        sn += (index - 1) * 8;
        bb.SetUInt16(sn);
        // Add data count.
        bb.SetUInt8(1);
        CGXDLMSSNParameters p(&m_Settings,
            DLMS_COMMAND_WRITE_REQUEST, 1,
            DLMS_VARIABLE_ACCESS_SPECIFICATION_VARIABLE_NAME,
            &bb, &value);
        ret = CGXDLMS::GetSnMessages(p, reply);
    }
    return ret;
}

int CGXDLMSClient::Write(CGXDLMSVariant& name, DLMS_OBJECT_TYPE objectType,
    int index, CGXByteBuffer& value, std::vector<CGXByteBuffer>& reply)
{
    if (index < 1)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    int ret;
    m_Settings.ResetBlockIndex();
    CGXByteBuffer bb;
    if (GetUseLogicalNameReferencing())
    {
        // Add CI.
        bb.SetUInt16(objectType);
        // Add LN.
        unsigned char ln[6];
        GXHelpers::SetLogicalName(name.strVal.c_str(), ln);
        bb.Set(ln, 6);
        // Attribute ID.
        bb.SetUInt8(index);
        // Access selection is not used.
        bb.SetUInt8(0);
        CGXDLMSLNParameters p(&m_Settings, 0,
            DLMS_COMMAND_SET_REQUEST, DLMS_SET_COMMAND_TYPE_NORMAL,
            &bb, &value, 0xff, DLMS_COMMAND_NONE);
        ret = CGXDLMS::GetLnMessages(p, reply);
    }
    else
    {
        // Add name.
        int sn = name.ToInteger();
        sn += (index - 1) * 8;
        bb.SetUInt16(sn);
        // Add data count.
        bb.SetUInt8(1);
        CGXDLMSSNParameters p(&m_Settings,
            DLMS_COMMAND_WRITE_REQUEST, 1,
            DLMS_VARIABLE_ACCESS_SPECIFICATION_VARIABLE_NAME,
            &bb, &value);
        ret = CGXDLMS::GetSnMessages(p, reply);
    }
    return ret;
}

/**
    * Generate Method (Action) request.
    *
    * @param item
    *            Method object short name or Logical Name.
    * @param index
    *            Method index.
    * @param data
    *            Method data.
    * @param type
    *            Data type.
    * @return DLMS action message.
    */
int CGXDLMSClient::Method(CGXDLMSObject* item, int index,
    CGXDLMSVariant& data, std::vector<CGXByteBuffer>& reply)
{
    return Method(item, index, data, data.vt, reply);
}

/**
    * Generate Method (Action) request.
    *
    * @param item
    *            Method object short name or Logical Name.
    * @param index
    *            Method index.
    * @param data
    *            Method data.
    * @param type
    *            Data type.
    * @return DLMS action message.
    */
int CGXDLMSClient::Method(CGXDLMSObject* item, int index,
    CGXDLMSVariant& data, DLMS_DATA_TYPE dataType, std::vector<CGXByteBuffer>& reply)
{
    CGXDLMSVariant name = item->GetName();
    return Method(name, item->GetObjectType(), index, data, dataType, reply);
}

int CGXDLMSClient::Method(
    CGXDLMSVariant name,
    DLMS_OBJECT_TYPE objectType,
    int index,
    CGXDLMSVariant& value,
    std::vector<CGXByteBuffer>& reply)
{
    return Method(name, objectType,
        index, value, value.vt, reply);
}

int CGXDLMSClient::Method(
    CGXDLMSVariant name,
    DLMS_OBJECT_TYPE objectType,
    int index,
    CGXDLMSVariant& value,
    DLMS_DATA_TYPE dataType,
    std::vector<CGXByteBuffer>& reply)
{
    int ret;
    if (index < 1)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }

    CGXByteBuffer bb, data;
    m_Settings.ResetBlockIndex();
    if ((ret = GXHelpers::SetData(&m_Settings, data, dataType, value)) != 0)
    {
        return ret;
    }
    if (GetUseLogicalNameReferencing())
    {
        // CI
        bb.SetUInt16(objectType);
        // Add LN.
        unsigned char ln[6];
        GXHelpers::SetLogicalName(name.strVal.c_str(), ln);
        bb.Set(ln, 6);
        // Attribute ID.
        bb.SetUInt8(index);
        // Method Invocation Parameters is not used.
        if (value.vt == DLMS_DATA_TYPE_NONE)
        {
            bb.SetUInt8(0);
        }
        else
        {
            bb.SetUInt8(1);
        }
        CGXDLMSLNParameters p(&m_Settings, 0,
            DLMS_COMMAND_METHOD_REQUEST, DLMS_ACTION_COMMAND_TYPE_NORMAL,
            &bb, &data, 0xff, DLMS_COMMAND_NONE);
        ret = CGXDLMS::GetLnMessages(p, reply);
    }
    else
    {
        int requestType;
        if (value.vt == DLMS_DATA_TYPE_NONE)
        {
            requestType = DLMS_VARIABLE_ACCESS_SPECIFICATION_VARIABLE_NAME;
        }
        else
        {
            requestType = DLMS_VARIABLE_ACCESS_SPECIFICATION_PARAMETERISED_ACCESS;
        }
        unsigned char ind, count;
        if ((ret = CGXDLMS::GetActionInfo(objectType, ind, count)) != 0)
        {
            return ret;
        }

        if (index > count)
        {
            //Invalid parameter
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        int sn = name.ToInteger();
        index = (ind + (index - 1) * 0x8);
        sn += index;
        // Add SN count.
        bb.SetUInt8(1);
        // Add name length.
        bb.SetUInt8(4);
        // Add name.
        bb.SetUInt16(sn);
        // Method Invocation Parameters is not used.
        if (value.vt == DLMS_DATA_TYPE_NONE)
        {
            bb.SetUInt8(0);
        }
        else
        {
            bb.SetUInt8(1);
        }
        CGXDLMSSNParameters p(&m_Settings, DLMS_COMMAND_READ_REQUEST, 1,
            requestType, &bb, &data);
        ret = CGXDLMS::GetSnMessages(p, reply);
    }

    return ret;
}


int CGXDLMSClient::Method(
    CGXDLMSVariant name,
    DLMS_OBJECT_TYPE objectType,
    int index,
    CGXByteBuffer& value,
    std::vector<CGXByteBuffer>& reply)
{
    int ret;
    if (index < 1)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }

    CGXByteBuffer bb;
    m_Settings.ResetBlockIndex();
    if (GetUseLogicalNameReferencing())
    {
        // CI
        bb.SetUInt16(objectType);
        // Add LN.
        unsigned char ln[6];
        GXHelpers::SetLogicalName(name.strVal.c_str(), ln);
        bb.Set(ln, 6);
        // Attribute ID.
        bb.SetUInt8(index);
        bb.SetUInt8(1);
        CGXDLMSLNParameters p(&m_Settings, 0,
            DLMS_COMMAND_METHOD_REQUEST, DLMS_ACTION_COMMAND_TYPE_NORMAL,
            &bb, &value, 0xff, DLMS_COMMAND_NONE);
        ret = CGXDLMS::GetLnMessages(p, reply);
    }
    else
    {
        int requestType;
        requestType = DLMS_VARIABLE_ACCESS_SPECIFICATION_PARAMETERISED_ACCESS;
        unsigned char ind, count;
        if ((ret = CGXDLMS::GetActionInfo(objectType, ind, count)) != 0)
        {
            return ret;
        }

        if (index > count)
        {
            //Invalid parameter
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        int sn = name.ToInteger();
        index = (ind + (index - 1) * 0x8);
        sn += index;
        // Add SN count.
        bb.SetUInt8(1);
        // Add name length.
        bb.SetUInt8(4);
        // Add name.
        bb.SetUInt16(sn);
        // Method Invocation Parameters is not used.
        bb.SetUInt8(1);
        CGXDLMSSNParameters p(&m_Settings, DLMS_COMMAND_READ_REQUEST, 1,
            requestType, &bb, &value);
        ret = CGXDLMS::GetSnMessages(p, reply);
    }
    return ret;
}

int CGXDLMSClient::ReadRowsByEntry(
    CGXDLMSProfileGeneric* pg,
    int index,
    int count,
    std::vector<CGXByteBuffer>& reply)
{
    std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject*> > cols;
    return ReadRowsByEntry(pg, index, count, cols, reply);
}

int CGXDLMSClient::ReadRowsByEntry(
    CGXDLMSProfileGeneric* pg,
    int index,
    int count,
    std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject*> >& columns,
    std::vector<CGXByteBuffer>& reply)
{
    CGXByteBuffer buff(19);
    if (pg == NULL)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    pg->Reset();
    // Add AccessSelector value
    buff.SetUInt8(0x02);
    // Add enum tag.
    buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE);
    // Add item count
    buff.SetUInt8(0x04);
    // Add start index
    CGXDLMSVariant tmp = index;
    GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT32, tmp);
    // Add Count
    if (count == 0)
    {
        tmp = count;
    }
    else
    {
        tmp = index + count - 1;
    }
    GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT32, tmp);
    tmp = 1;
    // Read all columns.
    GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT16, tmp);
    tmp = 0;
    GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT16, tmp);
    CGXDLMSVariant name = pg->GetName();
    return Read(name, DLMS_OBJECT_TYPE_PROFILE_GENERIC, 2, &buff, reply);
}

int CGXDLMSClient::ReadRowsByRange(
    CGXDLMSProfileGeneric* pg,
    CGXDateTime& start,
    CGXDateTime& end,
    std::vector<CGXByteBuffer>& reply)
{
    if (pg == NULL)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    int ret;
    bool unixTime = false;
    unsigned char LN[] = { 0, 0, 1, 0, 0, 255 };
    DLMS_OBJECT_TYPE type = DLMS_OBJECT_TYPE_CLOCK;
    unsigned char* pLn = LN;
    CGXByteBuffer buff(51);
    CGXDLMSVariant name = pg->GetName();
    if (pg->GetCaptureObjects().size() != 0)
    {
        std::pair<CGXDLMSObject*, CGXDLMSCaptureObject*> kv = pg->GetCaptureObjects()[0];
        type = kv.first->GetObjectType();
        pLn = kv.first->m_LN;
        unsigned char UNIX_LN[] = { 0, 0, 1, 1, 0, 255 };
        unixTime = type == DLMS_OBJECT_TYPE_DATA && memcmp(pLn, UNIX_LN, 6) == 0;
    }
    pg->Reset();
    m_Settings.ResetBlockIndex();
    // Add AccessSelector value.
    buff.SetUInt8(0x01);
    // Add enum tag.
    buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE);
    // Add item count
    buff.SetUInt8(0x04);
    // Add enum tag.
    buff.SetUInt8(0x02);
    // Add item count
    buff.SetUInt8(0x04);
    // CI
    CGXDLMSVariant tmp = DLMS_OBJECT_TYPE_CLOCK;
    GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT16, tmp);
    // LN
    CGXDLMSVariant ln(pLn, 6, DLMS_DATA_TYPE_OCTET_STRING);
    GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_OCTET_STRING, ln);
    // Add attribute index.
    tmp = 2;
    GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_INT8, tmp);
    // Add version
    tmp = 0;
    if ((ret = GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT16, tmp)) != 0)
    {
        return ret;
    }
    // Add start time
    if (unixTime)
    {
        tmp = start.ToUnixTime();
        if ((ret = GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT32, tmp)) != 0)
        {
            return ret;
        }
    }
    else
    {
        tmp = start;
        if ((ret = GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
        {
            return ret;
        }
    }
    // Add end time
    if (unixTime)
    {
        tmp = end.ToUnixTime();
        if ((ret = GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_UINT32, tmp)) != 0)
        {
            return ret;
        }
    }
    else
    {
        tmp = end;
        if ((ret = GXHelpers::SetData(&m_Settings, buff, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
        {
            return ret;
        }
    }
    // Add array of read columns. Read All...
    buff.SetUInt8(0x01);
    // Add item count
    buff.SetUInt8(0x00);
    return Read(name, DLMS_OBJECT_TYPE_PROFILE_GENERIC, 2, &buff, reply);
}


int CGXDLMSClient::ReadRowsByRange(
    CGXDLMSProfileGeneric* pg,
    struct tm* start,
    struct tm* end,
    std::vector<CGXByteBuffer>& reply)
{
    if (pg == NULL || start == NULL || end == NULL)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    CGXDateTime s(start), e(end);
    s.SetSkip(DATETIME_SKIPS_MS);
    e.SetSkip(DATETIME_SKIPS_MS);
    return ReadRowsByRange(pg, s, e, reply);
}

int CGXDLMSClient::ReadRowsByRange(
    CGXDLMSProfileGeneric* pg,
    struct tm* start,
    struct tm* end,
    std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject*> >& columns,
    std::vector<CGXByteBuffer>& reply)
{
    return ReadRowsByRange(pg, start, end, reply);
}

int CGXDLMSClient::GetServerAddressFromSerialNumber(
    unsigned long serialNumber,
    unsigned short logicalAddress,
    const char* formula)
{
    int value;
    // If formula is not given use default formula.
    // This formula is defined in DLMS specification.
    if (formula == NULL || strlen(formula) == 0)
    {
        value = CGXSerialNumberCounter::Count(serialNumber, "SN % 10000 + 1000");
    }
    else
    {
        value = CGXSerialNumberCounter::Count(serialNumber, formula);
    }
    if (logicalAddress != 0)
    {
        value |= logicalAddress << 14;
    }
    return value;
}

int  CGXDLMSClient::GetServerAddress(unsigned long logicalAddress,
    unsigned long physicalAddress, unsigned char addressSize)
{
    if (addressSize < 4 && physicalAddress < 0x80
        && logicalAddress < 0x80)
    {
        return logicalAddress << 7 | physicalAddress;
    }
    if (physicalAddress < 0x4000 && logicalAddress < 0x4000)
    {
        return logicalAddress << 14 | physicalAddress;
    }
    return DLMS_ERROR_CODE_INVALID_PARAMETER;
}

char* CGXDLMSClient::GetProtocolVersion()
{
    return m_Settings.GetProtocolVersion();
}

void CGXDLMSClient::SetProtocolVersion(char* value)
{
    m_Settings.SetProtocolVersion(value);
}

int CGXDLMSClient::ParsePushObjects(std::vector<CGXDLMSVariant>& data, std::vector<std::pair<CGXDLMSObject*, unsigned char> >& items)
{
    CGXDLMSObject* obj;
    int ret;
    CGXDLMSVariant tmp, value;
    CGXDLMSVariant ln;
    for (std::vector<CGXDLMSVariant>::iterator it = data.begin(); it != data.end(); ++it)
    {
        int classID = it->Arr[0].ToInteger() & 0xFFFF;
        if (classID > 0)
        {
            ln.Clear();
            if ((ret = CGXDLMSClient::ChangeType(it->Arr[1], DLMS_DATA_TYPE_OCTET_STRING, ln)) != 0)
            {
                return ret;
            }
            obj = GetObjects().FindByLN((DLMS_OBJECT_TYPE)classID, ln.strVal);
            if (obj == NULL)
            {
                obj = CGXDLMSObjectFactory::CreateObject((DLMS_OBJECT_TYPE)classID, ln.strVal);
                GetObjects().push_back(obj);
            }
            items.push_back(std::pair<CGXDLMSObject*, unsigned char>(obj, it->Arr[2].ToInteger()));
        }
    }
    return 0;
}

void CGXDLMSClient::SetCtoSChallenge(CGXByteBuffer& value)
{
    m_Settings.SetUseCustomChallenge(value.GetSize() != 0);
    m_Settings.SetCtoSChallenge(value);
}

CGXByteBuffer& CGXDLMSClient::GetCtoSChallenge()
{
    return m_Settings.GetCtoSChallenge();
}

int CGXDLMSClient::AccessRequest(struct tm* time, std::vector<CGXDLMSAccessItem>& list, std::vector<CGXByteBuffer>& packets)
{
    int ret;
    if (list.size() == 0)
    {
        //Invalid parameter
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    if ((GetNegotiatedConformance() & DLMS_CONFORMANCE_ACCESS) == 0) {
        //Meter doesn't support access.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    unsigned char ln[6];
    std::string tmp;
    CGXByteBuffer bb;
    if ((ret = GXHelpers::SetObjectCount((unsigned long)list.size(), bb)) == 0)
    {
        for (std::vector< CGXDLMSAccessItem >::iterator it = list.begin(); it != list.end(); ++it)
        {
            if ((ret = bb.SetUInt8(it->GetCommand())) != 0 ||
                //Object type.
                (ret = bb.SetUInt16(it->GetTarget()->GetObjectType())) != 0)
            {
                break;
            }
            //LN
            GXHelpers::GetLogicalName(ln, tmp);
            bb.Set(it->GetTarget()->m_LN, 6);
            // Attribute ID.
            bb.SetUInt8(it->GetIndex());
        }
        //Data
        DLMS_DATA_TYPE type;
        GXHelpers::SetObjectCount((unsigned long)list.size(), bb);
        for (std::vector< CGXDLMSAccessItem >::iterator it = list.begin(); it != list.end(); ++it)
        {
            if (it->GetCommand() == DLMS_ACCESS_SERVICE_COMMAND_TYPE_GET)
            {
                bb.SetUInt8(0);
            }
            else if (it->GetCommand() == DLMS_ACCESS_SERVICE_COMMAND_TYPE_SET ||
                it->GetCommand() == DLMS_ACCESS_SERVICE_COMMAND_TYPE_ACTION)
            {
                CGXDLMSValueEventArg e(it->GetTarget(), it->GetIndex());
                if ((ret = it->GetTarget()->GetValue(m_Settings, e)) != 0)
                {
                    break;
                }
                CGXDLMSVariant& value = e.GetValue();
                it->GetTarget()->GetDataType(it->GetIndex(), type);
                if (type == DLMS_DATA_TYPE_NONE)
                {
                    type = value.vt;
                }
                if ((ret = GXHelpers::SetData(&m_Settings, bb, type, value)) != 0)
                {
                    break;
                }
            }
            else
            {
                ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                break;
            }
        }
        if (ret == 0)
        {
            CGXDLMSLNParameters p(&m_Settings, 0, DLMS_COMMAND_ACCESS_REQUEST, 0xFF, NULL, &bb, 0XFF, DLMS_COMMAND_NONE);
            p.SetTime(time);
            ret = CGXDLMS::GetLnMessages(p, packets);
        }
    }
    return ret;
}

/// <summary>
/// Parse access response.
/// </summary>
/// <param name="list">Collection of access items.</param>
/// <param name="data">Received data from the meter.</param>
/// <returns>Collection of received data and status codes.</returns>
/// <seealso cref="AccessRequest"/>
int CGXDLMSClient::ParseAccessResponse(std::vector<CGXDLMSAccessItem>& list, CGXByteBuffer& data)
{
    unsigned char ch;
    unsigned long count;
    int ret;
    //Get count
    CGXDataInfo info;
    CGXDLMSVariant value;
    if ((ret = GXHelpers::GetObjectCount(data, count)) != 0)
    {
        return ret;
    }
    if (list.size() != count)
    {
        //List size and values size do not match.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    for (std::vector< CGXDLMSAccessItem >::iterator it = list.begin(); it != list.end(); ++it)
    {
        info.Clear();
        if ((ret = GXHelpers::GetData(&m_Settings, data, info, value)) != 0)
        {
            return ret;
        }
        it->SetValue(value);
    }
    //Get status codes.
    if ((ret = GXHelpers::GetObjectCount(data, count)) != 0)
    {
        return ret;
    }
    if (list.size() != count)
    {
        //List size and values size do not match.
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    for (std::vector< CGXDLMSAccessItem >::iterator it = list.begin(); it != list.end(); ++it)
    {
        //Get access type.
        if ((ret = data.GetUInt8(&ch)) != 0)
        {
            break;
        }
        //Get status.
        if ((ret = data.GetUInt8(&ch)) != 0)
        {
            break;
        }
        it->SetError((DLMS_ERROR_CODE)ch);
        if (it->GetCommand() == DLMS_ACCESS_SERVICE_COMMAND_TYPE_GET && it->GetError() == DLMS_ERROR_CODE_OK)
        {
            if ((ret = UpdateValue(*it->GetTarget(), it->GetIndex(), it->GetValue())) != 0)
            {
                break;
            }
        }
    }
    return ret;
}

char* CGXDLMSClient::GetManufacturerId()
{
    if (m_ManufacturerId[0] == 0)
    {
        return NULL;
    }
    return m_ManufacturerId;
}

void CGXDLMSClient::SetManufacturerId(char value[3])
{
    if (value == NULL)
    {
        memset(m_ManufacturerId, 0, sizeof(m_ManufacturerId));
    }
    else
    {
        memcpy(m_ManufacturerId, value, sizeof(m_ManufacturerId));
    }
}

int CGXDLMSClient::EncryptLandisGyrHighLevelAuthentication(CGXByteBuffer& password, CGXByteBuffer& seed, CGXByteBuffer& crypted)
{
    int pos, ret;
    if ((ret = crypted.Set(seed.GetData(), seed.GetSize())) != 0)
    {
        return ret;
    }
    unsigned char ch, ch2;
    for (pos = 0; pos != (int)password.GetSize(); ++pos)
    {
        if ((ret = password.GetUInt8(pos, &ch)) != 0)
        {
            break;
        }
        if (ch != 0x30)
        {
            if ((ret = crypted.GetUInt8(pos, &ch2)) != 0)
            {
                break;
            }
            ch2 += ch - 0x30;
            //Convert to upper case.
            if (ch2 > 0x39)
            {
                ch2 += 7;
            }
            if ((ret = crypted.SetUInt8(pos, ch2)) != 0)
            {
                break;
            }
        }
    }
    return ret;
}