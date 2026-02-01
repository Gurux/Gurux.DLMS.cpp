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

#include "../include/GXDLMSPushSetup.h"
#include "../include/GXDLMSClient.h"
#include "../include/GXDLMSObjectFactory.h"
#include <sstream>
#ifndef DLMS_IGNORE_PUSH_SETUP
//Constructor.
CGXDLMSPushSetup::CGXDLMSPushSetup() :
    CGXDLMSPushSetup("0.7.25.9.0.255", 0)
{
}

//SN Constructor.
CGXDLMSPushSetup::CGXDLMSPushSetup(std::string ln, unsigned short sn) :
    CGXDLMSObject(DLMS_OBJECT_TYPE_PUSH_SETUP, ln, sn)
{
    m_RandomisationStartInterval = m_NumberOfRetries = m_RepetitionDelay = 0;
    GXHelpers::SetLogicalName("0.7.25.9.0.255", m_LN);
    m_Service = DLMS_SERVICE_TYPE_TCP;
    m_Message = DLMS_MESSAGE_TYPE_COSEM_APDU;
    m_PortReference = NULL;
}

//LN Constructor.
CGXDLMSPushSetup::CGXDLMSPushSetup(std::string ln) :
    CGXDLMSPushSetup(ln, 0)
{
}

DLMS_SERVICE_TYPE CGXDLMSPushSetup::GetService()
{
    return m_Service;
}
void CGXDLMSPushSetup::SetService(DLMS_SERVICE_TYPE value)
{
    m_Service = value;
}

std::string& CGXDLMSPushSetup::GetDestination()
{
    return m_Destination;
}
void CGXDLMSPushSetup::SetDestination(std::string& value)
{
    m_Destination = value;
}

DLMS_MESSAGE_TYPE CGXDLMSPushSetup::GetMessageType()
{
    return m_Message;
}

void CGXDLMSPushSetup::SetMessageType(DLMS_MESSAGE_TYPE value)
{
    m_Message = value;
}

int CGXDLMSPushSetup::GetAttributeCount()
{
    if (m_Version == 0)
    {
        return 7;
    }
    if (m_Version == 1)
    {
        return 10;
    }
    return 13;
}

// Returns amount of methods.
int CGXDLMSPushSetup::GetMethodCount()
{
    if (m_Version < 2)
    {
        return 1;
    }
    return 2;
}

void CGXDLMSPushSetup::GetValues(std::vector<std::string>& values)
{
    values.clear();
    std::string str;
    GetLogicalName(str);
    values.push_back(str);
    std::stringstream sb;
    sb << '[';
    bool empty = true;
    for (std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject> >::iterator it = m_PushObjectList.begin(); it != m_PushObjectList.end(); ++it)
    {
        if (!empty)
        {
            sb << ", ";
        }
        empty = false;
        str.clear();
        it->first->GetLogicalName(str);
        sb.write(str.c_str(), str.size());
    }
    sb << ']';
    values.push_back(sb.str());

    sb.str(std::string());
    sb << GetService();
    sb << " ";
    sb << GetDestination().c_str();
    sb << " ";
    sb << GetMessageType();
    values.push_back(sb.str());

    sb.str(std::string());
    sb << '[';
    empty = true;
    std::vector<std::pair<CGXDateTime, CGXDateTime> >::iterator it;
    for (it = m_CommunicationWindow.begin(); it != m_CommunicationWindow.end(); ++it)
    {
        if (!empty)
        {
            sb << ", ";
        }
        empty = false;
        str = it->first.ToString();
        sb.write(str.c_str(), str.size());
        sb << " ";
        str = it->second.ToString();
        sb.write(str.c_str(), str.size());
    }
    sb << ']';
    values.push_back(sb.str());

    values.push_back(CGXDLMSVariant(m_RandomisationStartInterval).ToString());
    values.push_back(CGXDLMSVariant(m_NumberOfRetries).ToString());
    if (m_Version < 2)
    {
        values.push_back(CGXDLMSVariant(m_RepetitionDelay).ToString());
    }
    else
    {
        str = std::to_string(m_RepetitionDelay2.GetMax());
        str += ", ";
        str += std::to_string(m_RepetitionDelay2.GetExponent());
        str += ", ";
        str += std::to_string(m_RepetitionDelay2.GetMax());
        values.push_back(sb.str());
        str.clear();
        if (m_PortReference != NULL)
        {
            m_PortReference->GetLogicalName(str);
        }
        values.push_back(str);

        str = std::to_string(m_PushClientSAP);
        values.push_back(str);

        sb.str(std::string());
        sb << '[';
        empty = true;
        std::vector<CGXPushProtectionParameters>::iterator it;
        for (it = m_PushProtectionParameters.begin();
            it != m_PushProtectionParameters.end(); ++it)
        {
            if (!empty)
            {
                sb << ", ";
            }
            empty = false;
            sb << "{";
            sb << std::to_string(it->GetProtectionType());
            sb << ", ";
            sb << it->GetTransactionId().ToString();
            sb << ", ";
            sb << it->GetOriginatorSystemTitle().ToString();
            sb << ", ";
            sb << it->GetRecipientSystemTitle().ToString();
            sb << ", ";
            sb << it->GetOtherInformation().ToString();
            sb << ", ";
            str = it->GetKeyInfo().ToString();
            sb << "}";
        }
        sb << ']';
        values.push_back(sb.str());

        str = std::to_string(m_PushOperationMethod);
        values.push_back(str);
        str = m_ConfirmationParameters.ToString();
        values.push_back(str);
        str = m_LastConfirmationDateTime.ToString();
        values.push_back(str);
    }
}

void CGXDLMSPushSetup::GetAttributeIndexToRead(bool all, std::vector<int>& attributes)
{
    //LN is static and read only once.
    if (all || CGXDLMSObject::IsLogicalNameEmpty(m_LN))
    {
        attributes.push_back(1);
    }
    //PushObjectList
    if (all || CanRead(2))
    {
        attributes.push_back(2);
    }

    //SendDestinationAndMethod
    if (all || CanRead(3))
    {
        attributes.push_back(3);
    }
    //CommunicationWindow
    if (all || CanRead(4))
    {
        attributes.push_back(4);
    }
    //RandomisationStartInterval
    if (all || CanRead(5))
    {
        attributes.push_back(5);
    }
    //NumberOfRetries
    if (all || CanRead(6))
    {
        attributes.push_back(6);
    }
    //RepetitionDelay
    if (all || CanRead(7))
    {
        attributes.push_back(7);
    }
    if (m_Version > 0)
    {
        // PortReference
        if (all || CanRead(8))
        {
            attributes.push_back(8);
        }
        // PushClientSAP
        if (all || CanRead(9))
        {
            attributes.push_back(9);
        }
        // PushProtectionParameters
        if (all || CanRead(10))
        {
            attributes.push_back(10);
        }
        if (m_Version < 1)
        {
            // PushOperationMethod
            if (all || CanRead(11))
            {
                attributes.push_back(11);
            }
            // ConfirmationParameters
            if (all || CanRead(12))
            {
                attributes.push_back(12);
            }
            // LastConfirmationDateTime
            if (all || CanRead(13))
            {
                attributes.push_back(13);
            }
        }
    }
}

int CGXDLMSPushSetup::GetDataType(int index, DLMS_DATA_TYPE& type)
{
    if (index == 1)
    {
        type = DLMS_DATA_TYPE_OCTET_STRING;
        return DLMS_ERROR_CODE_OK;
    }
    else if (index == 2)
    {
        type = DLMS_DATA_TYPE_ARRAY;
    }
    else if (index == 3)
    {
        type = DLMS_DATA_TYPE_STRUCTURE;
    }
    else if (index == 4)
    {
        type = DLMS_DATA_TYPE_ARRAY;
    }
    else if (index == 5)
    {
        type = DLMS_DATA_TYPE_UINT16;
    }
    else if (index == 6)
    {
        type = DLMS_DATA_TYPE_UINT8;
    }
    else if (index == 7)
    {
        if (m_Version < 2)
        {
            type = DLMS_DATA_TYPE_UINT16;
        }
        else
        {
            type = DLMS_DATA_TYPE_STRUCTURE;
        }
    }
    else
    {
        if (m_Version > 0)
        {
            // PortReference
            if (index == 8)
            {
                type = DLMS_DATA_TYPE_OCTET_STRING;
            }
            // PushClientSAP
            if (index == 9)
            {
                type = DLMS_DATA_TYPE_INT8;
            }
            // PushProtectionParameters
            if (index == 10)
            {
                type = DLMS_DATA_TYPE_ARRAY;
            }
            if (m_Version > 1)
            {
                // PushOperationMethod
                if (index == 11)
                {
                    type = DLMS_DATA_TYPE_ENUM;
                }
                // ConfirmationParameters
                if (index == 12)
                {
                    type = DLMS_DATA_TYPE_STRUCTURE;
                }
                // LastConfirmationDateTime
                if (index == 13)
                {
                    type = DLMS_DATA_TYPE_DATETIME;
                }
            }
            else
            {
                return DLMS_ERROR_CODE_INVALID_PARAMETER;
            }
        }
        else
        {
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
    }
    return DLMS_ERROR_CODE_OK;
}

// Returns value of given attribute.
int CGXDLMSPushSetup::GetValue(CGXDLMSSettings& settings, CGXDLMSValueEventArg& e)
{
    CGXDLMSVariant tmp;
    CGXByteBuffer buff;
    int ret;
    if (e.GetIndex() == 1)
    {
        if ((ret = GetLogicalName(this, tmp)) != 0)
        {
            return ret;
        }
        e.SetValue(tmp);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 2)
    {
        e.SetByteArray(true);
        buff.SetUInt8(DLMS_DATA_TYPE_ARRAY);
        GXHelpers::SetObjectCount((unsigned long)m_PushObjectList.size(), buff);
        for (std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject> >::iterator it = m_PushObjectList.begin(); it != m_PushObjectList.end(); ++it)
        {
            buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE);
            buff.SetUInt8(4);

            tmp = it->first->GetObjectType();
            if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_UINT16, tmp)) != 0)
            {
                return ret;
            }
            tmp.Clear();
            if ((ret = GetLogicalName(it->first, tmp)) != 0)
            {
                return ret;
            }
            if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
            {
                return ret;
            }
            tmp = (it->second).GetAttributeIndex();
            if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_INT8, tmp)) != 0)
            {
                return ret;
            }
            tmp = (it->second).GetDataIndex();
            if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_UINT16, tmp)) != 0)
            {
                return ret;
            }
        }
        e.SetValue(buff);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 3)
    {
        e.SetByteArray(true);
        buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE);
        buff.SetUInt8(3);
        tmp = GetService();
        if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_ENUM, tmp)) != 0)
        {
            return ret;
        }

        CGXByteBuffer bb;
        bb.AddString(GetDestination().c_str());
        tmp = bb;
        if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
        {
            return ret;
        }

        tmp = GetMessageType();
        if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_ENUM, tmp)) != 0)
        {
            return ret;
        }
        e.SetValue(buff);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 4)
    {
        e.SetByteArray(true);
        buff.SetUInt8(DLMS_DATA_TYPE_ARRAY);
        GXHelpers::SetObjectCount((unsigned long)m_CommunicationWindow.size(), buff);
        for (std::vector<std::pair< CGXDateTime, CGXDateTime> >::iterator it = m_CommunicationWindow.begin(); it != m_CommunicationWindow.end(); ++it)
        {
            buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE);
            buff.SetUInt8(2);
            tmp = it->first;
            if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
            {
                return ret;
            }

            tmp = it->second;
            if ((ret = GXHelpers::SetData(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, tmp)) != 0)
            {
                return ret;
            }
        }
        e.SetValue(buff);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 5)
    {
        e.SetValue(m_RandomisationStartInterval);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 6)
    {
        e.SetValue(m_NumberOfRetries);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 7)
    {
        if (m_Version < 2)
        {
            ret = 0;
            e.SetValue(m_RepetitionDelay);
        }
        else
        {
            e.SetByteArray(true);
            if ((ret = buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE)) == 0 &&
                (ret = GXHelpers::SetObjectCount(3, buff)) == 0 &&
                (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_UINT16, m_RepetitionDelay2.GetMin())) == 0 &&
                (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_UINT16, m_RepetitionDelay2.GetExponent())) == 0 &&
                (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_UINT16, m_RepetitionDelay2.GetMax())) == 0)
            {
                e.SetValue(buff);
            }
        }
        return ret;
    }
    if (e.GetIndex() == 8)
    {
        if ((ret = GetLogicalName(m_PortReference, tmp)) != 0)
        {
            return ret;
        }
        e.SetValue(tmp);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 9)
    {
        e.SetValue(m_PushClientSAP);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 10)
    {
        e.SetByteArray(true);
        if ((ret = buff.SetUInt8(DLMS_DATA_TYPE_ARRAY)) == 0 &&
            (ret = GXHelpers::SetObjectCount((unsigned long)m_PushProtectionParameters.size(), buff)) == 0)
        {
            for (std::vector<CGXPushProtectionParameters>::iterator it = m_PushProtectionParameters.begin(); it != m_PushProtectionParameters.end(); ++it)
            {
                if ((ret = buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE)) != 0 ||
                    (ret = buff.SetUInt8(2)) != 0 ||
                    (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_ENUM, it->GetProtectionType())) != 0 ||
                    (ret = buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE)) != 0 ||
                    (ret = buff.SetUInt8(5)) != 0 ||
                    (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, it->GetTransactionId())) != 0 ||
                    (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, it->GetOriginatorSystemTitle())) != 0 ||
                    (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, it->GetRecipientSystemTitle())) != 0 ||
                    (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING, it->GetOtherInformation())) != 0 ||
                    (ret = buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE)) != 0 ||
                    (ret = buff.SetUInt8(2)) != 0 ||
                    (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_ENUM, it->GetKeyInfo().GetDataProtectionKeyType())) != 0 ||
                    (ret = buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE)) != 0)
                {
                    break;
                }
                if (it->GetKeyInfo().GetDataProtectionKeyType() == DLMS_DATA_PROTECTION_KEY_TYPE_IDENTIFIED)
                {
                    if ((ret = buff.SetUInt8(1)) != 0 ||
                        (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_ENUM,
                            it->GetKeyInfo().GetIdentifiedKey().GetKeyType())) != 0)
                    {
                        break;
                    }
                }
                else if (it->GetKeyInfo().GetDataProtectionKeyType() == DLMS_DATA_PROTECTION_KEY_TYPE_WRAPPED) {
                    if ((ret = buff.SetUInt8(2)) != 0 ||
                        (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_ENUM,
                            it->GetKeyInfo().GetWrappedKey().GetKeyType())) != 0 ||
                        (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING,
                            it->GetKeyInfo().GetWrappedKey().GetKey())) != 0)
                    {
                        break;
                    }
                }
                else if (it->GetKeyInfo().GetDataProtectionKeyType() == DLMS_DATA_PROTECTION_KEY_TYPE_AGREED) {
                    if ((ret = buff.SetUInt8(2)) != 0 ||
                        (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING,
                            it->GetKeyInfo().GetAgreedKey().GetParameters())) != 0 ||
                        (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_OCTET_STRING,
                            it->GetKeyInfo().GetAgreedKey().GetData())) != 0)
                    {
                        break;
                    }
                }
            }
            e.SetValue(buff);
        }
        return ret;
    }
    if (e.GetIndex() == 11)
    {
        e.SetValue(m_PushOperationMethod);
        return DLMS_ERROR_CODE_OK;
    }
    if (e.GetIndex() == 12)
    {
        e.SetByteArray(true);
        if ((ret = buff.SetUInt8(DLMS_DATA_TYPE_STRUCTURE)) == 0 &&
            (ret = GXHelpers::SetObjectCount(2, buff)) == 0 &&
            (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_DATETIME, m_ConfirmationParameters.GetStartDate())) == 0 &&
            (ret = GXHelpers::SetData2(&settings, buff, DLMS_DATA_TYPE_UINT32, m_ConfirmationParameters.GetInterval())) == 0)
        {
            e.SetValue(buff);
        }
        return ret;
    }
    if (e.GetIndex() == 13)
    {
        e.SetValue(m_LastConfirmationDateTime);
        return DLMS_ERROR_CODE_OK;
    }
    return DLMS_ERROR_CODE_INVALID_PARAMETER;
}

// Set value of given attribute.
int CGXDLMSPushSetup::SetValue(CGXDLMSSettings& settings, CGXDLMSValueEventArg& e)
{
    std::string ln;
    if (e.GetIndex() == 1)
    {
        return SetLogicalName(this, e.GetValue());
    }
    else if (e.GetIndex() == 2)
    {
        m_PushObjectList.clear();
        if (e.GetValue().vt == DLMS_DATA_TYPE_ARRAY)
        {
            for (std::vector<CGXDLMSVariant>::iterator it = e.GetValue().Arr.begin(); it != e.GetValue().Arr.end(); ++it)
            {
                DLMS_OBJECT_TYPE type = (DLMS_OBJECT_TYPE)it->Arr[0].ToInteger();
                GXHelpers::GetLogicalName(it->Arr[1].byteArr, ln);
                CGXDLMSObject* obj = settings.GetObjects().FindByLN(type, ln);
                if (obj == NULL)
                {
                    obj = CGXDLMSObjectFactory::CreateObject(type);
                    if (obj != NULL)
                    {
                        settings.AddAllocateObject(obj);
                        CGXDLMSObject::SetLogicalName(obj, it->Arr[1]);
                    }
                }
                if (obj != NULL)
                {
                    CGXDLMSCaptureObject co(it->Arr[2].ToInteger(), it->Arr[3].ToInteger());
                    m_PushObjectList.push_back(std::pair<CGXDLMSObject*, CGXDLMSCaptureObject>(obj, co));
                }
            }
        }
    }
    else if (e.GetIndex() == 3)
    {
        if (e.GetValue().vt == DLMS_DATA_TYPE_STRUCTURE)
        {
            SetService((DLMS_SERVICE_TYPE)e.GetValue().Arr[0].ToInteger());
            std::string str;
            str.append(reinterpret_cast<char const*>(e.GetValue().Arr[1].byteArr), e.GetValue().Arr[1].size);
            SetDestination(str);
            SetMessageType((DLMS_MESSAGE_TYPE)e.GetValue().Arr[2].ToInteger());
        }
    }
    else if (e.GetIndex() == 4)
    {
        m_CommunicationWindow.clear();
        if (e.GetValue().vt == DLMS_DATA_TYPE_ARRAY)
        {
            int ret;
            std::vector<CGXDLMSVariant>::iterator it;
            for (it = e.GetValue().Arr.begin(); it != e.GetValue().Arr.end(); ++it)
            {
                CGXDLMSVariant tmp;
                if ((ret = CGXDLMSClient::ChangeType(it->Arr[0], DLMS_DATA_TYPE_DATETIME, tmp)) != 0)
                {
                    return ret;
                }
                CGXDateTime start = tmp.dateTime;
                if ((ret = CGXDLMSClient::ChangeType(it->Arr[1], DLMS_DATA_TYPE_DATETIME, tmp)) != 0)
                {
                    return ret;
                }
                CGXDateTime end = tmp.dateTime;
                m_CommunicationWindow.push_back(std::pair<CGXDateTime, CGXDateTime>(start, end));
            }
        }
    }
    else if (e.GetIndex() == 5)
    {
        m_RandomisationStartInterval = e.GetValue().ToInteger();
    }
    else if (e.GetIndex() == 6)
    {
        m_NumberOfRetries = e.GetValue().ToInteger();
    }
    else if (e.GetIndex() == 7)
    {
        if (m_Version < 2)
        {
            m_RepetitionDelay = e.GetValue().ToInteger();
        }
        else if (e.GetValue().vt == DLMS_DATA_TYPE_STRUCTURE)
        {
            m_RepetitionDelay2.SetMin(e.GetValue().Arr.at(0).ToInteger());
            m_RepetitionDelay2.SetExponent(e.GetValue().Arr.at(1).ToInteger());
            m_RepetitionDelay2.SetMax(e.GetValue().Arr.at(2).ToInteger());
        }
    }
    else if (m_Version > 0 && e.GetIndex() == 8)
    {
        m_PortReference = NULL;
        if (e.GetValue().vt == DLMS_DATA_TYPE_OCTET_STRING)
        {
            GXHelpers::GetLogicalName(e.GetValue().byteArr, ln);
            m_PortReference = settings.GetObjects().FindByLN(DLMS_OBJECT_TYPE_NONE, ln);
        }
    }
    else if (m_Version > 0 && e.GetIndex() == 9)
    {
        m_PushClientSAP = e.GetValue().ToInteger();
    }
    else if (m_Version > 0 && e.GetIndex() == 10)
    {
        m_PushProtectionParameters.clear();
        if (e.GetValue().vt == DLMS_DATA_TYPE_ARRAY)
        {
            CGXByteBuffer bb;
            std::vector<CGXDLMSVariant>::iterator it;
            for (it = e.GetValue().Arr.begin(); it != e.GetValue().Arr.end(); ++it)
            {
                CGXPushProtectionParameters p;
                p.SetProtectionType((DLMS_PROTECTION_TYPE)it->Arr.at(0).ToInteger());
                std::vector<CGXDLMSVariant> options = it->Arr.at(1).Arr;
                bb.Clear();
                options.at(0).GetBytes(bb);
                p.SetTransactionId(bb);
                bb.Clear();
                options.at(1).GetBytes(bb);
                p.SetOriginatorSystemTitle(bb);
                bb.Clear();
                options.at(2).GetBytes(bb);
                p.SetRecipientSystemTitle(bb);
                bb.Clear();
                options.at(3).GetBytes(bb);
                p.SetOtherInformation(bb);
                std::vector<CGXDLMSVariant> keyInfo = options.at(4).Arr;
                p.GetKeyInfo().SetDataProtectionKeyType((DLMS_DATA_PROTECTION_KEY_TYPE)keyInfo.at(0).ToInteger());
                std::vector<CGXDLMSVariant> data = keyInfo.at(1).Arr;
                if (p.GetKeyInfo().GetDataProtectionKeyType() == DLMS_DATA_PROTECTION_KEY_TYPE_IDENTIFIED)
                {
                    p.GetKeyInfo().GetIdentifiedKey().SetKeyType((DLMS_DATA_PROTECTION_IDENTIFIED_KEY_TYPE)data.at(0).ToInteger());
                }
                else if (p.GetKeyInfo().GetDataProtectionKeyType() == DLMS_DATA_PROTECTION_KEY_TYPE_WRAPPED)
                {
                    p.GetKeyInfo().GetWrappedKey().SetKeyType((DLMS_DATA_PROTECTION_WRAPPED_KEY_TYPE)data.at(0).ToInteger());
                    bb.Clear();
                    data.at(1).GetBytes(bb);
                    p.GetKeyInfo().GetWrappedKey().SetKey(bb);
                }
                else if (p.GetKeyInfo().GetDataProtectionKeyType() == DLMS_DATA_PROTECTION_KEY_TYPE_AGREED)
                {
                    bb.Clear();
                    data.at(0).GetBytes(bb);
                    p.GetKeyInfo().GetAgreedKey().SetParameters(bb);
                    bb.Clear();
                    data.at(1).GetBytes(bb);
                    p.GetKeyInfo().GetAgreedKey().SetData(bb);
                }
                m_PushProtectionParameters.push_back(p);
            }
        }
    }
    else if (m_Version > 1 && e.GetIndex() == 11)
    {
        m_PushOperationMethod = (DLMS_PUSH_OPERATION_METHOD)e.GetValue().ToInteger();
    }
    else if (m_Version > 1 && e.GetIndex() == 12)
    {
        if (e.GetValue().vt == DLMS_DATA_TYPE_STRUCTURE)
        {
            m_ConfirmationParameters.SetStartDate(e.GetValue().Arr.at(0).dateTime);
            m_ConfirmationParameters.SetInterval(e.GetValue().Arr.at(0).ToInteger());
        }
        else
        {
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
    }
    else if (m_Version > 1 && e.GetIndex() == 13)
    {
        m_LastConfirmationDateTime = e.GetValue().dateTime;
    }
    else
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    return DLMS_ERROR_CODE_OK;
}

int CGXDLMSPushSetup::GetPushValues(CGXDLMSClient* client,
    std::vector<CGXDLMSVariant>& values,
    std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject> >& results)
{
    int ret = 0;
    int pos = 0;
    if (values.size() != m_PushObjectList.size())
    {
        ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    else
    {
        CGXDLMSVariant value;
        std::string ln;
        for (std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject> >::iterator it = m_PushObjectList.begin(); it != m_PushObjectList.end(); ++it)
        {
            it->first->GetLogicalName(ln);
            CGXDLMSObject* obj = CGXDLMSObjectFactory::CreateObject(it->first->GetObjectType(), ln);
            obj->SetVersion(it->first->GetVersion());
            obj->SetDescription(it->first->GetDescription());
            CGXAttributeCollection& target = obj->GetAttributes();
            CGXAttributeCollection& att = it->first->GetAttributes();
            target.clear();
            target.insert(target.end(), att.begin(), att.end());
            value = values.at(pos);
            if (it->second.GetAttributeIndex() == 0)
            {
                std::vector<CGXDLMSVariant>& tmp = values.at(pos).Arr;
                for (int index = 1; index <= it->first->GetAttributeCount(); ++index)
                {
                    client->UpdateValue(*obj, index, tmp.at(index - 1));
                }
            }
            else
            {
                if ((ret = client->UpdateValue(*obj, it->second.GetAttributeIndex(), value)) != 0)
                {
                    break;
                }
            }
            results.push_back(std::pair<CGXDLMSObject*, CGXDLMSCaptureObject>(obj, it->second));
            ++pos;
        }
    }
    return ret;
}

int CGXDLMSPushSetup::Activate(
    CGXDLMSClient* client,
    std::vector<CGXByteBuffer>& reply)
{
    CGXDLMSVariant data((char)0);
    return client->Method(this, 1, data, reply);
}

int CGXDLMSPushSetup::Reset(
    CGXDLMSClient* client,
    std::vector<CGXByteBuffer>& reply)
{
    CGXDLMSVariant data((char)0);
    return client->Method(this, 2, data, reply);
}

#endif //DLMS_IGNORE_PUSH_SETUP