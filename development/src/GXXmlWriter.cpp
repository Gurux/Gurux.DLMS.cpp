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

#include <string>
#include "../include/GXIgnore.h"
#include "../include/GXXmlWriter.h"
#ifndef DLMS_IGNORE_ACTION_SCHEDULE
#include "../include/GXDLMSActionSchedule.h"
#endif //DLMS_IGNORE_ACTION_SCHEDULE
#ifndef DLMS_IGNORE_ACTIVITY_CALENDAR
#include "../include/GXDLMSActivityCalendar.h"
#endif //DLMS_IGNORE_ACTIVITY_CALENDAR
#ifndef DLMS_IGNORE_ASSOCIATION_LOGICAL_NAME
#include "../include/GXDLMSAssociationLogicalName.h"
#endif //DLMS_IGNORE_ASSOCIATION_LOGICAL_NAME
#ifndef DLMS_IGNORE_ASSOCIATION_SHORT_NAME
#include "../include/GXDLMSAssociationShortName.h"
#endif //DLMS_IGNORE_ASSOCIATION_SHORT_NAME
#ifndef DLMS_IGNORE_AUTO_ANSWER
#include "../include/GXDLMSAutoAnswer.h"
#endif //DLMS_IGNORE_AUTO_ANSWER
#ifndef DLMS_IGNORE_AUTO_CONNECT
#include "../include/GXDLMSAutoConnect.h"
#endif //DLMS_IGNORE_AUTO_CONNECT
#ifndef DLMS_IGNORE_CLOCK
#include "../include/GXDLMSClock.h"
#endif //DLMS_IGNORE_CLOCK
#ifndef DLMS_IGNORE_DATA
#include "../include/GXDLMSData.h"
#endif //DLMS_IGNORE_DATA
#ifndef DLMS_IGNORE_REGISTER
#include "../include/GXDLMSRegister.h"
#endif //DLMS_IGNORE_REGISTER
#ifndef DLMS_IGNORE_EXTENDED_REGISTER
#include "../include/GXDLMSExtendedRegister.h"
#endif //DLMS_IGNORE_EXTENDED_REGISTER
#ifndef DLMS_IGNORE_DEMAND_REGISTER
#include "../include/GXDLMSDemandRegister.h"
#endif //DLMS_IGNORE_DEMAND_REGISTER
#ifndef DLMS_IGNORE_REGISTER_MONITOR
#include "../include/GXDLMSRegisterMonitor.h"
#endif //DLMS_IGNORE_REGISTER_MONITOR
#ifndef DLMS_IGNORE_PROFILE_GENERIC
#include "../include/GXDLMSProfileGeneric.h"
#endif //DLMS_IGNORE_PROFILE_GENERIC
#ifndef DLMS_IGNORE_TCP_UDP_SETUP
#include "../include/GXDLMSTcpUdpSetup.h"
#endif //DLMS_IGNORE_TCP_UDP_SETUP
#ifndef DLMS_IGNORE_GPRS_SETUP
#include "../include/GXDLMSGPRSSetup.h"
#endif //DLMS_IGNORE_GPRS_SETUP
#ifndef DLMS_IGNORE_ACTION_SCHEDULE
#include "../include/GXDLMSActionSchedule.h"
#endif //DLMS_IGNORE_ACTION_SCHEDULE
#ifndef DLMS_IGNORE_SPECIAL_DAYS_TABLE
#include "../include/GXDLMSSpecialDaysTable.h"
#endif //DLMS_IGNORE_SPECIAL_DAYS_TABLE
#ifndef DLMS_IGNORE_IMAGE_TRANSFER
#include "../include/GXDLMSImageTransfer.h"
#endif //DLMS_IGNORE_IMAGE_TRANSFER
#ifndef DLMS_IGNORE_DISCONNECT_CONTROL
#include "../include/GXDLMSDisconnectControl.h"
#endif //DLMS_IGNORE_DISCONNECT_CONTROL
#ifndef DLMS_IGNORE_LIMITER
#include "../include/GXDLMSLimiter.h"
#endif //DLMS_IGNORE_LIMITER
#ifndef DLMS_IGNORE_MBUS_CLIENT
#include "../include/GXDLMSMBusClient.h"
#endif //DLMS_IGNORE_MBUS_CLIENT
#ifndef DLMS_IGNORE_SCRIPT_TABLE
#include "../include/GXDLMSScriptTable.h"
#endif //DLMS_IGNORE_SCRIPT_TABLE
#ifndef DLMS_IGNORE_MBUS_SLAVE_PORT_SETUP
#include "../include/GXDLMSMBusSlavePortSetup.h"
#endif //DLMS_IGNORE_MBUS_SLAVE_PORT_SETUP
#ifndef DLMS_IGNORE_SECURITY_SETUP
#include "../include/GXDLMSSecuritySetup.h"
#endif //DLMS_IGNORE_SECURITY_SETUP
#ifndef DLMS_IGNORE_PPP_SETUP
#include "../include/GXDLMSPppSetup.h"
#endif //DLMS_IGNORE_PPP_SETUP
#ifndef DLMS_IGNORE_MAC_ADDRESS_SETUP
#include "../include/GXDLMSMacAddressSetup.h"
#endif //DLMS_IGNORE_MAC_ADDRESS_SETUP
#ifndef DLMS_IGNORE_IEC_HDLC_SETUP
#include "../include/GXDLMSHdlcSetup.h"
#endif //DLMS_IGNORE_IEC_HDLC_SETUP
#ifndef DLMS_IGNORE_IEC_LOCAL_PORT_SETUP
#include "../include/GXDLMSIECOpticalPortSetup.h"
#endif //DLMS_IGNORE_IEC_LOCAL_PORT_SETUP
#ifndef DLMS_IGNORE_IP4_SETUP
#include "../include/GXDLMSIp4Setup.h"
#endif //DLMS_IGNORE_IP4_SETUP
#ifndef DLMS_IGNORE_IP6_SETUP
#include "../include/GXDLMSIp6Setup.h"
#endif //DLMS_IGNORE_IP6_SETUP
#ifndef DLMS_IGNORE_REGISTER_ACTIVATION
#include "../include/GXDLMSRegisterActivation.h"
#endif //DLMS_IGNORE_REGISTER_ACTIVATION
#ifndef DLMS_IGNORE_SCHEDULE
#include "../include/GXDLMSSchedule.h"
#endif //DLMS_IGNORE_SCHEDULE
#ifndef DLMS_IGNORE_MODEM_CONFIGURATION
#include "../include/GXDLMSModemConfiguration.h"
#endif //DLMS_IGNORE_MODEM_CONFIGURATION
#ifndef DLMS_IGNORE_SAP_ASSIGNMENT
#include "../include/GXDLMSSapAssignment.h"
#endif //DLMS_IGNORE_SAP_ASSIGNMENT
#ifndef DLMS_IGNORE_MBUS_MASTER_PORT_SETUP
#include "../include/GXDLMSMBusMasterPortSetup.h"
#endif //DLMS_IGNORE_MBUS_MASTER_PORT_SETUP
#ifndef DLMS_IGNORE_MESSAGE_HANDLER
#include "../include/GXDLMSMessageHandler.h"
#endif //DLMS_IGNORE_MESSAGE_HANDLER
#ifndef DLMS_IGNORE_PUSH_SETUP
#include "../include/GXDLMSPushSetup.h"
#endif //DLMS_IGNORE_PUSH_SETUP
#ifndef DLMS_IGNORE_GSM_DIAGNOSTIC
#include "../include/GXDLMSGSMDiagnostic.h"
#endif //DLMS_IGNORE_GSM_DIAGNOSTIC
#ifndef DLMS_IGNORE_ACCOUNT
#include "../include/GXDLMSAccount.h"
#endif //DLMS_IGNORE_ACCOUNT
#ifndef DLMS_IGNORE_CREDIT
#include "../include/GXDLMSCredit.h"
#endif //DLMS_IGNORE_CREDIT
#ifndef DLMS_IGNORE_CHARGE
#include "../include/GXDLMSCharge.h"
#endif //DLMS_IGNORE_CHARGE
#ifndef DLMS_IGNORE_PARAMETER_MONITOR
#include "../include/GXDLMSParameterMonitor.h"
#endif //DLMS_IGNORE_PARAMETER_MONITOR
#ifndef DLMS_IGNORE_TOKEN_GATEWAY
#include "../include/GXDLMSTokenGateway.h"
#endif //DLMS_IGNORE_TOKEN_GATEWAY
#ifndef DLMS_IGNORE_COMPACT_DATA
#include "../include/GXDLMSCompactData.h"
#endif //DLMS_IGNORE_COMPACT_DATA
#ifndef DLMS_IGNORE_UTILITY_TABLES
#include "../include/GXDLMSUtilityTables.h"
#endif //DLMS_IGNORE_UTILITY_TABLES
#ifndef DLMS_IGNORE_LLC_SSCS_SETUP
#include "../include/GXDLMSLlcSscsSetup.h"
#endif //DLMS_IGNORE_LLC_SSCS_SETUP
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_PHYSICAL_LAYER_COUNTERS
#include "../include/GXDLMSPrimeNbOfdmPlcPhysicalLayerCounters.h"
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_PHYSICAL_LAYER_COUNTERS
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_SETUP
#include "../include/GXDLMSPrimeNbOfdmPlcMacSetup.h"
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_SETUP
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS
#include "../include/GXDLMSPrimeNbOfdmPlcMacFunctionalParameters.h"
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_COUNTERS
#include "../include/GXDLMSPrimeNbOfdmPlcMacCounters.h"
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_COUNTERS
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA
#include "../include/GXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData.h"
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_APPLICATIONS_IDENTIFICATION
#include "../include/GXDLMSPrimeNbOfdmPlcApplicationsIdentification.h"
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_APPLICATIONS_IDENTIFICATION
#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE1_SETUP
#include "../include/GXDLMSIec8802LlcType1Setup.h"
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE1_SETUP
#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE2_SETUP
#include "../include/GXDLMSIec8802LlcType2Setup.h"
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE2_SETUP
#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE3_SETUP
#include "../include/GXDLMSIec8802LlcType3Setup.h"
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE3_SETUP
#ifndef DLMS_IGNORE_SFSK_REPORTING_SYSTEM_LIST
#include "../include/GXDLMSSFSKReportingSystemList.h"
#endif //DLMS_IGNORE_SFSK_REPORTING_SYSTEM_LIST
#ifndef DLMS_IGNORE_ARBITRATOR
#include "../include/GXDLMSArbitrator.h"
#endif //DLMS_IGNORE_ARBITRATOR
#ifndef DLMS_IGNORE_SFSK_MAC_COUNTERS
#include "../include/GXDLMSSFSKMacCounters.h"
#endif //DLMS_IGNORE_SFSK_MAC_COUNTERS
#ifndef DLMS_IGNORE_SFSK_MAC_SYNCHRONIZATION_TIMEOUTS
#include "../include/GXDLMSSFSKMacSynchronizationTimeouts.h"
#endif //DLMS_IGNORE_SFSK_MAC_SYNCHRONIZATION_TIMEOUTS
#ifndef DLMS_IGNORE_SFSK_ACTIVE_INITIATOR
#include "../include/GXDLMSSFSKActiveInitiator.h"
#endif //DLMS_IGNORE_SFSK_ACTIVE_INITIATOR
#ifndef DLMS_IGNORE_SFSK_PHY_MAC_SETUP
#include "../include/GXDLMSSFSKPhyMacSetUp.h"
#endif //DLMS_IGNORE_SFSK_PHY_MAC_SETUP
#ifndef DLMS_IGNORE_IEC_TWISTED_PAIR_SETUP
#include "../include/GXDLMSIecTwistedPairSetup.h"
#endif //DLMS_IGNORE_IEC_TWISTED_PAIR_SETUP
#ifndef DLMS_IGNORE_NTP_SETUP
#include "../include/GXDLMSNtpSetup.h"
#endif //DLMS_IGNORE_NTP_SETUP
#ifndef DLMS_IGNORE_COMMUNICATION_PORT_PROTECTION
#include "../include/GXDLMSCommunicationPortProtection.h"
#endif //DLMS_IGNORE_COMMUNICATION_PORT_PROTECTION

CGXXmlWriter::CGXXmlWriter(FILE* f, bool skipDefaults)
{
    m_f = f;
    m_SkipDefaults = skipDefaults;
}

int CGXXmlWriter::AppendSpaces()
{
    for (size_t pos = 0; pos != m_Elements.size(); ++pos)
    {
        fprintf(m_f, "%s", "  ");
    }
    return 0;
}

int CGXXmlWriter::Write(const char* data)
{
    fprintf(m_f, "%s", data);
    return 0;
}

int CGXXmlWriter::WriteStartDocument()
{
    m_Elements.clear();
    const char* str = "<?xml version=\"1.0\" ?>";
    fprintf(m_f, "%s%s", str, NEW_LINE);
    return 0;
}

int CGXXmlWriter::WriteStartElement(const char* name)
{
    AppendSpaces();
    m_Elements.push_back(name);
    fprintf(m_f, "<%s>%s", name, NEW_LINE);
    return 0;
}

int CGXXmlWriter::WriteElementString(const char* name, int value)
{
    if (!m_SkipDefaults || value != 0)
    {
        char buff[20];
#if _MSC_VER > 1000
        sprintf_s(buff, 20, "%d", value);
#else
        sprintf(buff, "%d", value);
#endif
        WriteElementString(name, buff);
    }
    return 0;
}

int CGXXmlWriter::WriteElementString(const char* name, bool value)
{
    int tmp = value ? 1 : 0;
    return CGXXmlWriter::WriteElementString(name, tmp);
}

int CGXXmlWriter::WriteElementString(const char* name, long value)
{
    if (!m_SkipDefaults || value != 0)
    {
        char buff[20];
#if _MSC_VER > 1000
        sprintf_s(buff, 20, "%ld", value);
#else
        sprintf(buff, "%ld", value);
#endif
        WriteElementString(name, buff);
    }
    return 0;
}

int CGXXmlWriter::WriteElementString(const char* name, unsigned long value)
{
    if (!m_SkipDefaults || value != 0)
    {
        char buff[20];
#if _MSC_VER > 1000
        sprintf_s(buff, 20, "%lu", value);
#else
        sprintf(buff, "%lu", value);
#endif
        WriteElementString(name, buff);
    }
    return 0;
}

int CGXXmlWriter::WriteElementString(const char* name, unsigned int value)
{
    if (!m_SkipDefaults || value != 0)
    {
        char buff[20];
#if _MSC_VER > 1000
        sprintf_s(buff, 20, "%d", value);
#else
        sprintf(buff, "%d", value);
#endif
        WriteElementString(name, buff);
    }
    return 0;
}

int CGXXmlWriter::WriteElementString(const char* name, double value, double defaultValue)
{
    if (!m_SkipDefaults || value != 0)
    {
        char buff[30];
        int ret = snprintf(buff, 30, "%lf", value);
        //Remove trailing zeroes.
        while (ret > 0 && buff[ret - 1] == '0')
        {
            --ret;
        }
        if (ret > 0)
        {
            if (buff[ret - 1] == ',' || buff[ret - 1] == '.')
            {
                --ret;
                buff[ret] = 0;
            }
        }
        WriteElementString(name, buff);
    }
    return 0;
}

int CGXXmlWriter::WriteElementString(const char* name, CGXDateTime& value)
{
    std::string str;
    int ret;
    if ((ret = value.ToFormatString("%m/%d/%Y %H:%M:%S", str)) == 0)
    {
        return WriteElementString(name, str);
    }
    return ret;
}

int CGXXmlWriter::WriteElementString(const char* name, CGXDate& value)
{
    std::string str;
    int ret;
    if ((ret = value.ToFormatString("%m/%d/%Y", str)) == 0)
    {
        return WriteElementString(name, str);
    }
    return ret;
}

int CGXXmlWriter::WriteElementString(const char* name, CGXTime& value)
{
    std::string str;
    int ret;
    if ((ret = value.ToFormatString("%H:%M:%S", str)) == 0)
    {
        return WriteElementString(name, str);
    }
    return ret;
}

int CGXXmlWriter::WriteElementString(const char* name, const char* value)
{
    if (!m_SkipDefaults || (value != NULL && strlen(value) != 0))
    {
        AppendSpaces();
        fprintf(m_f, "<%s>%s</%s>%s", name, value, name, NEW_LINE);
    }
    return 0;
}

int CGXXmlWriter::WriteElementString(const char* name, const std::string& value)
{
    return WriteElementString(name, value.c_str());
}

int CGXXmlWriter::WriteEndElement(bool addSpaces)
{
    std::string item = m_Elements.back();
    m_Elements.pop_back();
    if (addSpaces)
    {
        AppendSpaces();
    }
    Write("</");
    Write(item.c_str());
    Write(">");
    Write(NEW_LINE);
    return 0;
}

int CGXXmlWriter::WriteEndElement()
{
    return WriteEndElement(true);
}

int CGXXmlWriter::WriteEndDocument()
{
    return 0;
}

int CGXXmlWriter::WriteAttributeString(const char* name, const char* value)
{
    return 0;
    //writer->WriteAttributeString(name, value);
}

int CGXXmlWriter::WriteAttributeString(const char* name, const int value)
{
    return 0;
    //writer->WriteAttributeString(name, value);
}

int CGXXmlWriter::WriteArray(CGXDLMSVariant& data)
{
    int ret = 0;
    if (data.vt == DLMS_DATA_TYPE_ARRAY || data.vt == DLMS_DATA_TYPE_STRUCTURE)
    {
        for (std::vector<CGXDLMSVariant>::iterator it = data.Arr.begin(); it != data.Arr.end(); ++it)
        {
            if (it->vt == DLMS_DATA_TYPE_OCTET_STRING)
            {
                if ((ret = WriteElementObject("Item", *it)) != 0)
                {
                    break;
                }
            }
            else if (it->vt == DLMS_DATA_TYPE_ARRAY ||
                it->vt == DLMS_DATA_TYPE_STRUCTURE)
            {
                AppendSpaces();
                m_Elements.push_back("Item");
                fprintf(m_f, "<%s Type=\"%d\"", "Item", it->vt);
                if ((ret = WriteArray(*it)) != 0 ||
                    (ret = WriteEndElement()) != 0)
                {
                    break;
                }
            }
            else
            {
                if ((ret = WriteElementObject("Item", *it)) != 0)
                {
                    break;
                }
            }
        }
    }
    return ret;
}

int CGXXmlWriter::WriteElementObject(const char* name, CGXDLMSVariant& value, DLMS_DATA_TYPE dt, DLMS_DATA_TYPE uiType)
{
    int ret;
    std::string str;
    AppendSpaces();
    m_Elements.push_back(name);
    if (dt == DLMS_DATA_TYPE_NONE)
    {
        dt = value.vt;
    }
    fprintf(m_f, "<%s Type=\"%d\"", name, dt);
    if (uiType != DLMS_DATA_TYPE_NONE && dt != uiType && (uiType != DLMS_DATA_TYPE_STRING || dt == DLMS_DATA_TYPE_OCTET_STRING))
    {
        fprintf(m_f, " UIType=\"%d\"", uiType);
    }
    else if (value.vt == DLMS_DATA_TYPE_FLOAT32 || value.vt == DLMS_DATA_TYPE_FLOAT64)
    {
        fprintf(m_f, " UIType=\"%d\"", value.vt);
    }
    fprintf(m_f, ">");
    if (dt == DLMS_DATA_TYPE_ARRAY || dt == DLMS_DATA_TYPE_STRUCTURE)
    {
        ret = WriteArray(value);
    }
    else
    {
        if (value.vt == DLMS_DATA_TYPE_DATETIME)
        {
            std::string str;
            value.dateTime.ToFormatString("%m/%d/%Y %H:%M:%S", str);
            fprintf(m_f, "%s", str.c_str());
        }
        else if (value.vt == DLMS_DATA_TYPE_OCTET_STRING)
        {
            CGXByteBuffer bb;
            bb.Set(value.byteArr, value.GetSize());
            fprintf(m_f, "%s", bb.ToHexString().c_str());
        }
        else
        {
            fprintf(m_f, "%s", value.ToString().c_str());
        }
    }
    ret = WriteEndElement(false);
    return ret;
}

#ifndef DLMS_IGNORE_ACTION_SCHEDULE
int SaveActionSchedule(CGXXmlWriter* writer, CGXDLMSActionSchedule* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("TargetLN", obj->GetExecutedScriptLogicalName())) == 0 &&
        (ret = writer->WriteElementString("ExecutedScriptSelector", obj->GetExecutedScriptSelector())) == 0 &&
        (ret = writer->WriteElementString("Type", (int)obj->GetType())) == 0 &&
        (ret = writer->WriteStartElement("ExecutionTime")) == 0)
    {
        for (std::vector<CGXDateTime>::iterator it = obj->GetExecutionTime().begin(); it != obj->GetExecutionTime().end(); ++it)
        {
            if ((ret = writer->WriteElementString("Time", *it)) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_ACTION_SCHEDULE

#ifndef DLMS_IGNORE_ACTIVITY_CALENDAR
int SaveSeasonProfile(CGXXmlWriter* writer, std::vector<CGXDLMSSeasonProfile*>& list, const char* name)
{
    int ret;
    if ((ret = writer->WriteStartElement(name)) == 0)
    {
        for (std::vector<CGXDLMSSeasonProfile*>::iterator it = list.begin(); it != list.end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Name", (*it)->GetName().ToHexString())) != 0 ||
                //Some meters are returning time here, not date-time.
                (ret = writer->WriteElementString("Start", (*it)->GetStart())) != 0 ||
                (ret = writer->WriteElementString("WeekName", (*it)->GetWeekName().ToHexString())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveWeekProfileTable(CGXXmlWriter* writer, std::vector<CGXDLMSWeekProfile*>& list, const char* name)
{
    int ret;
    if ((ret = writer->WriteStartElement(name)) == 0)
    {
        CGXByteBuffer bb;
        for (std::vector<CGXDLMSWeekProfile*>::iterator it = list.begin(); it != list.end(); ++it)
        {
            (*it)->GetName(bb);
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Name", bb.ToHexString())) != 0 ||
                (ret = writer->WriteElementString("Monday", (*it)->GetMonday())) != 0 ||
                (ret = writer->WriteElementString("Tuesday", (*it)->GetTuesday())) != 0 ||
                (ret = writer->WriteElementString("Wednesday", (*it)->GetWednesday())) != 0 ||
                (ret = writer->WriteElementString("Thursday", (*it)->GetThursday())) != 0 ||
                (ret = writer->WriteElementString("Friday", (*it)->GetFriday())) != 0 ||
                (ret = writer->WriteElementString("Saturday", (*it)->GetSaturday())) != 0 ||
                (ret = writer->WriteElementString("Sunday", (*it)->GetSunday())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveDayProfileTable(CGXXmlWriter* writer, std::vector<CGXDLMSDayProfile*>& list, const char* name)
{
    int ret;
    if ((ret = writer->WriteStartElement(name)) == 0)
    {
        for (std::vector<CGXDLMSDayProfile*>::iterator it = list.begin(); it != list.end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) == 0 &&
                (ret = writer->WriteElementString("DayId", (*it)->GetDayId())) == 0 &&
                (ret = writer->WriteStartElement("Actions")) == 0)
            {
                for (std::vector<CGXDLMSDayProfileAction*>::iterator d = (*it)->GetDaySchedules().begin(); d != (*it)->GetDaySchedules().end(); ++d)
                {
                    if ((ret = writer->WriteStartElement("Action")) != 0 ||
                        (ret = writer->WriteElementString("Start", (*d)->GetStartTime())) != 0 ||
                        (ret = writer->WriteElementString("LN", (*d)->GetScriptLogicalName())) != 0 ||
                        (ret = writer->WriteElementString("Selector", (*d)->GetScriptSelector())) != 0 ||
                        (ret = writer->WriteEndElement()) != 0)
                    {
                        break;
                    }
                }
            }
            if (ret == 0)
            {
                ret = writer->WriteEndElement();
                ret = writer->WriteEndElement();
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveActivityCalendar(CGXXmlWriter* writer, CGXDLMSActivityCalendar* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("CalendarNameActive", obj->GetCalendarNameActive())) != 0 ||
        (ret = SaveSeasonProfile(writer, obj->GetSeasonProfileActive(), "SeasonProfileActive")) != 0 ||
        (ret = SaveWeekProfileTable(writer, obj->GetWeekProfileTableActive(), "WeekProfileTableActive")) != 0 ||
        (ret = SaveDayProfileTable(writer, obj->GetDayProfileTableActive(), "DayProfileTableActive")) != 0 ||
        (ret = writer->WriteElementString("CalendarNamePassive", obj->GetCalendarNamePassive())) != 0 ||
        (ret = SaveSeasonProfile(writer, obj->GetSeasonProfilePassive(), "SeasonProfilePassive")) != 0 ||
        (ret = SaveWeekProfileTable(writer, obj->GetWeekProfileTablePassive(), "WeekProfileTablePassive")) != 0 ||
        (ret = SaveDayProfileTable(writer, obj->GetDayProfileTablePassive(), "DayProfileTablePassive")) != 0 ||
        (ret = writer->WriteElementString("Time", obj->GetTime())) != 0)
    {

    }
    return ret;
}

#endif //DLMS_IGNORE_ACTIVITY_CALENDAR

#ifndef DLMS_IGNORE_ASSOCIATION_LOGICAL_NAME
int SaveAssociationLogicalName(CGXXmlWriter* writer, CGXDLMSAssociationLogicalName* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("ClientSAP", obj->GetClientSAP())) == 0 &&
        (ret = writer->WriteElementString("ServerSAP", obj->GetServerSAP())) == 0 &&
        (ret = writer->WriteStartElement("ApplicationContextName")) == 0 &&
        (ret = writer->WriteElementString("JointIsoCtt", obj->GetApplicationContextName().GetJointIsoCtt())) == 0 &&
        (ret = writer->WriteElementString("Country", obj->GetApplicationContextName().GetCountry())) == 0 &&
        (ret = writer->WriteElementString("CountryName", obj->GetApplicationContextName().GetCountryName())) == 0 &&
        (ret = writer->WriteElementString("IdentifiedOrganization", obj->GetApplicationContextName().GetIdentifiedOrganization())) == 0 &&
        (ret = writer->WriteElementString("DlmsUA", obj->GetApplicationContextName().GetDlmsUA())) == 0 &&
        (ret = writer->WriteElementString("ApplicationContext", obj->GetApplicationContextName().GetApplicationContext())) == 0 &&
        (ret = writer->WriteElementString("ContextId", obj->GetApplicationContextName().GetContextId())) == 0 &&
        (ret = writer->WriteEndElement()) == 0 &&

        (ret = writer->WriteStartElement("XDLMSContextInfo")) == 0 &&
        (ret = writer->WriteElementString("Conformance", obj->GetXDLMSContextInfo().GetConformance())) == 0 &&
        (ret = writer->WriteElementString("MaxReceivePduSize", obj->GetXDLMSContextInfo().GetMaxReceivePduSize())) == 0 &&
        (ret = writer->WriteElementString("MaxSendPduSize", obj->GetXDLMSContextInfo().GetMaxSendPduSize())) == 0 &&
        (ret = writer->WriteElementString("DlmsVersionNumber", obj->GetXDLMSContextInfo().GetDlmsVersionNumber())) == 0 &&
        (ret = writer->WriteElementString("QualityOfService", obj->GetXDLMSContextInfo().GetQualityOfService())) == 0 &&
        (ret = writer->WriteElementString("CypheringInfo", obj->GetXDLMSContextInfo().GetCypheringInfo().ToHexString())) == 0 &&
        (ret = writer->WriteEndElement()) == 0 &&

        (ret = writer->WriteStartElement("AuthenticationMechanismName")) == 0 &&
        (ret = writer->WriteElementString("JointIsoCtt", obj->GetAuthenticationMechanismName().GetJointIsoCtt())) == 0 &&
        (ret = writer->WriteElementString("Country", obj->GetAuthenticationMechanismName().GetCountry())) == 0 &&
        (ret = writer->WriteElementString("CountryName", obj->GetAuthenticationMechanismName().GetCountryName())) == 0 &&
        (ret = writer->WriteElementString("IdentifiedOrganization", obj->GetAuthenticationMechanismName().GetIdentifiedOrganization())) == 0 &&
        (ret = writer->WriteElementString("DlmsUA", obj->GetAuthenticationMechanismName().GetDlmsUA())) == 0 &&
        (ret = writer->WriteElementString("AuthenticationMechanismName", obj->GetAuthenticationMechanismName().GetAuthenticationMechanismName())) == 0 &&
        (ret = writer->WriteElementString("MechanismId", obj->GetAuthenticationMechanismName().GetMechanismId())) == 0 &&
        (ret = writer->WriteEndElement()) == 0 &&
        (ret = writer->WriteElementString("Secret", obj->GetSecret().ToHexString())) == 0 &&
        (ret = writer->WriteElementString("AssociationStatus", obj->GetAssociationStatus())) == 0)
    {
        if (obj->GetSecuritySetupReference().size() == 0)
        {
            ret = writer->WriteElementString("SecuritySetupReference", "0.0.0.0.0.0");
        }
        else
        {
            ret = writer->WriteElementString("SecuritySetupReference", obj->GetSecuritySetupReference());
        }
    }
    return ret;
}

#endif //DLMS_IGNORE_ASSOCIATION_LOGICAL_NAME

#ifndef DLMS_IGNORE_ASSOCIATION_SHORT_NAME
int SaveAssociationShortName(CGXXmlWriter* writer, CGXDLMSAssociationShortName* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Secret", obj->GetSecret().ToHexString())) == 0)
    {
        ret = writer->WriteElementString("SecuritySetupReference", obj->GetSecuritySetupReference());
    }
    return ret;
}
#endif //DLMS_IGNORE_ASSOCIATION_SHORT_NAME

#ifndef DLMS_IGNORE_AUTO_ANSWER
int SaveAutoAnswer(CGXXmlWriter* writer, CGXDLMSAutoAnswer* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Mode", obj->GetMode())) == 0 &&
        (ret = writer->WriteStartElement("ListeningWindow")) == 0)
    {
        for (std::vector<std::pair< CGXDateTime, CGXDateTime> >::iterator it = obj->GetListeningWindow().begin(); it != obj->GetListeningWindow().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Start", it->first)) != 0 ||
                (ret = writer->WriteElementString("End", it->second)) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if ((ret == 0))
        {
            if ((ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteElementString("Status", obj->GetStatus())) == 0 &&
                (ret = writer->WriteElementString("NumberOfCalls", obj->GetNumberOfCalls())) == 0 &&
                (ret = writer->WriteElementString("NumberOfRingsInListeningWindow", obj->GetNumberOfRingsInListeningWindow())) == 0 &&
                (ret = writer->WriteElementString("NumberOfRingsOutListeningWindow", obj->GetNumberOfRingsOutListeningWindow())) == 0)
            {

            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_AUTO_ANSWER

#ifndef DLMS_IGNORE_AUTO_CONNECT
int SaveAutoConnect(CGXXmlWriter* writer, CGXDLMSAutoConnect* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Mode", obj->GetMode())) == 0 &&
        (ret = writer->WriteElementString("Repetitions", obj->GetRepetitions())) == 0 &&
        (ret = writer->WriteElementString("RepetitionDelay", obj->GetRepetitionDelay())) == 0 &&
        (ret = writer->WriteStartElement("CallingWindow")) == 0)
    {
        for (std::vector<std::pair< CGXDateTime, CGXDateTime> >::iterator it = obj->GetCallingWindow().begin(); it != obj->GetCallingWindow().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Start", it->first)) != 0 ||
                (ret = writer->WriteElementString("End", it->second)) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((writer->WriteEndElement()) == 0)
            {
                std::string str;
                GXHelpers::Join(";", obj->GetDestinations(), str);
                ret = writer->WriteElementString("Destinations", str);
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_AUTO_CONNECT

#ifndef DLMS_IGNORE_CLOCK
int SaveClock(CGXXmlWriter* writer, CGXDLMSClock* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Time", obj->GetTime())) == 0 &&
        (ret = writer->WriteElementString("TimeZone", obj->GetTimeZone())) == 0 &&
        (ret = writer->WriteElementString("Status", obj->GetStatus())) == 0 &&
        (ret = writer->WriteElementString("Begin", obj->GetBegin())) == 0 &&
        (ret = writer->WriteElementString("End", obj->GetEnd())) == 0 &&
        (ret = writer->WriteElementString("Deviation", obj->GetDeviation())) == 0 &&
        (ret = writer->WriteElementString("Enabled", obj->GetEnabled())) == 0 &&
        (ret = writer->WriteElementString("ClockBase", obj->GetClockBase())) == 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_CLOCK

#ifndef DLMS_IGNORE_DATA
int SaveData(CGXXmlWriter* writer, CGXDLMSData* obj)
{
    int ret;
    DLMS_DATA_TYPE dt, uiDt;
    if ((ret = obj->GetDataType(2, dt)) != 0 ||
        (ret = obj->GetUIDataType(2, uiDt)) != 0 ||
        (ret = writer->WriteElementObject("Value", obj->GetValue(), dt, uiDt)) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_DATA

#ifndef DLMS_IGNORE_DEMAND_REGISTER
int SaveDemandRegister(CGXXmlWriter* writer, CGXDLMSDemandRegister* obj)
{
    int ret;
    if ((ret = writer->WriteElementObject("CurrentAverageValue", obj->GetCurrentAverageValue())) != 0 ||
        (ret = writer->WriteElementObject("LastAverageValue", obj->GetLastAverageValue())) != 0 ||
        (ret = writer->WriteElementString("Scaler", obj->GetScaler(), 1)) != 0 ||
        (ret = writer->WriteElementString("Unit", obj->GetUnit())) != 0 ||
        (ret = writer->WriteElementObject("Status", obj->GetStatus())) != 0 ||
        (ret = writer->WriteElementString("CaptureTime", obj->GetCaptureTime())) != 0 ||
        (ret = writer->WriteElementString("StartTimeCurrent", obj->GetStartTimeCurrent())) != 0 ||
        (ret = writer->WriteElementString("Period", obj->GetPeriod())) != 0 ||
        (ret = writer->WriteElementString("NumberOfPeriods", obj->GetNumberOfPeriods())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_DEMAND_REGISTER

#ifndef DLMS_IGNORE_MAC_ADDRESS_SETUP
int SaveMacAddressSetup(CGXXmlWriter* writer, CGXDLMSMacAddressSetup* obj)
{
    return writer->WriteElementString("MacAddress", obj->GetMacAddress());
}
#endif //DLMS_IGNORE_MAC_ADDRESS_SETUP

#ifndef DLMS_IGNORE_EXTENDED_REGISTER
int SaveExtendedRegister(CGXXmlWriter* writer, CGXDLMSExtendedRegister* obj)
{
    int ret;
    DLMS_DATA_TYPE dt, uiDt;
    CGXDLMSVariant value = obj->GetValue();
    if ((ret = writer->WriteElementString("Unit", obj->GetUnit())) != 0 ||
        (ret = writer->WriteElementString("Scaler", obj->GetScaler(), 1)) != 0 ||
        (ret = obj->GetDataType(2, dt)) != 0 ||
        (ret = obj->GetUIDataType(2, uiDt)) != 0 ||
        (ret = writer->WriteElementObject("Value", value, dt, uiDt)) != 0 ||
        (ret = writer->WriteElementObject("Status", obj->GetStatus())) != 0 ||
        (ret = writer->WriteElementString("CaptureTime", obj->GetCaptureTime())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_EXTENDED_REGISTER

#ifndef DLMS_IGNORE_GPRS_SETUP
int SaveGprsSetup(CGXXmlWriter* writer, CGXDLMSGPRSSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("APN", obj->GetAPN())) != 0 ||
        (ret = writer->WriteElementString("PINCode", obj->GetPINCode())) != 0 ||
        (ret = writer->WriteStartElement("DefaultQualityOfService")) != 0 ||
        (ret = writer->WriteElementString("Precedence", obj->GetDefaultQualityOfService().GetPrecedence())) != 0 ||
        (ret = writer->WriteElementString("Delay", obj->GetDefaultQualityOfService().GetDelay())) != 0 ||
        (ret = writer->WriteElementString("Reliability", obj->GetDefaultQualityOfService().GetReliability())) != 0 ||
        (ret = writer->WriteElementString("PeakThroughput", obj->GetDefaultQualityOfService().GetPeakThroughput())) != 0 ||
        (ret = writer->WriteElementString("MeanThroughput", obj->GetDefaultQualityOfService().GetMeanThroughput())) != 0 ||
        (ret = writer->WriteEndElement()) != 0 ||
        (ret = writer->WriteStartElement("RequestedQualityOfService")) != 0 ||
        (ret = writer->WriteElementString("Precedence", obj->GetRequestedQualityOfService().GetPrecedence())) != 0 ||
        (ret = writer->WriteElementString("Delay", obj->GetRequestedQualityOfService().GetDelay())) != 0 ||
        (ret = writer->WriteElementString("Reliability", obj->GetRequestedQualityOfService().GetReliability())) != 0 ||
        (ret = writer->WriteElementString("PeakThroughput", obj->GetRequestedQualityOfService().GetPeakThroughput())) != 0 ||
        (ret = writer->WriteElementString("MeanThroughput", obj->GetRequestedQualityOfService().GetMeanThroughput())) != 0 ||
        (ret = writer->WriteEndElement()) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_GPRS_SETUP

#ifndef DLMS_IGNORE_IEC_HDLC_SETUP
int SaveIecHdlcSetup(CGXXmlWriter* writer, CGXDLMSIecHdlcSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Speed", obj->GetCommunicationSpeed(), DLMS_BAUD_RATE_9600)) != 0 ||
        (ret = writer->WriteElementString("WindowSizeTx", obj->GetWindowSizeTransmit(), 1)) != 0 ||
        (ret = writer->WriteElementString("WindowSizeRx", obj->GetWindowSizeReceive(), 1)) != 0 ||
        (ret = writer->WriteElementString("MaximumInfoLengthTx", obj->GetMaximumInfoLengthTransmit(), 0x80)) != 0 ||
        (ret = writer->WriteElementString("MaximumInfoLengthRx", obj->GetMaximumInfoLengthReceive(), 0x80)) != 0 ||
        (ret = writer->WriteElementString("InterCharachterTimeout", obj->GetInterCharachterTimeout(), 30)) != 0 ||
        (ret = writer->WriteElementString("InactivityTimeout", obj->GetInactivityTimeout(), 120)) != 0 ||
        (ret = writer->WriteElementString("DeviceAddress", obj->GetDeviceAddress(), 0)) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_IEC_HDLC_SETUP

#ifndef DLMS_IGNORE_IEC_LOCAL_PORT_SETUP
int SaveIecLocalPortSetup(CGXXmlWriter* writer, CGXDLMSIECLocalPortSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("DefaultMode", obj->GetDefaultMode())) != 0 ||
        (ret = writer->WriteElementString("DefaultBaudrate", obj->GetDefaultBaudrate())) != 0 ||
        (ret = writer->WriteElementString("ProposedBaudrate", obj->GetProposedBaudrate())) != 0 ||
        (ret = writer->WriteElementString("ResponseTime", obj->GetResponseTime())) != 0 ||
        (ret = writer->WriteElementString("DeviceAddress", obj->GetDeviceAddress())) != 0 ||
        (ret = writer->WriteElementString("Password1", obj->GetPassword1())) != 0 ||
        (ret = writer->WriteElementString("Password2", obj->GetPassword2())) != 0 ||
        (ret = writer->WriteElementString("Password5", obj->GetPassword5())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_IEC_LOCAL_PORT_SETUP

int SaveIecTwistedPairSetup(CGXXmlWriter* writer, CGXDLMSIecTwistedPairSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Mode", (int)obj->GetMode())) == 0 &&
        (ret = writer->WriteElementString("Speed", (int)obj->GetSpeed())) == 0)
    {
        CGXByteBuffer bb;
        for (std::vector<unsigned char>::iterator it = obj->GetPrimaryAddresses().begin();
            it != obj->GetPrimaryAddresses().end(); ++it)
        {
            bb.SetUInt8(*it);
        }
        if ((ret = writer->WriteElementString("PrimaryAddresses", bb.ToHexString(true))) == 0)
        {
            bb.Clear();
            for (std::vector<char>::iterator it = obj->GetTabis().begin();
                it != obj->GetTabis().end(); ++it)
            {
                bb.SetUInt8(*it);
            }
            ret = writer->WriteElementString("LN", bb.ToHexString(true));
        }
    }
    return ret;
}

#ifndef DLMS_IGNORE_IP4_SETUP
int SaveIp4Setup(CGXXmlWriter* writer, CGXDLMSIp4Setup* obj)
{
    int ret;
    std::string str;
    obj->GetIPAddress(str);
    if ((ret = writer->WriteElementString("DataLinkLayerReference", obj->GetDataLinkLayerReference())) == 0 &&
        (ret = writer->WriteElementString("IPAddress", str)) == 0 &&
        (ret = writer->WriteStartElement("MulticastIPAddress")) == 0)
    {
        for (std::vector<unsigned int>::iterator it = obj->GetMulticastIPAddress().begin(); it != obj->GetMulticastIPAddress().end(); ++it)
        {
            if ((ret = writer->WriteElementString("Value", *it)) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteStartElement("IPOptions")) == 0)
            {
                for (std::vector<CGXDLMSIp4SetupIpOption>::iterator it = obj->GetIPOptions().begin(); it != obj->GetIPOptions().end(); ++it)
                {
                    if ((ret = writer->WriteStartElement("IPOptions")) != 0 ||
                        (ret = writer->WriteElementString("Type", it->GetType())) != 0 ||
                        (ret = writer->WriteElementString("Length", it->GetLength())) != 0 ||
                        (ret = writer->WriteElementString("Data", it->GetData().ToHexString())) != 0 ||
                        (ret = writer->WriteEndElement()) != 0)
                    {
                        break;
                    }
                }
                if (ret == 0)
                {
                    obj->GetSubnetMask(str);
                    if ((ret = writer->WriteEndElement()) == 0 &&
                        (ret = writer->WriteElementString("SubnetMask", str)) == 0)
                    {
                        obj->GetGatewayIPAddress(str);
                        if ((ret = writer->WriteElementString("GatewayIPAddress", str)) == 0)
                        {
                            obj->GetPrimaryDNSAddress(str);
                            if ((ret = writer->WriteElementString("UseDHCP", obj->GetUseDHCP())) == 0 &&
                                (ret = writer->WriteElementString("PrimaryDNSAddress", str)) == 0)
                            {
                                obj->GetSecondaryDNSAddress(str);
                                ret = writer->WriteElementString("SecondaryDNSAddress", str);
                            }
                        }
                    }
                }
            }
        }
    }
    return ret;
}

#endif //DLMS_IGNORE_IP4_SETUP

#ifndef DLMS_IGNORE_IP6_SETUP
int SaveIPAddress(CGXXmlWriter* writer, std::vector<IN6_ADDR>& list, const char* name)
{
    char tmp[33];
    if (!list.empty())
    {
        writer->WriteStartElement(name);
        for (std::vector<IN6_ADDR>::iterator it = list.begin(); it != list.end(); ++it)
        {
            inet_ntop(AF_INET6, &(*it), tmp, sizeof(tmp));
            writer->WriteElementString("Value", tmp);
        }
        writer->WriteEndElement();
    }
    return 0;
}

int SaveNeighborDiscoverySetup(CGXXmlWriter* writer, std::vector<CGXNeighborDiscoverySetup*>& list, const char* name)
{
    if (!list.empty())
    {
        writer->WriteStartElement(name);
        for (std::vector<CGXNeighborDiscoverySetup*>::iterator it = list.begin(); it != list.end(); ++it)
        {
            writer->WriteStartElement("Item");
            writer->WriteElementString("MaxRetry", (*it)->GetMaxRetry());
            writer->WriteElementString("RetryWaitTime", (*it)->GetRetryWaitTime());
            writer->WriteElementString("SendPeriod", (*it)->GetSendPeriod());
            writer->WriteEndElement();
        }
        writer->WriteEndElement();
    }
    return 0;
}

int SaveIp6Setup(CGXXmlWriter* writer, CGXDLMSIp6Setup* obj)
{
    int ret;
    char tmp[64];
    std::string str;
    if ((ret = writer->WriteElementString("DataLinkLayerReference", obj->GetDataLinkLayerReference())) == 0 &&
        (ret = writer->WriteElementString("AddressConfigMode", obj->GetAddressConfigMode())) == 0 &&
        (ret = SaveIPAddress(writer, obj->GetUnicastIPAddress(), "UnicastIPAddress")) == 0 &&
        (ret = SaveIPAddress(writer, obj->GetMulticastIPAddress(), "MulticastIPAddress")) == 0 &&
        (ret = SaveIPAddress(writer, obj->GetGatewayIPAddress(), "GatewayIPAddress")) == 0)
    {
        inet_ntop(AF_INET6, &obj->GetPrimaryDNSAddress(), tmp, sizeof(tmp));
        if ((ret = writer->WriteElementString("PrimaryDNSAddress", tmp)) == 0)
        {
            inet_ntop(AF_INET6, &obj->GetSecondaryDNSAddress(), tmp, sizeof(tmp));
            if ((ret = writer->WriteElementString("SecondaryDNSAddress", tmp)) == 0 &&
                (ret = writer->WriteElementString("TrafficClass", obj->GetTrafficClass())) == 0 &&
                (ret = SaveNeighborDiscoverySetup(writer, obj->GetNeighborDiscoverySetup(), "NeighborDiscoverySetup")) == 0)
            {
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_IP6_SETUP

#ifndef DLMS_IGNORE_GSM_DIAGNOSTIC
int SaveGSMDiagnostic(CGXXmlWriter* writer, CGXDLMSGSMDiagnostic* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Operator", obj->GetOperator())) == 0 &&
        (ret = writer->WriteElementString("Status", obj->GetStatus())) == 0 &&
        (ret = writer->WriteElementString("CircuitSwitchStatus", obj->GetCircuitSwitchStatus())) == 0 &&
        (ret = writer->WriteElementString("PacketSwitchStatus", obj->GetPacketSwitchStatus())) == 0 &&
        (ret = writer->WriteStartElement("CellInfo")) == 0 &&
        (ret = writer->WriteElementString("CellId", obj->GetCellInfo().GetCellId())) == 0 &&
        (ret = writer->WriteElementString("LocationId", obj->GetCellInfo().GetLocationId())) == 0 &&
        (ret = writer->WriteElementString("SignalQuality", obj->GetCellInfo().GetSignalQuality())) == 0 &&
        (ret = writer->WriteElementString("Ber", obj->GetCellInfo().GetBer())) == 0 &&
        (ret = writer->WriteEndElement()) == 0 &&
        (ret = writer->WriteStartElement("AdjacentCells")) == 0)
    {
        for (std::vector<GXAdjacentCell*>::iterator it = obj->GetAdjacentCells().begin(); it != obj->GetAdjacentCells().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("CellId", (*it)->GetCellId())) != 0 ||
                (ret = writer->WriteElementString("SignalQuality", (*it)->GetSignalQuality())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0)
            {
                ret = writer->WriteElementString("CaptureTime", obj->GetCaptureTime());
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_GSM_DIAGNOSTIC

#ifndef DLMS_IGNORE_MBUS_SLAVE_PORT_SETUP
int SaveMBusSlavePortSetup(CGXXmlWriter* writer, CGXDLMSMBusSlavePortSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("DefaultBaud", obj->GetDefaultBaud())) != 0 ||
        (ret = writer->WriteElementString("AvailableBaud", obj->GetAvailableBaud())) != 0 ||
        (ret = writer->WriteElementString("AddressState", obj->GetAddressState())) != 0 ||
        (ret = writer->WriteElementString("BusAddress", obj->GetBusAddress())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_MBUS_SLAVE_PORT_SETUP

#ifndef DLMS_IGNORE_MODEM_CONFIGURATION
int SaveModemConfiguration(CGXXmlWriter* writer, CGXDLMSModemConfiguration* obj)
{
    int ret;
    std::string str;
    if ((ret = writer->WriteElementString("CommunicationSpeed", obj->GetCommunicationSpeed(), DLMS_BAUD_RATE_300)) == 0 &&
        (ret = writer->WriteStartElement("InitialisationStrings")) == 0)
    {
        for (std::vector<CGXDLMSModemInitialisation>::iterator it = obj->GetInitialisationStrings().begin(); it != obj->GetInitialisationStrings().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Initialisation")) != 0 ||
                (ret = writer->WriteElementString("Request", it->GetRequest())) != 0 ||
                (ret = writer->WriteElementString("Response", it->GetResponse())) != 0 ||
                (ret = writer->WriteElementString("Delay", it->GetDelay())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0)
            {
                GXHelpers::Join(";", obj->GetModemProfile(), str);
                ret = writer->WriteElementString("ModemProfile", str);
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_MODEM_CONFIGURATION

#ifndef DLMS_IGNORE_PUSH_SETUP
int SavePushSetup(CGXXmlWriter* writer, CGXDLMSPushSetup* obj)
{
    int ret;
    std::string str;
    if ((ret = writer->WriteStartElement("ObjectList")) == 0)
    {
        for (std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject> >::iterator it = obj->GetPushObjectList().begin(); it != obj->GetPushObjectList().end(); ++it)
        {
            it->first->GetLogicalName(str);
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("ObjectType", it->first->GetObjectType())) != 0 ||
                (ret = writer->WriteElementString("LN", str)) != 0 ||
                (ret = writer->WriteElementString("AI", it->second.GetAttributeIndex())) != 0 ||
                (ret = writer->WriteElementString("DI", it->second.GetDataIndex())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteElementString("Service", (int)obj->GetService())) == 0 &&
                (ret = writer->WriteElementString("Destination", obj->GetDestination())) == 0 &&
                (ret = writer->WriteElementString("Message", obj->GetMessageType())) == 0 &&
                (ret = writer->WriteStartElement("CommunicationWindow")) == 0)
            {
                for (std::vector<std::pair<CGXDateTime, CGXDateTime> >::iterator it = obj->GetCommunicationWindow().begin(); it != obj->GetCommunicationWindow().end(); ++it)
                {
                    if ((ret = writer->WriteStartElement("Item")) != 0 ||
                        (ret = writer->WriteElementString("Start", it->first)) != 0 ||
                        (ret = writer->WriteElementString("End", it->second)) != 0 ||
                        (ret = writer->WriteEndElement()) != 0)
                    {
                        break;
                    }
                }
                if (ret == 0)
                {
                    if ((ret = writer->WriteEndElement()) != 0 ||
                        (ret = writer->WriteElementString("RandomisationStartInterval", obj->GetRandomisationStartInterval())) != 0 ||
                        (ret = writer->WriteElementString("NumberOfRetries", obj->GetNumberOfRetries())) != 0 ||
                        (ret = writer->WriteElementString("RepetitionDelay", obj->GetRepetitionDelay())) != 0)
                    {
                    }
                }
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_PUSH_SETUP

#ifndef DLMS_IGNORE_PPP_SETUP
int SavePppSetup(CGXXmlWriter* writer, CGXDLMSPppSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("PHYReference", obj->GetPHYReference())) == 0 &&
        (ret = writer->WriteStartElement("LCPOptions")) == 0)
    {
        for (std::vector<CGXDLMSPppSetupLcpOption>::iterator it = obj->GetLCPOptions().begin(); it != obj->GetLCPOptions().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Type", it->GetType())) != 0 ||
                (ret = writer->WriteElementString("Length", it->GetLength())) != 0 ||
                (ret = writer->WriteElementObject("Data", it->GetData())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteStartElement("IPCPOptions")) == 0)
            {
                for (std::vector<CGXDLMSPppSetupIPCPOption>::iterator it = obj->GetIPCPOptions().begin(); it != obj->GetIPCPOptions().end(); ++it)
                {
                    if ((ret = writer->WriteStartElement("Item")) != 0 ||
                        (ret = writer->WriteElementString("Type", it->GetType())) != 0 ||
                        (ret = writer->WriteElementString("Length", it->GetLength())) != 0 ||
                        (ret = writer->WriteElementObject("Data", it->GetData())) != 0 ||
                        (ret = writer->WriteEndElement()) != 0)
                    {
                        break;
                    }
                }
                if (ret == 0)
                {
                    if ((ret = writer->WriteEndElement()) != 0 ||
                        (ret = writer->WriteElementString("UserName", obj->GetUserName().ToHexString())) != 0 ||
                        (ret = writer->WriteElementString("Password", obj->GetPassword().ToHexString())) != 0)
                    {

                    }
                }
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_PPP_SETUP

#ifndef DLMS_IGNORE_PROFILE_GENERIC
int SaveProfileGeneric(CGXXmlWriter* writer, CGXDLMSProfileGeneric* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("Buffer")) == 0)
    {
        /*
        GXDateTime lastdt = NULL;
        int add = CapturePeriod;
        //Some meters are returning 0 if capture period is one hour.
        if (add == 0)
        {
            add = 60;
        }
        //Get data types.
        List<DataType> list = new List<DataType>();
        if (CaptureObjects != NULL && CaptureObjects.Count != 0)
        {
            foreach(var it in CaptureObjects)
            {
                if (it.Value.AttributeIndex == 0)
                {
                    list.Add(it.Key.GetDataType(it.Value.AttributeIndex));
                }
                else
                {
                    list.Add(DataType.None);
                }
            }
        }
        foreach(object[] row in Buffer)
        {
            writer->WriteStartElement("Row");
            int pos = 0;
            foreach(object it in row)
            {
                //If capture objects is not read.
                if (CaptureObjects.Count > pos)
                {
                    GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject> c = CaptureObjects[pos];
                    ++pos;
                    if (CaptureObjects != NULL && c.Key is GXDLMSClock && c.Value.AttributeIndex == 2)
                    {
                        if (it != NULL)
                        {
                            lastdt = (c.Key as GXDLMSClock).Time;
                        }
                        else if (lastdt != NULL)
                        {
                            lastdt = new GXDateTime(lastdt.Value.AddMinutes(add));
                            writer->WriteElementObject("Cell", lastdt);
                            continue;
                        }
                        else
                        {
                            writer->WriteElementObject("Cell", DateTime.MinValue);
                        }
                    }
                }
                writer->WriteElementObject("Cell", it);
            }
            ret = writer->WriteEndElement();
        }
        */
        ret = writer->WriteEndElement();
    }
    if (ret == 0)
    {
        std::string str;
        if ((ret = writer->WriteStartElement("CaptureObjects")) == 0)
        {
            for (std::vector<std::pair<CGXDLMSObject*, CGXDLMSCaptureObject*> >::iterator it = obj->GetCaptureObjects().begin();
                it != obj->GetCaptureObjects().end(); ++it)
            {
                it->first->GetLogicalName(str);
                if ((ret = writer->WriteStartElement("Item")) != 0 ||
                    (ret = writer->WriteElementString("ObjectType", it->first->GetObjectType())) != 0 ||
                    (ret = writer->WriteElementString("LN", str)) != 0 ||
                    (ret = writer->WriteElementString("Attribute", it->second->GetAttributeIndex())) != 0 ||
                    (ret = writer->WriteElementString("Data", it->second->GetDataIndex())) != 0 ||
                    (ret = writer->WriteEndElement()) != 0)
                {
                    break;
                }
            }
            if (ret == 0)
            {
                ret = writer->WriteEndElement();
            }
        }
        if (ret == 0)
        {
            std::string ln;
            DLMS_OBJECT_TYPE ot = DLMS_OBJECT_TYPE_NONE;
            if (obj->GetSortObject() != NULL)
            {
                ot = obj->GetSortObject()->GetObjectType();
                obj->GetSortObject()->GetLogicalName(ln);
            }
            if ((ret = writer->WriteElementString("CapturePeriod", obj->GetCapturePeriod())) != 0 ||
                (ret = writer->WriteElementString("SortMethod", obj->GetSortMethod())) != 0 ||
                (ret = writer->WriteStartElement("SortObject")) != 0 ||
                (ret = writer->WriteElementString("ObjectType", ot)) != 0 ||
                (ret = writer->WriteElementString("LN", ln)) != 0 ||
                (ret = writer->WriteEndElement()) != 0 ||
                (ret = writer->WriteElementString("EntriesInUse", obj->GetEntriesInUse())) != 0 ||
                (ret = writer->WriteElementString("ProfileEntries", obj->GetProfileEntries())) != 0)
            {

            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_PROFILE_GENERIC

#ifndef DLMS_IGNORE_REGISTER
int SaveRegister(CGXXmlWriter* writer, CGXDLMSRegister* obj)
{
    DLMS_DATA_TYPE dt, uiDt;
    int ret;
    if ((ret = obj->GetDataType(2, dt)) != 0 ||
        (ret = obj->GetUIDataType(2, uiDt)) != 0 ||
        (ret = writer->WriteElementString("Unit", obj->GetUnit())) != 0 ||
        (ret = writer->WriteElementString("Scaler", obj->GetScaler(), 1)) != 0 ||
        (ret = writer->WriteElementObject("Value", obj->GetValue(), dt, uiDt)) != 0)
    {
        //Error code is returned at the end of the function.
    }
    return ret;
}
#endif //DLMS_IGNORE_REGISTER

#ifndef DLMS_IGNORE_REGISTER_ACTIVATION
int SaveRegisterActivation(CGXXmlWriter* writer, CGXDLMSRegisterActivation* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("RegisterAssignment")) == 0)
    {
        for (std::vector<CGXDLMSObjectDefinition>::iterator it = obj->GetRegisterAssignment().begin(); it != obj->GetRegisterAssignment().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("ObjectType", it->GetObjectType())) != 0 ||
                (ret = writer->WriteElementString("LN", it->GetLogicalName())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteStartElement("MaskList")) == 0)
            {
                std::string str;
                for (std::vector<std::pair<CGXByteBuffer, CGXByteBuffer > >::iterator it = obj->GetMaskList().begin(); it != obj->GetMaskList().end(); ++it)
                {
                    str = it->second.ToHexString();
                    GXHelpers::Replace(str, " ", ";");
                    if ((ret = writer->WriteStartElement("Item")) != 0 ||
                        (ret = writer->WriteElementString("Mask", it->first.ToHexString())) != 0 ||
                        (ret = writer->WriteElementString("Index", str)) != 0 ||
                        (ret = writer->WriteEndElement()) != 0)
                    {
                        break;
                    }
                }
                if (ret == 0)
                {
                    if ((ret = writer->WriteEndElement()) == 0)
                    {
                        ret = writer->WriteElementString("ActiveMask", obj->GetActiveMask().ToHexString());
                    }
                }
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_REGISTER_ACTIVATION

#ifndef DLMS_IGNORE_REGISTER_MONITOR
int SaveRegisterMonitor(CGXXmlWriter* writer, CGXDLMSRegisterMonitor* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("Thresholds")) == 0)
    {
        for (std::vector<CGXDLMSVariant>::iterator it = obj->GetThresholds().begin(); it != obj->GetThresholds().end(); ++it)
        {
            if ((ret = writer->WriteElementObject("Value", *it)) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteStartElement("MonitoredValue")) == 0 &&
                (ret = writer->WriteElementString("ObjectType", obj->GetMonitoredValue().GetObjectType())) == 0 &&
                (ret = writer->WriteElementString("LN", obj->GetMonitoredValue().GetLogicalName())) == 0 &&
                (ret = writer->WriteElementString("Index", obj->GetMonitoredValue().GetAttributeIndex())) == 0 &&
                (ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteStartElement("Actions")) == 0)
            {
                for (std::vector<CGXDLMSActionSet*>::iterator it = obj->GetActions().begin(); it != obj->GetActions().end(); ++it)
                {
                    if ((ret = writer->WriteStartElement("Item")) != 0 ||
                        (ret = writer->WriteStartElement("Up")) != 0 ||
                        (ret = writer->WriteElementString("LN", (*it)->GetActionUp().GetLogicalName())) != 0 ||
                        (ret = writer->WriteElementString("Selector", (*it)->GetActionUp().GetScriptSelector())) != 0 ||
                        (ret = writer->WriteEndElement()) != 0 ||
                        (ret = writer->WriteStartElement("Down")) != 0 ||
                        (ret = writer->WriteElementString("LN", (*it)->GetActionDown().GetLogicalName())) != 0 ||
                        (ret = writer->WriteElementString("Selector", (*it)->GetActionDown().GetScriptSelector())) != 0 ||
                        (ret = writer->WriteEndElement()) != 0 ||
                        (ret = writer->WriteEndElement()) != 0)
                    {
                        break;
                    }
                }
                if (ret == 0)
                {
                    ret = writer->WriteEndElement();
                }
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_REGISTER_MONITOR

#ifndef DLMS_IGNORE_DISCONNECT_CONTROL
int SaveDisconnectControl(CGXXmlWriter* writer, CGXDLMSDisconnectControl* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("OutputState", obj->GetOutputState())) != 0 ||
        (ret = writer->WriteElementString("ControlState", obj->GetControlState(), 0)) != 0 ||
        (ret = writer->WriteElementString("ControlMode", obj->GetControlMode(), 0)) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_DISCONNECT_CONTROL

#ifndef DLMS_IGNORE_LIMITER
int SaveLimiter(CGXXmlWriter* writer, CGXDLMSLimiter* obj)
{
    int ret;
    std::string ln;
    DLMS_OBJECT_TYPE ot = DLMS_OBJECT_TYPE_NONE;
    if (obj->GetMonitoredValue() != NULL)
    {
        obj->GetMonitoredValue()->GetLogicalName(ln);
        ot = obj->GetMonitoredValue()->GetObjectType();
    }
    if ((ret = writer->WriteStartElement("MonitoredValue")) == 0 &&
        (ret = writer->WriteElementString("ObjectType", ot)) == 0 &&
        (ret = writer->WriteElementString("LN", ln)) == 0 &&
        (ret = writer->WriteEndElement()) == 0 &&
        (ret = writer->WriteElementObject("ThresholdActive", obj->GetThresholdActive())) == 0 &&
        (ret = writer->WriteElementObject("ThresholdNormal", obj->GetThresholdNormal())) == 0 &&
        (ret = writer->WriteElementObject("ThresholdEmergency", obj->GetThresholdEmergency())) == 0 &&
        (ret = writer->WriteElementString("MinOverThresholdDuration", obj->GetMinOverThresholdDuration())) == 0 &&
        (ret = writer->WriteElementString("MinUnderThresholdDuration", obj->GetMinUnderThresholdDuration())) == 0 &&
        (ret = writer->WriteStartElement("EmergencyProfile")) == 0 &&
        (ret = writer->WriteElementString("ID", obj->GetEmergencyProfile().GetID())) == 0 &&
        (ret = writer->WriteElementString("Time", obj->GetEmergencyProfile().GetActivationTime())) == 0 &&
        (ret = writer->WriteElementString("Duration", obj->GetEmergencyProfile().GetDuration())) == 0 &&
        (ret = writer->WriteEndElement()) == 0 &&
        (ret = writer->WriteStartElement("EmergencyProfileGroupIDs")) == 0)
    {
        for (std::vector<int>::iterator it = obj->GetEmergencyProfileGroupIDs().begin(); it != obj->GetEmergencyProfileGroupIDs().end(); ++it)
        {
            if ((ret = writer->WriteElementString("Value", *it)) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) != 0 ||
                (ret = writer->WriteElementString("Active", obj->GetEmergencyProfileActive())) != 0 ||
                (ret = writer->WriteStartElement("ActionOverThreshold")) != 0 ||
                (ret = writer->WriteElementString("LN", obj->GetActionOverThreshold().GetLogicalName())) != 0 ||
                (ret = writer->WriteElementString("ScriptSelector", obj->GetActionOverThreshold().GetScriptSelector())) != 0 ||
                (ret = writer->WriteEndElement()) != 0 ||
                (ret = writer->WriteStartElement("ActionUnderThreshold")) != 0 ||
                (ret = writer->WriteElementString("LN", obj->GetActionUnderThreshold().GetLogicalName())) != 0 ||
                (ret = writer->WriteElementString("ScriptSelector", obj->GetActionUnderThreshold().GetScriptSelector())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {

            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_LIMITER

#ifndef DLMS_IGNORE_MBUS_CLIENT
int SaveMBusClient(CGXXmlWriter* writer, CGXDLMSMBusClient* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("MBusPortReference", obj->GetMBusPortReference())) == 0 &&
        (ret = writer->WriteStartElement("CaptureDefinition")) == 0)
    {
        for (std::vector<std::pair<std::string, std::string> >::iterator it = obj->GetCaptureDefinition().begin(); it != obj->GetCaptureDefinition().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Data", it->first)) != 0 ||
                (ret = writer->WriteElementString("Value", it->second)) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0 &&
                (ret = writer->WriteElementString("CapturePeriod", obj->GetCapturePeriod())) == 0 &&
                (ret = writer->WriteElementString("PrimaryAddress", obj->GetPrimaryAddress())) == 0 &&
                (ret = writer->WriteElementString("IdentificationNumber", obj->GetIdentificationNumber())) == 0 &&
                (ret = writer->WriteElementString("ManufacturerID", obj->GetManufacturerID())) == 0 &&
                (ret = writer->WriteElementString("DataHeaderVersion", obj->GetDataHeaderVersion())) == 0 &&
                (ret = writer->WriteElementString("DeviceType", obj->GetDeviceType())) == 0 &&
                (ret = writer->WriteElementString("AccessNumber", obj->GetAccessNumber())) == 0 &&
                (ret = writer->WriteElementString("Status", obj->GetStatus())) == 0 &&
                (ret = writer->WriteElementString("Alarm", obj->GetAlarm())) == 0)
            {
                if (obj->GetVersion() > 0)
                {
                    if ((ret = writer->WriteElementString("Configuration", obj->GetConfiguration())) == 0)
                    {
                        ret = writer->WriteElementString("EncryptionKeyStatus", obj->GetEncryptionKeyStatus());
                    }
                }
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_MBUS_CLIENT

#ifndef DLMS_IGNORE_COMPACT_DATA
int SaveCompactData(CGXXmlWriter* writer, CGXDLMSCompactData* obj)
{
    return 0;
}
#endif //DLMS_IGNORE_COMPACT_DATA

#ifndef DLMS_IGNORE_LLC_SSCS_SETUP
int SaveLlcSscsSetup(CGXXmlWriter* writer, CGXDLMSLlcSscsSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("ServiceNodeAddress", obj->GetServiceNodeAddress())) == 0)
    {
        ret = writer->WriteElementString("BaseNodeAddress", obj->GetBaseNodeAddress());
    }
    return ret;
}
#endif //DLMS_IGNORE_LLC_SSCS_SETUP

#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_PHYSICAL_LAYER_COUNTERS

int SavePrimeNbOfdmPlcPhysicalLayerCounters(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcPhysicalLayerCounters* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("CrcIncorrectCount", obj->GetCrcIncorrectCount())) != 0 ||
        (ret = writer->WriteElementString("CrcFailedCount", obj->GetCrcFailedCount())) != 0 ||
        (ret = writer->WriteElementString("TxDropCount", obj->GetTxDropCount())) != 0 ||
        (ret = writer->WriteElementString("RxDropCount", obj->GetRxDropCount())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_PHYSICAL_LAYER_COUNTERS

#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_SETUP
int SavePrimeNbOfdmPlcMacSetup(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("MacMinSwitchSearchTime", obj->GetMacMinSwitchSearchTime())) != 0 ||
        (ret = writer->WriteElementString("MacMaxPromotionPdu", obj->GetMacMaxPromotionPdu())) != 0 ||
        (ret = writer->WriteElementString("MacPromotionPduTxPeriod", obj->GetMacPromotionPduTxPeriod())) != 0 ||
        (ret = writer->WriteElementString("MacBeaconsPerFrame", obj->GetMacBeaconsPerFrame())) != 0 ||
        (ret = writer->WriteElementString("MacScpMaxTxAttempts", obj->GetMacScpMaxTxAttempts())) != 0 ||
        (ret = writer->WriteElementString("MacCtlReTxTimer", obj->GetMacCtlReTxTimer())) != 0 ||
        (ret = writer->WriteElementString("MacMaxCtlReTx", obj->GetMacMaxCtlReTx())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_SETUP

#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS
int SavePrimeNbOfdmPlcMacFunctionalParameters(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacFunctionalParameters* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("LnId", obj->GetLnId())) != 0 ||
        (ret = writer->WriteElementString("LsId", obj->GetLsId())) != 0 ||
        (ret = writer->WriteElementString("SId", obj->GetSId())) != 0 ||
        (ret = writer->WriteElementString("SNa", obj->GetSna().ToHexString())) != 0 ||
        (ret = writer->WriteElementString("State", obj->GetState())) != 0 ||
        (ret = writer->WriteElementString("ScpLength", obj->GetScpLength())) != 0 ||
        (ret = writer->WriteElementString("NodeHierarchyLevel", obj->GetNodeHierarchyLevel())) != 0 ||
        (ret = writer->WriteElementString("BeaconSlotCount", obj->GetBeaconSlotCount())) != 0 ||
        (ret = writer->WriteElementString("BeaconRxSlot", obj->GetBeaconRxSlot())) != 0 ||
        (ret = writer->WriteElementString("BeaconTxSlot", obj->GetBeaconTxSlot())) != 0 ||
        (ret = writer->WriteElementString("BeaconRxFrequency", obj->GetBeaconRxFrequency())) != 0 ||
        (ret = writer->WriteElementString("BeaconTxFrequency", obj->GetBeaconTxFrequency())) != 0 ||
        (ret = writer->WriteElementString("Capabilities", obj->GetCapabilities())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS

#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_COUNTERS
int SavePrimeNbOfdmPlcMacCounters(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacCounters* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("TxDataPktCount", obj->GetTxDataPktCount())) != 0 ||
        (ret = writer->WriteElementString("RxDataPktCount", obj->GetRxDataPktCount())) != 0 ||
        (ret = writer->WriteElementString("TxCtrlPktCount", obj->GetTxCtrlPktCount())) != 0 ||
        (ret = writer->WriteElementString("RxCtrlPktCount", obj->GetRxCtrlPktCount())) != 0 ||
        (ret = writer->WriteElementString("CsmaFailCount", obj->GetCsmaFailCount())) != 0 ||
        (ret = writer->WriteElementString("CsmaChBusyCount", obj->GetCsmaChBusyCount())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_COUNTERS

#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA

int SaveMulticastEntries(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("MulticastEntries")) == 0)
    {
        for (std::vector<CGXMacMulticastEntry*>::iterator it = obj->GetMulticastEntries().begin(); it != obj->GetMulticastEntries().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Id", (*it)->GetId())) != 0 ||
                (ret = writer->WriteElementString("Members", (*it)->GetMembers())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveSwitchTable(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("SwitchTable")) == 0)
    {
        for (std::vector<short>::iterator it = obj->GetSwitchTable().begin(); it != obj->GetSwitchTable().end(); ++it)
        {
            if ((ret = writer->WriteElementString("Item", *it)) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveDirectTable(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("DirectTable")) == 0)
    {
        for (std::vector<CGXMacDirectTable*>::iterator it = obj->GetDirectTable().begin(); it != obj->GetDirectTable().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("SourceSId", (*it)->GetSourceSId())) != 0 ||
                (ret = writer->WriteElementString("SourceLnId", (*it)->GetSourceLnId())) != 0 ||
                (ret = writer->WriteElementString("SourceLcId", (*it)->GetSourceLcId())) != 0 ||
                (ret = writer->WriteElementString("DestinationSId", (*it)->GetDestinationSId())) != 0 ||
                (ret = writer->WriteElementString("DestinationLnId", (*it)->GetDestinationLnId())) != 0 ||
                (ret = writer->WriteElementString("DestinationLcId", (*it)->GetDestinationLcId())) != 0 ||
                (ret = writer->WriteElementString("Did", (*it)->GetDid().ToHexString())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveAvailableSwitches(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("AvailableSwitches")) == 0)
    {
        for (std::vector<CGXMacAvailableSwitch*>::iterator it = obj->GetAvailableSwitches().begin(); it != obj->GetAvailableSwitches().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Sna", (*it)->GetSna().ToHexString())) != 0 ||
                (ret = writer->WriteElementString("LsId", (*it)->GetLsId())) != 0 ||
                (ret = writer->WriteElementString("Level", (*it)->GetLevel())) != 0 ||
                (ret = writer->WriteElementString("RxLevel", (*it)->GetRxLevel())) != 0 ||
                (ret = writer->WriteElementString("RxSnr", (*it)->GetRxSnr())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveCommunications(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("Communications")) == 0)
    {
        for (std::vector<CGXMacPhyCommunication*>::iterator it = obj->GetCommunications().begin(); it != obj->GetCommunications().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Eui", (*it)->GetEui().ToHexString())) != 0 ||
                (ret = writer->WriteElementString("TxPower", (*it)->GetTxPower())) != 0 ||
                (ret = writer->WriteElementString("TxCoding", (*it)->GetTxCoding())) != 0 ||
                (ret = writer->WriteElementString("RxCoding", (*it)->GetRxCoding())) != 0 ||
                (ret = writer->WriteElementString("RxLvl", (*it)->GetRxLvl())) != 0 ||
                (ret = writer->WriteElementString("Snr", (*it)->GetSnr())) != 0 ||
                (ret = writer->WriteElementString("TxPowerModified", (*it)->GetTxPowerModified())) != 0 ||
                (ret = writer->WriteElementString("TxCodingModified", (*it)->GetTxCodingModified())) != 0 ||
                (ret = writer->WriteElementString("RxCodingModified", (*it)->GetRxCodingModified())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SavePrimeNbOfdmPlcMacNetworkAdministrationData(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData* obj)
{
    int ret;
    if ((ret = SaveMulticastEntries(writer, obj)) != 0 ||
        (ret = SaveSwitchTable(writer, obj)) != 0 ||
        (ret = SaveDirectTable(writer, obj)) != 0 ||
        (ret = SaveAvailableSwitches(writer, obj)) != 0 ||
        (ret = SaveCommunications(writer, obj)) != 0)
    {

    }
    return ret;
}

#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA

#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_APPLICATIONS_IDENTIFICATION
int SavePrimeNbOfdmPlcApplicationsIdentification(CGXXmlWriter* writer, CGXDLMSPrimeNbOfdmPlcApplicationsIdentification* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("FirmwareVersion", obj->GetFirmwareVersion())) != 0 ||
        (ret = writer->WriteElementString("VendorId", obj->GetVendorId())) != 0 ||
        (ret = writer->WriteElementString("ProductId", obj->GetProductId())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_APPLICATIONS_IDENTIFICATION

#ifndef DLMS_IGNORE_PARAMETER_MONITOR
int SaveParameterMonitor(CGXXmlWriter* writer, CGXDLMSParameterMonitor* obj)
{
    int ret = 0;
    std::string ln;
    if (obj->GetChangedParameter().GetTarget() != NULL)
    {
        obj->GetChangedParameter().GetTarget()->GetLogicalName(ln);
        if ((ret = writer->WriteStartElement("ChangedParameter")) != 0 ||
            (ret = writer->WriteElementString("Type", obj->GetChangedParameter().GetTarget()->GetObjectType())) != 0 ||
            (ret = writer->WriteElementString("LN", ln)) != 0 ||
            (ret = writer->WriteElementString("Index", obj->GetChangedParameter().GetAttributeIndex())) != 0 ||
            (ret = writer->WriteElementObject("Value", obj->GetChangedParameter().GetValue())) != 0 ||
            (ret = writer->WriteEndElement()) != 0)
        {

        }
    }
    if (ret == 0)
    {
        if ((ret = writer->WriteElementString("Time", obj->GetCaptureTime())) == 0 &&
            (ret = writer->WriteStartElement("Parameters")) == 0)
        {
            for (std::vector<CGXDLMSTarget*>::iterator it = obj->GetParameters().begin(); it != obj->GetParameters().end(); ++it)
            {
                (*it)->GetTarget()->GetLogicalName(ln);
                if ((ret = writer->WriteStartElement("Item")) != 0 ||
                    (ret = writer->WriteElementString("Type", (*it)->GetTarget()->GetObjectType())) != 0 ||
                    (ret = writer->WriteElementString("LN", ln)) != 0 ||
                    (ret = writer->WriteElementString("Index", (*it)->GetAttributeIndex())) != 0 ||
                    (ret = writer->WriteEndElement()) != 0)
                {
                    break;
                }
            }
            if (ret == 0)
            {
                ret = writer->WriteEndElement();
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_PARAMETER_MONITOR

/*
int SaveWirelessModeQchannel(CGXXmlWriter* writer, CGXDLMSWirelessModeQchannel* obj)
{
    return writer->WriteElementString("AddressState", obj->GetAddressState());
}
*/

#ifndef DLMS_IGNORE_MBUS_MASTER_PORT_SETUP
int SaveMBusMasterPortSetup(CGXXmlWriter* writer, CGXDLMSMBusMasterPortSetup* obj)
{
    return writer->WriteElementString("CommSpeed", obj->GetCommSpeed(), DLMS_BAUD_RATE_2400);
}
#endif //DLMS_IGNORE_MBUS_MASTER_PORT_SETUP

/*
#ifndef DLMS_IGNORE_REGISTER_TABLE
int SaveRegisterTable(CGXXmlWriter* writer, CGXDLMSRegisterTable* obj)
{
    return DLMS_ERROR_CODE_NOT_IMPLEMENTED;
}
#endif //DLMS_IGNORE_REGISTER_TABLE

#ifndef DLMS_IGNORE_ZIG_BEE_SAS_STARTUP
int SaveZigBeeSasStartup(CGXXmlWriter* writer, CGXDLMSZigBeeSasStartup* obj)
{
    return DLMS_ERROR_CODE_NOT_IMPLEMENTED;
}
#endif //DLMS_IGNORE_ZIG_BEE_SAS_STARTUP

#ifndef DLMS_IGNORE_ZIG_BEE_SAS_JOIN
int SaveZigBeeSasJoin(CGXXmlWriter* writer, CGXDLMSZigBeeSasJoin* obj)
{
}
#endif //DLMS_IGNORE_ZIG_BEE_SAS_JOIN
#ifndef DLMS_IGNORE_ZIG_BEE_SAS_APS_FRAGMENTATION
int SaveZigBeeSasApsFragmentation(CGXXmlWriter* writer, CGXDLMSZigBeeSasApsFragmentation* obj)
{
}
#endif //DLMS_IGNORE_ZIG_BEE_SAS_APS_FRAGMENTATION

#ifndef DLMS_IGNORE_ZIG_BEE_NETWORK_CONTROL
int SaveZigBeeNetworkControl(CGXXmlWriter* writer, CGXDLMSZigBeeNetworkControl* obj)
{
}
#endif //DLMS_IGNORE_ZIG_BEE_NETWORK_CONTROL

int SaveDataProtection(CGXXmlWriter* writer, CGXDLMSDataProtection* obj)
{
}
*/

#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE1_SETUP
int SaveIec8802LlcType1Setup(CGXXmlWriter* writer, CGXDLMSIec8802LlcType1Setup* obj)
{
    return writer->WriteElementString("MaximumOctetsUiPdu", obj->GetMaximumOctetsUiPdu());
}
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE1_SETUP

#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE2_SETUP
int SaveIec8802LlcType2Setup(CGXXmlWriter* writer, CGXDLMSIec8802LlcType2Setup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("TransmitWindowSizeK", obj->GetTransmitWindowSizeK())) != 0 ||
        (ret = writer->WriteElementString("TransmitWindowSizeRW", obj->GetTransmitWindowSizeRW())) != 0 ||
        (ret = writer->WriteElementString("MaximumOctetsPdu", obj->GetMaximumOctetsPdu())) != 0 ||
        (ret = writer->WriteElementString("MaximumNumberTransmissions", obj->GetMaximumNumberTransmissions())) != 0 ||
        (ret = writer->WriteElementString("AcknowledgementTimer", obj->GetAcknowledgementTimer())) != 0 ||
        (ret = writer->WriteElementString("BitTimer", obj->GetBitTimer())) != 0 ||
        (ret = writer->WriteElementString("RejectTimer", obj->GetRejectTimer())) != 0 ||
        (ret = writer->WriteElementString("BusyStateTimer", obj->GetBusyStateTimer())) != 0)
    {

    }
    return 0;
}
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE2_SETUP

#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE3_SETUP
int SaveIec8802LlcType3Setup(CGXXmlWriter* writer, CGXDLMSIec8802LlcType3Setup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("MaximumOctetsACnPdu", obj->GetMaximumOctetsACnPdu())) != 0 ||
        (ret = writer->WriteElementString("MaximumTransmissions", obj->GetMaximumTransmissions())) != 0 ||
        (ret = writer->WriteElementString("AcknowledgementTime", obj->GetAcknowledgementTime())) != 0 ||
        (ret = writer->WriteElementString("ReceiveLifetime", obj->GetReceiveLifetime())) != 0 ||
        (ret = writer->WriteElementString("TransmitLifetime", obj->GetTransmitLifetime())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE3_SETUP

#ifndef DLMS_IGNORE_SFSK_REPORTING_SYSTEM_LIST
int SaveSFSKReportingSystemList(CGXXmlWriter* writer, CGXDLMSSFSKReportingSystemList* obj)
{
    int ret = 0;
    if ((ret = writer->WriteStartElement("ReportingSystems")) == 0)
    {
        for (std::vector<CGXByteBuffer>::iterator it = obj->GetReportingSystemList().begin(); it != obj->GetReportingSystemList().end(); ++it)
        {
            if ((ret = writer->WriteElementString("Item", it->ToHexString(false))) != 0)
            {
                break;
            }
        }
        ret = writer->WriteEndElement();
    }
    return ret;
}
#endif //DLMS_IGNORE_SFSK_REPORTING_SYSTEM_LIST

#ifndef DLMS_IGNORE_ARBITRATOR
int SaveArbitrator(CGXXmlWriter* writer, CGXDLMSArbitrator* obj)
{
    int ret = 0;
    if ((ret = writer->WriteStartElement("Actions")) == 0)
    {
        for (std::vector<CGXDLMSActionItem>::iterator it = obj->GetActions().begin();
            it != obj->GetActions().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("LN", it->GetLogicalName())) != 0 ||
                (ret = writer->WriteElementString("ScriptSelector", it->GetScriptSelector())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        ret = writer->WriteEndElement();//Actions
    }
    if (ret == 0)
    {
        ret = writer->WriteStartElement("PermissionTable");
        if (ret == 0)
        {
            for (std::vector<std::string>::iterator it = obj->GetPermissionsTable().begin();
                it != obj->GetPermissionsTable().end(); ++it)
            {
                if ((ret = writer->WriteElementString("Item", *it)) != 0)
                {
                    break;
                }
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0 &&//PermissionTable
                (ret = writer->WriteStartElement("WeightingTable")) == 0)
            {
                for (std::vector< std::vector<uint16_t> >::iterator it = obj->GetWeightingsTable().begin();
                    it != obj->GetWeightingsTable().end(); ++it)
                {
                    ret = writer->WriteStartElement("Weightings");
                    for (std::vector<uint16_t>::iterator it2 = it->begin(); it2 != it->end(); ++it2)
                    {
                        if ((ret = writer->WriteElementString("Item", *it2)) != 0)
                        {
                            break;
                        }
                    }
                    ret = writer->WriteEndElement();//Weightings
                }
            }
            if (ret == 0)
            {
                if ((ret = writer->WriteEndElement()) == 0 &&//WeightingTable
                    (ret = writer->WriteStartElement("MostRecentRequestsTable")) == 0)
                {
                    for (std::vector<std::string>::iterator it = obj->GetMostRecentRequestsTable().begin();
                        it != obj->GetMostRecentRequestsTable().end(); ++it)
                    {
                        if ((ret = writer->WriteElementString("Item", *it)) != 0)
                        {
                            break;
                        }
                    }
                    if ((ret = writer->WriteEndElement()) == 0)//MostRecentRequestsTable
                    {
                        ret = writer->WriteElementString("LastOutcome", obj->GetLastOutcome());
                    }
                }
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_ARBITRATOR

#ifndef DLMS_IGNORE_SFSK_MAC_COUNTERS
int SaveSFSKMacCounters(CGXXmlWriter* writer, CGXDLMSSFSKMacCounters* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("SynchronizationRegisters")) == 0)
    {
        for (std::vector< std::pair<uint16_t, uint32_t> >::iterator it = obj->GetSynchronizationRegister().begin();
            it != obj->GetSynchronizationRegister().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Key", it->first)) != 0 ||
                (ret = writer->WriteElementString("Value", it->second)) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) == 0)
            {
                if ((ret = writer->WriteElementString("PhysicalLayerDesynchronization", obj->GetPhysicalLayerDesynchronization())) == 0 &&
                    (ret = writer->WriteElementString("TimeOutNotAddressedDesynchronization", obj->GetTimeOutNotAddressedDesynchronization())) == 0 &&
                    (ret = writer->WriteElementString("TimeOutFrameNotOkDesynchronization", obj->GetTimeOutFrameNotOkDesynchronization())) == 0 &&
                    (ret = writer->WriteElementString("WriteRequestDesynchronization", obj->GetWriteRequestDesynchronization())) == 0 &&
                    (ret = writer->WriteElementString("WrongInitiatorDesynchronization", obj->GetWrongInitiatorDesynchronization())) == 0 &&
                    (ret = writer->WriteStartElement("BroadcastFramesCounters")) == 0)
                {
                    for (std::vector< std::pair<uint16_t, uint32_t> >::iterator it = obj->GetBroadcastFramesCounter().begin();
                        it != obj->GetBroadcastFramesCounter().end(); ++it)
                    {
                        if ((ret = writer->WriteStartElement("Item")) != 0 ||
                            (ret = writer->WriteElementString("Key", it->first)) != 0 ||
                            (ret = writer->WriteElementString("Value", it->second)) != 0 ||
                            (ret = writer->WriteEndElement()) != 0)
                        {
                            break;
                        }
                    }
                    if (ret == 0)
                    {
                        if ((ret = writer->WriteEndElement()) != 0 ||
                            (ret = writer->WriteElementString("RepetitionsCounter", obj->GetRepetitionsCounter())) != 0 ||
                            (ret = writer->WriteElementString("TransmissionsCounter", obj->GetTransmissionsCounter())) != 0 ||
                            (ret = writer->WriteElementString("CrcOkFramesCounter", obj->GetCrcOkFramesCounter())) != 0 ||
                            (ret = writer->WriteElementString("CrcNOkFramesCounter", obj->GetCrcNOkFramesCounter())) != 0)
                        {

                        }
                    }
                }
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_SFSK_MAC_COUNTERS

#ifndef DLMS_IGNORE_SFSK_MAC_SYNCHRONIZATION_TIMEOUTS
int SaveSFSKMacSynchronizationTimeouts(CGXXmlWriter* writer, CGXDLMSSFSKMacSynchronizationTimeouts* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("SearchInitiatorTimeout", obj->GetSearchInitiatorTimeout())) != 0 ||
        (ret = writer->WriteElementString("SynchronizationConfirmationTimeout", obj->GetSynchronizationConfirmationTimeout())) != 0 ||
        (ret = writer->WriteElementString("TimeOutNotAddressed", obj->GetTimeOutNotAddressed())) != 0 ||
        (ret = writer->WriteElementString("TimeOutFrameNotOK", obj->GetTimeOutFrameNotOK())) != 0)
    {
    }
    return ret;
}
#endif //DLMS_IGNORE_SFSK_MAC_SYNCHRONIZATION_TIMEOUTS

#ifndef DLMS_IGNORE_SFSK_ACTIVE_INITIATOR
int SaveSFSKActiveInitiator(CGXXmlWriter* writer, CGXDLMSSFSKActiveInitiator* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("SystemTitle", obj->GetSystemTitle().ToHexString(false))) != 0 ||
        (ret = writer->WriteElementString("MacAddress", obj->GetMacAddress())) != 0 ||
        (ret = writer->WriteElementString("LSapSelector", obj->GetLSapSelector())) != 0)
    {
    }
    return ret;
}
#endif //DLMS_IGNORE_SFSK_ACTIVE_INITIATOR

#ifndef DLMS_IGNORE_SFSK_PHY_MAC_SETUP
int SaveSFSKPhyMacSetUp(CGXXmlWriter* writer, CGXDLMSSFSKPhyMacSetUp* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("InitiatorElectricalPhase", obj->GetInitiatorElectricalPhase())) == 0 &&
        (ret = writer->WriteElementString("DeltaElectricalPhase", obj->GetDeltaElectricalPhase())) == 0 &&
        (ret = writer->WriteElementString("MaxReceivingGain", obj->GetMaxReceivingGain())) == 0 &&
        (ret = writer->WriteElementString("MaxTransmittingGain", obj->GetMaxTransmittingGain())) == 0 &&
        (ret = writer->WriteElementString("SearchInitiatorThreshold", obj->GetSearchInitiatorThreshold())) == 0 &&
        (ret = writer->WriteElementString("MarkFrequency", obj->GetMarkFrequency())) == 0 &&
        (ret = writer->WriteElementString("SpaceFrequency", obj->GetSpaceFrequency())) == 0 &&
        (ret = writer->WriteElementString("MacAddress", obj->GetMacAddress())) == 0 &&
        (ret = writer->WriteStartElement("MacGroupAddresses")) == 0)
    {
        for (std::vector<uint16_t>::iterator it = obj->GetMacGroupAddresses().begin();
            it != obj->GetMacGroupAddresses().end(); ++it)
        {
            if ((ret = writer->WriteElementString("Value", *it)) != 0)
            {
                break;
            }
        }
        if (ret == 0 &&
            (ret = writer->WriteEndElement()) == 0 &&
            (ret = writer->WriteElementString("Repeater", obj->GetRepeater())) == 0 &&
            (ret = writer->WriteElementString("RepeaterStatus", obj->GetRepeaterStatus())) == 0 &&
            (ret = writer->WriteElementString("MinDeltaCredit", obj->GetMinDeltaCredit())) == 0 &&
            (ret = writer->WriteElementString("InitiatorMacAddress", obj->GetInitiatorMacAddress())) == 0 &&
            (ret = writer->WriteElementString("SynchronizationLocked", obj->GetSynchronizationLocked())) == 0 &&
            (ret = writer->WriteElementString("TransmissionSpeed", obj->GetTransmissionSpeed())) == 0)
        {

        }
    }
    return ret;
}
#endif //DLMS_IGNORE_SFSK_PHY_MAC_SETUP

#ifndef DLMS_IGNORE_NTP_SETUP
int SaveNtpSetup(CGXXmlWriter* writer, CGXDLMSNtpSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Activated", obj->GetActivated())) == 0 &&
        (ret = writer->WriteElementString("ServerAddress", obj->GetServerAddress())) == 0 &&
        (ret = writer->WriteElementString("Port", obj->GetPort())) == 0 &&
        (ret = writer->WriteElementString("Authentication", obj->GetAuthentication())) == 0 &&
        (ret = writer->WriteStartElement("Keys")) == 0)
    {
        for (std::map<uint32_t, CGXByteBuffer>::iterator it = obj->GetKeys().begin();
            it != obj->GetKeys().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("ID", std::to_string(it->first))) != 0 ||
                (ret = writer->WriteElementString("Key", it->second.ToHexString())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            // Keys
            if ((ret = writer->WriteEndElement()) == 0)
            {
                ret = writer->WriteElementString("ClientKey", obj->GetClientKey().ToHexString());
            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_NTP_SETUP
#ifndef DLMS_IGNORE_COMMUNICATION_PORT_PROTECTION
int SaveCommunicationPortProtection(CGXXmlWriter* writer, CGXDLMSCommunicationPortProtection* obj)
{
    int ret;
    std::string ln;
    if (obj->GetPort() != NULL)
    {
        obj->GetPort()->GetLogicalName(ln);
    }
    if ((ret = writer->WriteElementString("ProtectionMode", obj->GetProtectionMode())) == 0 &&
        (ret = writer->WriteElementString("AllowedFailedAttempts", obj->GetAllowedFailedAttempts())) == 0 &&
        (ret = writer->WriteElementString("InitialLockoutTime", obj->GetInitialLockoutTime())) == 0 &&
        (ret = writer->WriteElementString("SteepnessFactor", obj->GetSteepnessFactor())) == 0 &&
        (ret = writer->WriteElementString("MaxLockoutTime", obj->GetMaxLockoutTime())) == 0 &&
        (ret = writer->WriteElementString("Port", ln)) == 0 &&
        (ret = writer->WriteElementString("ProtectionStatus", obj->GetProtectionStatus())) == 0 &&
        (ret = writer->WriteElementString("FailedAttempts", obj->GetFailedAttempts())) == 0 &&
        (ret = writer->WriteElementString("CumulativeFailedAttempts", obj->GetCumulativeFailedAttempts())) == 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_COMMUNICATION_PORT_PROTECTION

int SaveReferences(CGXXmlWriter* writer, std::vector<std::string>& list, const char* name)
{
    int ret;
    if ((ret = writer->WriteStartElement(name)) == 0)
    {
        for (std::vector<std::string>::iterator it = list.begin(); it != list.end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Name", *it)) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

#ifndef DLMS_IGNORE_TOKEN_GATEWAY
int SaveCreditChargeConfigurations(CGXXmlWriter* writer, std::vector<CGXCreditChargeConfiguration>& list)
{
    int ret;
    if ((ret = writer->WriteStartElement("CreditChargeConfigurations")) == 0)
    {
        for (std::vector<CGXCreditChargeConfiguration>::iterator it = list.begin(); it != list.end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Credit", it->GetCreditReference())) != 0 ||
                (ret = writer->WriteElementString("Charge", it->GetChargeReference())) != 0 ||
                (ret = writer->WriteElementString("Configuration", it->GetCollectionConfiguration())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

int SaveTokenGatewayConfigurations(CGXXmlWriter* writer, std::vector<CGXTokenGatewayConfiguration>& list)
{
    int ret;
    if ((ret = writer->WriteStartElement("TokenGatewayConfigurations")) == 0)
    {
        for (std::vector<CGXTokenGatewayConfiguration>::iterator it = list.begin(); it != list.end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Credit", it->GetCreditReference())) != 0 ||
                (ret = writer->WriteElementString("Token", it->GetTokenProportion())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

#endif //DLMS_IGNORE_TOKEN_GATEWAY

#ifndef DLMS_IGNORE_ACCOUNT
int SaveAccount(CGXXmlWriter* writer, CGXDLMSAccount* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("PaymentMode", obj->GetPaymentMode())) != 0 ||
        (ret = writer->WriteElementString("AccountStatus", obj->GetAccountStatus())) != 0 ||
        (ret = writer->WriteElementString("CurrentCreditInUse", obj->GetCurrentCreditInUse())) != 0 ||
        (ret = writer->WriteElementString("CurrentCreditStatus", obj->GetCurrentCreditStatus())) != 0 ||
        (ret = writer->WriteElementString("AvailableCredit", obj->GetAvailableCredit())) != 0 ||
        (ret = writer->WriteElementString("AmountToClear", obj->GetAmountToClear())) != 0 ||
        (ret = writer->WriteElementString("ClearanceThreshold", obj->GetClearanceThreshold())) != 0 ||
        (ret = writer->WriteElementString("AggregatedDebt", obj->GetAggregatedDebt())) != 0 ||
        (ret = SaveReferences(writer, obj->GetCreditReferences(), "CreditReferences")) != 0 ||
        (ret = SaveReferences(writer, obj->GetChargeReferences(), "ChargeReferences")) != 0 ||
        (ret = SaveCreditChargeConfigurations(writer, obj->GetCreditChargeConfigurations())) != 0 ||
        (ret = SaveTokenGatewayConfigurations(writer, obj->GetTokenGatewayConfigurations())) != 0 ||
        (ret = writer->WriteElementString("AccountActivationTime", obj->GetAccountActivationTime())) != 0 ||
        (ret = writer->WriteElementString("AccountClosureTime", obj->GetAccountClosureTime())) != 0 ||
        (ret = writer->WriteElementString("CurrencyName", obj->GetCurrency().GetName())) != 0 ||
        (ret = writer->WriteElementString("CurrencyScale", obj->GetCurrency().GetScale())) != 0 ||
        (ret = writer->WriteElementString("CurrencyUnit", obj->GetCurrency().GetUnit())) != 0 ||
        (ret = writer->WriteElementString("LowCreditThreshold", obj->GetLowCreditThreshold())) != 0 ||
        (ret = writer->WriteElementString("NextCreditAvailableThreshold", obj->GetNextCreditAvailableThreshold())) != 0 ||
        (ret = writer->WriteElementString("MaxProvision", obj->GetMaxProvision())) != 0 ||
        (ret = writer->WriteElementString("MaxProvisionPeriod", obj->GetMaxProvisionPeriod())) != 0)
    {
    }
    return ret;
}
#endif //DLMS_IGNORE_ACCOUNT

#ifndef DLMS_IGNORE_CREDIT
int SaveCredit(CGXXmlWriter* writer, CGXDLMSCredit* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("CurrentCreditAmount", obj->GetCurrentCreditAmount())) != 0 ||
        (ret = writer->WriteElementString("Type", obj->GetType())) != 0 ||
        (ret = writer->WriteElementString("Priority", obj->GetPriority())) != 0 ||
        (ret = writer->WriteElementString("WarningThreshold", obj->GetWarningThreshold())) != 0 ||
        (ret = writer->WriteElementString("Limit", obj->GetLimit())) != 0 ||
        (ret = writer->WriteElementString("CreditConfiguration", obj->GetCreditConfiguration())) != 0 ||
        (ret = writer->WriteElementString("Status", obj->GetStatus())) != 0 ||
        (ret = writer->WriteElementString("PresetCreditAmount", obj->GetPresetCreditAmount())) != 0 ||
        (ret = writer->WriteElementString("CreditAvailableThreshold", obj->GetCreditAvailableThreshold())) != 0 ||
        (ret = writer->WriteElementString("Period", obj->GetPeriod())) != 0)
    {
    }
    return ret;
}
#endif //DLMS_IGNORE_CREDIT

#ifndef DLMS_IGNORE_CHARGE
int SaveUnitChargeActive(CGXXmlWriter* writer, const char* name, CGXUnitCharge& charge)
{
    return 0;
}

int SaveCharge(CGXXmlWriter* writer, CGXDLMSCharge* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("TotalAmountPaid", obj->GetTotalAmountPaid())) != 0 ||
        (ret = writer->WriteElementString("ChargeType", obj->GetChargeType())) != 0 ||
        (ret = writer->WriteElementString("Priority", obj->GetPriority())) != 0 ||
        (ret = SaveUnitChargeActive(writer, "UnitChargeActive", obj->GetUnitChargeActive())) != 0 ||
        (ret = SaveUnitChargeActive(writer, "UnitChargePassive", obj->GetUnitChargePassive())) != 0 ||
        (ret = writer->WriteElementString("UnitChargeActivationTime", obj->GetUnitChargeActivationTime())) != 0 ||
        (ret = writer->WriteElementString("Period", obj->GetPeriod())) != 0 ||
        (ret = writer->WriteElementString("ChargeConfiguration", obj->GetChargeConfiguration())) != 0 ||
        (ret = writer->WriteElementString("LastCollectionTime", obj->GetLastCollectionTime())) != 0 ||
        (ret = writer->WriteElementString("LastCollectionAmount", obj->GetLastCollectionAmount())) != 0 ||
        (ret = writer->WriteElementString("TotalAmountRemaining", obj->GetTotalAmountRemaining())) != 0 ||
        (ret = writer->WriteElementString("Proportion", obj->GetProportion())) != 0)
    {
    }
    return ret;
}
#endif //DLMS_IGNORE_CHARGE

#ifndef DLMS_IGNORE_TOKEN_GATEWAY
int SaveTokenGateway(CGXXmlWriter* writer, CGXDLMSTokenGateway* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Token", obj->GetToken().ToHexString())) == 0 &&
        (ret = writer->WriteElementString("Time", obj->GetTime())) == 0 &&
        (ret = writer->WriteStartElement("Descriptions")) == 0)
    {
        for (std::vector< std::string >::iterator it = obj->GetDescriptions().begin(); it != obj->GetDescriptions().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Name", *it)) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            if ((ret = writer->WriteEndElement()) != 0 ||
                (ret = writer->WriteElementString("DeliveryMethod", obj->GetDeliveryMethod())) != 0 ||
                (ret = writer->WriteElementString("Status", obj->GetStatusCode())) != 0 ||
                (ret = writer->WriteElementString("Data", obj->GetDataValue())) != 0)
            {

            }
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_TOKEN_GATEWAY

#ifndef DLMS_IGNORE_SAP_ASSIGNMENT
int SaveSapAssignment(CGXXmlWriter* writer, CGXDLMSSapAssignment* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("SapAssignmentList")) == 0)
    {
        for (std::map<int, std::string >::iterator it = obj->GetSapAssignmentList().begin(); it != obj->GetSapAssignmentList().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("SAP", it->first)) != 0 ||
                (ret = writer->WriteElementString("LDN", it->second)) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_SAP_ASSIGNMENT

#ifndef DLMS_IGNORE_IMAGE_TRANSFER
int SaveImageTransfer(CGXXmlWriter* writer, CGXDLMSImageTransfer* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("ImageBlockSize", obj->GetImageBlockSize())) == 0 &&
        (ret = writer->WriteElementString("ImageTransferredBlocksStatus", obj->GetImageTransferredBlocksStatus())) == 0 &&
        (ret = writer->WriteElementString("ImageFirstNotTransferredBlockNumber", obj->GetImageFirstNotTransferredBlockNumber())) == 0 &&
        (ret = writer->WriteElementString("ImageTransferEnabled", obj->GetImageTransferEnabled())) == 0 &&
        (ret = writer->WriteElementString("ImageTransferStatus", obj->GetImageTransferStatus())) == 0 &&
        (ret = writer->WriteStartElement("ImageActivateInfo")) == 0)
    {
        for (std::vector<CGXDLMSImageActivateInfo*>::iterator it = obj->GetImageActivateInfo().begin(); it != obj->GetImageActivateInfo().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Size", (*it)->GetSize())) != 0 ||
                (ret = writer->WriteElementString("Identification", (*it)->GetIdentification().ToHexString())) != 0 ||
                (ret = writer->WriteElementString("Signature", (*it)->GetSignature().ToHexString())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_IMAGE_TRANSFER

#ifndef DLMS_IGNORE_SCHEDULE
int SaveSchedule(CGXXmlWriter* writer, CGXDLMSSchedule* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("Entries")) == 0)
    {
        for (std::vector<CGXDLMSScheduleEntry*>::iterator it = obj->GetEntries().begin(); it != obj->GetEntries().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Index", (*it)->GetIndex())) != 0 ||
                (ret = writer->WriteElementString("Enable", (*it)->GetEnable())) != 0 ||
                (ret = writer->WriteElementString("LogicalName", (*it)->GetLogicalName())) != 0 ||
                (ret = writer->WriteElementString("ScriptSelector", (*it)->GetScriptSelector())) != 0 ||
                (ret = writer->WriteElementString("SwitchTime", (*it)->GetSwitchTime())) != 0 ||
                (ret = writer->WriteElementString("ValidityWindow", (*it)->GetValidityWindow())) != 0 ||
                (ret = writer->WriteElementString("ExecWeekdays", (*it)->GetExecWeekdays())) != 0 ||
                (ret = writer->WriteElementString("ExecSpecDays", (*it)->GetExecSpecDays())) != 0 ||
                (ret = writer->WriteElementString("BeginDate", (*it)->GetBeginDate())) != 0 ||
                (ret = writer->WriteElementString("EndDate", (*it)->GetEndDate())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_SCHEDULE

#ifndef DLMS_IGNORE_SCRIPT_TABLE
int SaveScriptTable(CGXXmlWriter* writer, CGXDLMSScriptTable* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("Scripts")) == 0)
    {
        for (std::vector<CGXDLMSScript*>::iterator it = obj->GetScripts().begin(); it != obj->GetScripts().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Script")) == 0 &&
                (ret = writer->WriteElementString("ID", (*it)->GetID())) == 0 &&
                (ret = writer->WriteStartElement("Actions")) == 0)
            {
                for (std::vector<CGXDLMSScriptAction*>::iterator a = (*it)->GetActions().begin(); a != (*it)->GetActions().end(); ++a)
                {
                    if ((ret = writer->WriteStartElement("Action")) != 0 ||
                        (ret = writer->WriteElementString("Type", (*a)->GetType())) != 0 ||
                        (ret = writer->WriteElementString("ObjectType", (*a)->GetObjectType())) != 0 ||
                        (ret = writer->WriteElementString("LN", (*a)->GetLogicalName())) != 0 ||
                        (ret = writer->WriteElementString("Index", (*a)->GetIndex())) != 0 ||
                        (ret = writer->WriteElementString("ParameterDataType", (*a)->GetParameter().vt)) != 0 ||
                        (ret = writer->WriteElementString("Parameter", (*a)->GetParameter().ToString())) != 0 ||
                        (ret = writer->WriteEndElement()) != 0)
                    {
                        break;
                    }
                }
                if (ret == 0)
                {
                    ret = writer->WriteEndElement();//Actions
                    ret = writer->WriteEndElement();//Script
                }
            }
        }
    }
    if (ret == 0)
    {
        ret = writer->WriteEndElement();
    }
    return ret;
}
#endif //DLMS_IGNORE_SCRIPT_TABLE

/*
int SaveSmtpSetup(CGXXmlWriter* writer, CGXDLMSSmtpSetup* obj)
{
}
*/

#ifndef DLMS_IGNORE_SPECIAL_DAYS_TABLE

int SaveSpecialDaysTable(CGXXmlWriter* writer, CGXDLMSSpecialDaysTable* obj)
{
    int ret;
    if ((ret = writer->WriteStartElement("Entries")) == 0)
    {
        for (std::vector<CGXDLMSSpecialDay*>::iterator it = obj->GetEntries().begin(); it != obj->GetEntries().end(); ++it)
        {
            if ((ret = writer->WriteStartElement("Entry")) != 0 ||
                (ret = writer->WriteElementString("Index", (*it)->GetIndex())) != 0 ||
                (ret = writer->WriteElementString("Date", (*it)->GetDate())) != 0 ||
                (ret = writer->WriteElementString("DayId", (*it)->GetDayId())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        //Entries
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}
#endif //DLMS_IGNORE_SPECIAL_DAYS_TABLE

/*
int SaveStatusMapping(CGXXmlWriter* writer, CGXDLMSStatusMapping* obj)
{
}
*/

#ifndef DLMS_IGNORE_SECURITY_SETUP
int SaveSecuritySetup(CGXXmlWriter* writer, CGXDLMSSecuritySetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("SecurityPolicy", obj->GetSecurityPolicy())) == 0 &&
        (ret = writer->WriteElementString("SecuritySuite", obj->GetSecuritySuite())) == 0 &&
        (ret = writer->WriteElementString("ClientSystemTitle", obj->GetClientSystemTitle().ToHexString())) == 0 &&
        (ret = writer->WriteElementString("ServerSystemTitle", obj->GetServerSystemTitle().ToHexString())) == 0 &&
        (ret = writer->WriteStartElement("Certificates")) == 0)
    {
        for (std::vector<CGXDLMSCertificateInfo*>::iterator it = obj->GetCertificates().begin(); it != obj->GetCertificates().end(); ++it)
        {
            CGXByteBuffer sn;
            (*it)->GetSerialNumber().ToArray(sn);
            if ((ret = writer->WriteStartElement("Item")) != 0 ||
                (ret = writer->WriteElementString("Entity", (*it)->GetEntity())) != 0 ||
                (ret = writer->WriteElementString("Type", (*it)->GetType())) != 0 ||
                (ret = writer->WriteElementString("SerialNumber", sn.ToHexString(false))) != 0 ||
                (ret = writer->WriteElementString("Issuer", (*it)->GetIssuer())) != 0 ||
                (ret = writer->WriteElementString("Subject", (*it)->GetSubject())) != 0 ||
                (ret = writer->WriteElementString("SubjectAltName", (*it)->GetSubjectAltName())) != 0 ||
                (ret = writer->WriteEndElement()) != 0)
            {
                break;
            }
        }
        if (ret == 0)
        {
            ret = writer->WriteEndElement();
        }
    }
    return ret;
}

#endif //DLMS_IGNORE_SECURITY_SETUP

#ifndef DLMS_IGNORE_TCP_UDP_SETUP
int SaveTcpUdpSetup(CGXXmlWriter* writer, CGXDLMSTcpUdpSetup* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Port", obj->GetPort())) != 0 ||
        (ret = writer->WriteElementString("IPReference", obj->GetIPReference())) != 0 ||
        (ret = writer->WriteElementString("MaximumSegmentSize", obj->GetMaximumSegmentSize())) != 0 ||
        (ret = writer->WriteElementString("MaximumSimultaneousConnections", obj->GetMaximumSimultaneousConnections())) != 0 ||
        (ret = writer->WriteElementString("InactivityTimeout", obj->GetInactivityTimeout())) != 0)
    {

    }
    return ret;
}
#endif //DLMS_IGNORE_TCP_UDP_SETUP

#ifndef DLMS_IGNORE_UTILITY_TABLES
int SaveUtilityTables(CGXXmlWriter* writer, CGXDLMSUtilityTables* obj)
{
    int ret;
    if ((ret = writer->WriteElementString("Id", obj->GetTableId())) != 0 ||
        (ret = writer->WriteElementString("Buffer", obj->GetBuffer().ToHexString())) != 0)
    {
    }
    return ret;
}
#endif //DLMS_IGNORE_UTILITY_TABLES

/*
int SaveSFSKPhyMacSetUp(CGXXmlWriter* writer, CGXDLMSSFSKPhyMacSetUp* obj)
{
}
int SaveSFSKActiveInitiator(CGXXmlWriter* writer, CGXDLMSSFSKActiveInitiator* obj)
{
}
int SaveSFSKMacSynchronizationTimeouts(CGXXmlWriter* writer, CGXDLMSSFSKMacSynchronizationTimeouts* obj)
{
}
int SaveSFSKMacCounters(CGXXmlWriter* writer, CGXDLMSSFSKMacCounters* obj)
{
}
int SaveG3PlcMacLayerCounters(CGXXmlWriter* writer, CGXDLMSG3PlcMacLayerCounters* obj)
{
}
int SaveG3PlcMacSetup(CGXXmlWriter* writer, CGXDLMSG3PlcMacSetup* obj)
{
}
int SaveG3Plc6LoWPan(CGXXmlWriter* writer, CGXDLMSG3Plc6LoWPan* obj)
{
}
int SaveIEC14908Identification(CGXXmlWriter* writer, CGXDLMSIEC14908Identification* obj)
{
}
int SaveIEC14908PhysicalSetup(CGXXmlWriter* writer, CGXDLMSIEC14908PhysicalSetup* obj)
{
}
int SaveIEC14908PhysicalStatus(CGXXmlWriter* writer, CGXDLMSIEC14908PhysicalStatus* obj)
{
}

int SaveIEC14908Diagnostic(CGXXmlWriter* writer, CGXDLMSIEC14908Diagnostic* obj)
{
}

int SaveTariffPlan(CGXXmlWriter* writer, CGXDLMSTariffPlan* obj)
{

}
*/

int CGXXmlWriter::Save(CGXDLMSObject* obj)
{
    switch (obj->GetObjectType())
    {
#ifndef DLMS_IGNORE_ACTION_SCHEDULE
    case DLMS_OBJECT_TYPE_ACTION_SCHEDULE:
        return SaveActionSchedule(this, (CGXDLMSActionSchedule*)obj);
#endif //DLMS_IGNORE_ACTION_SCHEDULE
#ifndef DLMS_IGNORE_ACTIVITY_CALENDAR
    case DLMS_OBJECT_TYPE_ACTIVITY_CALENDAR:
        return SaveActivityCalendar(this, (CGXDLMSActivityCalendar*)obj);
#endif //DLMS_IGNORE_ACTIVITY_CALENDAR
#ifndef DLMS_IGNORE_ASSOCIATION_LOGICAL_NAME
    case DLMS_OBJECT_TYPE_ASSOCIATION_LOGICAL_NAME:
        return SaveAssociationLogicalName(this, (CGXDLMSAssociationLogicalName*)obj);
#endif //DLMS_IGNORE_ASSOCIATION_LOGICAL_NAME
#ifndef DLMS_IGNORE_ASSOCIATION_SHORT_NAME
    case DLMS_OBJECT_TYPE_ASSOCIATION_SHORT_NAME:
        return SaveAssociationShortName(this, (CGXDLMSAssociationShortName*)obj);
#endif //DLMS_IGNORE_ASSOCIATION_SHORT_NAME
#ifndef DLMS_IGNORE_AUTO_ANSWER
    case DLMS_OBJECT_TYPE_AUTO_ANSWER:
        return SaveAutoAnswer(this, (CGXDLMSAutoAnswer*)obj);
#endif //DLMS_IGNORE_AUTO_ANSWER
#ifndef DLMS_IGNORE_AUTO_CONNECT
    case DLMS_OBJECT_TYPE_AUTO_CONNECT:
        return SaveAutoConnect(this, (CGXDLMSAutoConnect*)obj);
#endif //DLMS_IGNORE_AUTO_CONNECT
#ifndef DLMS_IGNORE_CLOCK
    case DLMS_OBJECT_TYPE_CLOCK:
        return SaveClock(this, (CGXDLMSClock*)obj);
#endif //DLMS_IGNORE_CLOCK
#ifndef DLMS_IGNORE_DATA
    case DLMS_OBJECT_TYPE_DATA:
        return SaveData(this, (CGXDLMSData*)obj);
#endif //DLMS_IGNORE_DATA
#ifndef DLMS_IGNORE_DEMAND_REGISTER
    case DLMS_OBJECT_TYPE_DEMAND_REGISTER:
        return SaveDemandRegister(this, (CGXDLMSDemandRegister*)obj);
#endif //DLMS_IGNORE_DEMAND_REGISTER
#ifndef DLMS_IGNORE_MAC_ADDRESS_SETUP
    case DLMS_OBJECT_TYPE_MAC_ADDRESS_SETUP:
        return SaveMacAddressSetup(this, (CGXDLMSMacAddressSetup*)obj);
#endif //DLMS_IGNORE_MAC_ADDRESS_SETUP
#ifndef DLMS_IGNORE_EXTENDED_REGISTER
    case DLMS_OBJECT_TYPE_EXTENDED_REGISTER:
        return SaveExtendedRegister(this, (CGXDLMSExtendedRegister*)obj);
#endif //DLMS_IGNORE_EXTENDED_REGISTER
#ifndef DLMS_IGNORE_GPRS_SETUP
    case DLMS_OBJECT_TYPE_GPRS_SETUP:
        return SaveGprsSetup(this, (CGXDLMSGPRSSetup*)obj);
#endif //DLMS_IGNORE_GPRS_SETUP
#ifndef DLMS_IGNORE_SECURITY_SETUP
    case DLMS_OBJECT_TYPE_SECURITY_SETUP:
        return SaveSecuritySetup(this, (CGXDLMSSecuritySetup*)obj);
#endif //DLMS_IGNORE_SECURITY_SETUP
#ifndef DLMS_IGNORE_IEC_HDLC_SETUP
    case DLMS_OBJECT_TYPE_IEC_HDLC_SETUP:
        return SaveIecHdlcSetup(this, (CGXDLMSIecHdlcSetup*)obj);
#endif //DLMS_IGNORE_IEC_HDLC_SETUP
#ifndef DLMS_IGNORE_IEC_LOCAL_PORT_SETUP
    case DLMS_OBJECT_TYPE_IEC_LOCAL_PORT_SETUP:
        return SaveIecLocalPortSetup(this, (CGXDLMSIECLocalPortSetup*)obj);
#endif //DLMS_IGNORE_IEC_LOCAL_PORT_SETUP
#ifndef DLMS_IGNORE_IEC_TWISTED_PAIR_SETUP
    case DLMS_OBJECT_TYPE_IEC_TWISTED_PAIR_SETUP:
        return SaveIecTwistedPairSetup(this, (CGXDLMSIecTwistedPairSetup*)obj);
#endif //DLMS_IGNORE_IEC_TWISTED_PAIR_SETUP
#ifndef DLMS_IGNORE_IP4_SETUP
    case DLMS_OBJECT_TYPE_IP4_SETUP:
        return SaveIp4Setup(this, (CGXDLMSIp4Setup*)obj);
#endif //DLMS_IGNORE_IP4_SETUP
#ifndef DLMS_IGNORE_IP6_SETUP
    case DLMS_OBJECT_TYPE_IP6_SETUP:
        return SaveIp6Setup(this, (CGXDLMSIp6Setup*)obj);
#endif //DLMS_IGNORE_IP6_SETUP
#ifndef DLMS_IGNORE_MBUS_SLAVE_PORT_SETUP
    case DLMS_OBJECT_TYPE_MBUS_SLAVE_PORT_SETUP:
        return SaveMBusSlavePortSetup(this, (CGXDLMSMBusSlavePortSetup*)obj);
#endif //DLMS_IGNORE_MBUS_SLAVE_PORT_SETUP
#ifndef DLMS_IGNORE_IMAGE_TRANSFER
    case DLMS_OBJECT_TYPE_IMAGE_TRANSFER:
        return SaveImageTransfer(this, (CGXDLMSImageTransfer*)obj);
#endif //DLMS_IGNORE_IMAGE_TRANSFER
#ifndef DLMS_IGNORE_DISCONNECT_CONTROL
    case DLMS_OBJECT_TYPE_DISCONNECT_CONTROL:
        return SaveDisconnectControl(this, (CGXDLMSDisconnectControl*)obj);
#endif //DLMS_IGNORE_DISCONNECT_CONTROL
#ifndef DLMS_IGNORE_LIMITER
    case DLMS_OBJECT_TYPE_LIMITER:
        return SaveLimiter(this, (CGXDLMSLimiter*)obj);
#endif //DLMS_IGNORE_LIMITER
#ifndef DLMS_IGNORE_MBUS_CLIENT
    case DLMS_OBJECT_TYPE_MBUS_CLIENT:
        return SaveMBusClient(this, (CGXDLMSMBusClient*)obj);
#endif //DLMS_IGNORE_MBUS_CLIENT
#ifndef DLMS_IGNORE_MODEM_CONFIGURATION
    case DLMS_OBJECT_TYPE_MODEM_CONFIGURATION:
        return SaveModemConfiguration(this, (CGXDLMSModemConfiguration*)obj);
#endif //DLMS_IGNORE_MODEM_CONFIGURATION
#ifndef DLMS_IGNORE_PPP_SETUP
    case DLMS_OBJECT_TYPE_PPP_SETUP:
        return SavePppSetup(this, (CGXDLMSPppSetup*)obj);
#endif //DLMS_IGNORE_PPP_SETUP
#ifndef DLMS_IGNORE_PROFILE_GENERIC
    case DLMS_OBJECT_TYPE_PROFILE_GENERIC:
        return SaveProfileGeneric(this, (CGXDLMSProfileGeneric*)obj);
#endif //DLMS_IGNORE_PROFILE_GENERIC
#ifndef DLMS_IGNORE_REGISTER
    case DLMS_OBJECT_TYPE_REGISTER:
        return SaveRegister(this, (CGXDLMSRegister*)obj);
#endif //DLMS_IGNORE_REGISTER
#ifndef DLMS_IGNORE_REGISTER_ACTIVATION
    case DLMS_OBJECT_TYPE_REGISTER_ACTIVATION:
        return SaveRegisterActivation(this, (CGXDLMSRegisterActivation*)obj);
#endif //DLMS_IGNORE_REGISTER_ACTIVATION
#ifndef DLMS_IGNORE_REGISTER_MONITOR
    case DLMS_OBJECT_TYPE_REGISTER_MONITOR:
        return SaveRegisterMonitor(this, (CGXDLMSRegisterMonitor*)obj);
#endif //DLMS_IGNORE_REGISTER_MONITOR
        /*
        #ifndef DLMS_IGNORE_REGISTER_TABLE
            case DLMS_OBJECT_TYPE_REGISTER_TABLE:
                return SaveRegisterTable(this, (CGXDLMSRegisterTable*)obj);
        #endif //DLMS_IGNORE_REGISTER_TABLE
        #ifndef DLMS_IGNORE_ZIG_BEE_SAS_STARTUP
            case DLMS_OBJECT_TYPE_ZIG_BEE_SAS_STARTUP:
                return SaveZigBeeSasStartup(this, (CGXDLMSZigBeeSasStartup*)obj);
        #endif //DLMS_IGNORE_ZIG_BEE_SAS_STARTUP
        #ifndef DLMS_IGNORE_ZIG_BEE_SAS_JOIN
            case DLMS_OBJECT_TYPE_ZIG_BEE_SAS_JOIN:
                return SaveZigBeeSasJoin(this, (CGXDLMSZigBeeSasJoin*)obj);
        #endif //DLMS_IGNORE_ZIG_BEE_SAS_JOIN
        #ifndef DLMS_IGNORE_ZIG_BEE_SAS_APS_FRAGMENTATION
            case DLMS_OBJECT_TYPE_ZIG_BEE_SAS_APS_FRAGMENTATION:
                return SaveZigBeeSasApsFragmentation(this, (CGXDLMSZigBeeSasApsFragmentation*)obj);
        #endif //DLMS_IGNORE_ZIG_BEE_SAS_APS_FRAGMENTATION
        #ifndef DLMS_IGNORE_ZIG_BEE_NETWORK_CONTROL
            case DLMS_OBJECT_TYPE_ZIG_BEE_NETWORK_CONTROL:
                return SaveZigBeeNetworkControl(this, (CGXDLMSZigBeeNetworkControl*)obj);
        #endif //DLMS_IGNORE_ZIG_BEE_NETWORK_CONTROL
        */
#ifndef DLMS_IGNORE_SAP_ASSIGNMENT
    case DLMS_OBJECT_TYPE_SAP_ASSIGNMENT:
        return SaveSapAssignment(this, (CGXDLMSSapAssignment*)obj);
#endif //DLMS_IGNORE_SAP_ASSIGNMENT
#ifndef DLMS_IGNORE_SCHEDULE
    case DLMS_OBJECT_TYPE_SCHEDULE:
        return SaveSchedule(this, (CGXDLMSSchedule*)obj);
#endif //DLMS_IGNORE_SCHEDULE
#ifndef DLMS_IGNORE_SCRIPT_TABLE
    case DLMS_OBJECT_TYPE_SCRIPT_TABLE:
        return SaveScriptTable(this, (CGXDLMSScriptTable*)obj);
#endif //DLMS_IGNORE_SCRIPT_TABLE
        /*
#ifndef DLMS_IGNORE_SMTP_SETUP
    case DLMS_OBJECT_TYPE_SMTP_SETUP:
        return SaveSMTPSetup(this, (CGXDLMSSMTPSetup*)obj);
#endif //DLMS_IGNORE_SMTP_SETUP
*/
#ifndef DLMS_IGNORE_SPECIAL_DAYS_TABLE
    case DLMS_OBJECT_TYPE_SPECIAL_DAYS_TABLE:
        return SaveSpecialDaysTable(this, (CGXDLMSSpecialDaysTable*)obj);
#endif //DLMS_IGNORE_SPECIAL_DAYS_TABLE
        /*
#ifndef DLMS_IGNORE_STATUS_MAPPING
    case DLMS_OBJECT_TYPE_STATUS_MAPPING:
        return SaveStatusMapping(this, (CGXDLMSStatusMapping*)obj);
#endif //DLMS_IGNORE_STATUS_MAPPING
*/
#ifndef DLMS_IGNORE_TCP_UDP_SETUP
    case DLMS_OBJECT_TYPE_TCP_UDP_SETUP:
        return SaveTcpUdpSetup(this, (CGXDLMSTcpUdpSetup*)obj);
#endif //DLMS_IGNORE_TCP_UDP_SETUP
#ifndef DLMS_IGNORE_UTILITY_TABLES
    case DLMS_OBJECT_TYPE_UTILITY_TABLES:
        return SaveUtilityTables(this, (CGXDLMSUtilityTables*)obj);
#endif //DLMS_IGNORE_UTILITY_TABLES
#ifndef DLMS_IGNORE_MBUS_MASTER_PORT_SETUP
    case DLMS_OBJECT_TYPE_MBUS_MASTER_PORT_SETUP:
        return SaveMBusMasterPortSetup(this, (CGXDLMSMBusMasterPortSetup*)obj);
#endif //DLMS_IGNORE_MBUS_MASTER_PORT_SETUP
        /*
#ifndef DLMS_IGNORE_MESSAGE_HANDLER
    case DLMS_OBJECT_TYPE_MESSAGE_HANDLER:
        return SaveMessageHandler(this, (CGXDLMSMessageHandler*)obj);
#endif //DLMS_IGNORE_MESSAGE_HANDLER
*/
#ifndef DLMS_IGNORE_PUSH_SETUP
    case DLMS_OBJECT_TYPE_PUSH_SETUP:
        return SavePushSetup(this, (CGXDLMSPushSetup*)obj);
#endif //DLMS_IGNORE_PUSH_SETUP
#ifndef DLMS_IGNORE_ACCOUNT
    case DLMS_OBJECT_TYPE_ACCOUNT:
        return SaveAccount(this, (CGXDLMSAccount*)obj);
#endif //DLMS_IGNORE_ACCOUNT
#ifndef DLMS_IGNORE_CREDIT
    case DLMS_OBJECT_TYPE_CREDIT:
        return SaveCredit(this, (CGXDLMSCredit*)obj);
#endif //DLMS_IGNORE_CREDIT
#ifndef DLMS_IGNORE_CHARGE
    case DLMS_OBJECT_TYPE_CHARGE:
        return SaveCharge(this, (CGXDLMSCharge*)obj);
#endif //DLMS_IGNORE_CHARGE
#ifndef DLMS_IGNORE_PARAMETER_MONITOR
    case DLMS_OBJECT_TYPE_PARAMETER_MONITOR:
        return SaveParameterMonitor(this, (CGXDLMSParameterMonitor*)obj);
#endif //DLMS_IGNORE_PARAMETER_MONITOR
#ifndef DLMS_IGNORE_TOKEN_GATEWAY
    case DLMS_OBJECT_TYPE_TOKEN_GATEWAY:
        return SaveTokenGateway(this, (CGXDLMSTokenGateway*)obj);
#endif //DLMS_IGNORE_TOKEN_GATEWAY
#ifndef DLMS_IGNORE_GSM_DIAGNOSTIC
    case DLMS_OBJECT_TYPE_GSM_DIAGNOSTIC:
        return SaveGSMDiagnostic(this, (CGXDLMSGSMDiagnostic*)obj);
#endif //DLMS_IGNORE_GSM_DIAGNOSTIC
#ifndef DLMS_IGNORE_COMPACT_DATA
    case DLMS_OBJECT_TYPE_COMPACT_DATA:
        return SaveCompactData(this, (CGXDLMSCompactData*)obj);
#endif //DLMS_IGNORE_COMPACT_DATA
#ifndef DLMS_IGNORE_LLC_SSCS_SETUP
    case DLMS_OBJECT_TYPE_LLC_SSCS_SETUP:
        return SaveLlcSscsSetup(this, (CGXDLMSLlcSscsSetup*)obj);
#endif //DLMS_IGNORE_LLC_SSCS_SETUP
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_PHYSICAL_LAYER_COUNTERS
    case DLMS_OBJECT_TYPE_PRIME_NB_OFDM_PLC_PHYSICAL_LAYER_COUNTERS:
        return SavePrimeNbOfdmPlcPhysicalLayerCounters(this, (CGXDLMSPrimeNbOfdmPlcPhysicalLayerCounters*)obj);
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_PHYSICAL_LAYER_COUNTERS
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_SETUP
    case DLMS_OBJECT_TYPE_PRIME_NB_OFDM_PLC_MAC_SETUP:
        return SavePrimeNbOfdmPlcMacSetup(this, (CGXDLMSPrimeNbOfdmPlcMacSetup*)obj);
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_SETUP
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS
    case DLMS_OBJECT_TYPE_PRIME_NB_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS:
        return SavePrimeNbOfdmPlcMacFunctionalParameters(this, (CGXDLMSPrimeNbOfdmPlcMacFunctionalParameters*)obj);
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_FUNCTIONAL_PARAMETERS
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_COUNTERS
    case DLMS_OBJECT_TYPE_PRIME_NB_OFDM_PLC_MAC_COUNTERS:
        return SavePrimeNbOfdmPlcMacCounters(this, (CGXDLMSPrimeNbOfdmPlcMacCounters*)obj);
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_COUNTERS
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA
    case DLMS_OBJECT_TYPE_PRIME_NB_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA:
        return SavePrimeNbOfdmPlcMacNetworkAdministrationData(this, (CGXDLMSPrimeNbOfdmPlcMacNetworkAdministrationData*)obj);
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_MAC_NETWORK_ADMINISTRATION_DATA
#ifndef DLMS_IGNORE_PRIME_NB_OFDM_PLC_APPLICATIONS_IDENTIFICATION
    case DLMS_OBJECT_TYPE_PRIME_NB_OFDM_PLC_APPLICATIONS_IDENTIFICATION:
        return SavePrimeNbOfdmPlcApplicationsIdentification(this, (CGXDLMSPrimeNbOfdmPlcApplicationsIdentification*)obj);
#endif //DLMS_IGNORE_PRIME_NB_OFDM_PLC_APPLICATIONS_IDENTIFICATION
#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE1_SETUP
    case DLMS_OBJECT_TYPE_IEC_8802_LLC_TYPE1_SETUP:
        return SaveIec8802LlcType1Setup(this, (CGXDLMSIec8802LlcType1Setup*)obj);
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE1_SETUP
#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE2_SETUP
    case DLMS_OBJECT_TYPE_IEC_8802_LLC_TYPE2_SETUP:
        return SaveIec8802LlcType2Setup(this, (CGXDLMSIec8802LlcType2Setup*)obj);
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE2_SETUP
#ifndef DLMS_IGNORE_IEC_8802_LLC_TYPE3_SETUP
    case DLMS_OBJECT_TYPE_IEC_8802_LLC_TYPE3_SETUP:
        return SaveIec8802LlcType3Setup(this, (CGXDLMSIec8802LlcType3Setup*)obj);
#endif //DLMS_IGNORE_IEC_8802_LLC_TYPE3_SETUP
#ifndef DLMS_IGNORE_SFSK_REPORTING_SYSTEM_LIST
    case DLMS_OBJECT_TYPE_SFSK_REPORTING_SYSTEM_LIST:
        return SaveSFSKReportingSystemList(this, (CGXDLMSSFSKReportingSystemList*)obj);
#endif //DLMS_IGNORE_SFSK_REPORTING_SYSTEM_LIST
#ifndef DLMS_IGNORE_ARBITRATOR
    case DLMS_OBJECT_TYPE_ARBITRATOR:
        return SaveArbitrator(this, (CGXDLMSArbitrator*)obj);
#endif //DLMS_IGNORE_ARBITRATOR
#ifndef DLMS_IGNORE_SFSK_MAC_COUNTERS
    case DLMS_OBJECT_TYPE_SFSK_MAC_COUNTERS:
        return SaveSFSKMacCounters(this, (CGXDLMSSFSKMacCounters*)obj);
#endif //DLMS_IGNORE_SFSK_MAC_COUNTERS
#ifndef DLMS_IGNORE_SFSK_MAC_SYNCHRONIZATION_TIMEOUTS
    case DLMS_OBJECT_TYPE_SFSK_MAC_SYNCHRONIZATION_TIMEOUTS:
        return SaveSFSKMacSynchronizationTimeouts(this, (CGXDLMSSFSKMacSynchronizationTimeouts*)obj);
#endif //DLMS_IGNORE_SFSK_MAC_SYNCHRONIZATION_TIMEOUTS
#ifndef DLMS_IGNORE_SFSK_ACTIVE_INITIATOR
    case DLMS_OBJECT_TYPE_SFSK_ACTIVE_INITIATOR:
        return SaveSFSKActiveInitiator(this, (CGXDLMSSFSKActiveInitiator*)obj);
#endif //DLMS_IGNORE_SFSK_ACTIVE_INITIATOR
#ifndef DLMS_IGNORE_SFSK_PHY_MAC_SETUP
    case DLMS_OBJECT_TYPE_SFSK_PHY_MAC_SETUP:
        return SaveSFSKPhyMacSetUp(this, (CGXDLMSSFSKPhyMacSetUp*)obj);
#endif //DLMS_IGNORE_SFSK_PHY_MAC_SETUP
#ifndef DLMS_IGNORE_NTP_SETUP
    case DLMS_OBJECT_TYPE_NTP_SETUP:
        return SaveNtpSetup(this, (CGXDLMSNtpSetup*)obj);
#endif //DLMS_IGNORE_NTP_SETUP
#ifndef DLMS_IGNORE_COMMUNICATION_PORT_PROTECTION
    case DLMS_OBJECT_TYPE_COMMUNICATION_PORT_PROTECTION:
        return SaveCommunicationPortProtection(this, (CGXDLMSCommunicationPortProtection*)obj);
#endif //DLMS_IGNORE_COMMUNICATION_PORT_PROTECTION
    default:
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
}
