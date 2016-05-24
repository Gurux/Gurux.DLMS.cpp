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

#ifndef GXDLMSCLIENT_H
#define GXDLMSCLIENT_H

#include "GXDLMS.h"
#include "GXStandardObisCodeCollection.h"
#include "GXDLMSProfileGeneric.h"

class CGXDLMSClient
{
private:
    bool m_IsAuthenticationRequired;
    CGXDLMSSettings m_Settings;
    static void UpdateOBISCodes(CGXDLMSObjectCollection& objects);
    // SN referencing
    int ParseSNObjects(CGXByteBuffer& buff, CGXDLMSObjectCollection& objects, bool onlyKnownObjects);
    /**
    * Parse LN objects.
    *
    * buff
    *            Byte stream where objects are parsed.
    * onlyKnownObjects
    *            Only known objects are parsed.
    * @return Collection of COSEM objects.
    */
    int ParseLNObjects(
        CGXByteBuffer& buff,
        CGXDLMSObjectCollection& objects,
        bool onlyKnownObjects);

    /**
    * Generates a read message.
    *
    * name : Short or Logical Name.
    * objectType : COSEM object type.
    * attributeOrdinal : Attribute index of the object.
    * data : Read data parameter.
    * reply : Generated read message(s).
    * Returns error status.
    */
    int Read(
        CGXDLMSVariant& name,
        DLMS_OBJECT_TYPE objectType,
        int attributeOrdinal,
        CGXByteBuffer* data,
        std::vector<CGXByteBuffer>& reply);

public:
    /////////////////////////////////////////////////////////////////////////////
    //Constructor
    /////////////////////////////////////////////////////////////////////////////
    CGXDLMSClient(
        bool UseLogicalNameReferencing = true,
        int ClientAddress = 16,
        int ServerAddress = 1,
        //Authentication type.
        DLMS_AUTHENTICATION authentication = DLMS_AUTHENTICATION_NONE,
        //Password if authentication is used.
        const char* password = NULL,
        DLMS_INTERFACE_TYPE intefaceType = DLMS_INTERFACE_TYPE_HDLC);

    /////////////////////////////////////////////////////////////////////////////
    //Destructor.
    /////////////////////////////////////////////////////////////////////////////
    ~CGXDLMSClient();

    bool GetUseLogicalNameReferencing();

    DLMS_INTERFACE_TYPE GetInterfaceType();

    CGXDLMSLimits& GetLimits();

    /////////////////////////////////////////////////////////////////////////////
    // Returns SNRMRequest query as byte array.
    /////////////////////////////////////////////////////////////////////////////
    // packets: Packets to send.
    // Returns: 0 if succeed. Otherwise error number.
    /////////////////////////////////////////////////////////////////////////////
    int SNRMRequest(
        std::vector<CGXByteBuffer>& packets);

    /////////////////////////////////////////////////////////////////////////////
    // Parses UAResponse.
    /////////////////////////////////////////////////////////////////////////////
    // data: Byte array containing the data from the meter.
    // Returns: 0 if succeed. Otherwise error number.
    int ParseUAResponse(
        CGXByteBuffer& data);

    /////////////////////////////////////////////////////////////////////////////
    // Returns AARQRequest query as byte array.
    /////////////////////////////////////////////////////////////////////////////
    // Packets: Packets to send.
    // Returns: 0 if succeed. Otherwise error number.
    /////////////////////////////////////////////////////////////////////////////
    int AARQRequest(
        std::vector<CGXByteBuffer>& Packets);

    /////////////////////////////////////////////////////////////////////////////
    // Parses AAREResponse byte array.
    /////////////////////////////////////////////////////////////////////////////
    // data: buffer containing the data from the meter.
    // Returns: 0 if succeed. Otherwise error number.
    /////////////////////////////////////////////////////////////////////////////
    int ParseAAREResponse(
        CGXByteBuffer& data);

    /////////////////////////////////////////////////////////////////////////////
    // Returns ReceiverReady query as byte array.
    /////////////////////////////////////////////////////////////////////////////
    // Type: type of the next requested packet.
    // Data: Data to send.
    // Returns: 0 if succeed. Otherwise error number.
    /////////////////////////////////////////////////////////////////////////////
    int ReceiverReady(
        DLMS_DATA_REQUEST_TYPES Type,
        CGXByteBuffer& Data);

    /////////////////////////////////////////////////////////////////////////////
    // Changes byte array received from the meter to given type.
    /////////////////////////////////////////////////////////////////////////////
    // value Byte array received from the meter.
    // type Wanted type.
    // returns Value changed by type.
    static int ChangeType(
        CGXByteBuffer& value,
        DLMS_DATA_TYPE type,
        CGXDLMSVariant& newValue);

    /////////////////////////////////////////////////////////////////////////////
    // Changes byte array received from the meter to given type.
    /////////////////////////////////////////////////////////////////////////////
    // value Byte array received from the meter.
    // type Wanted type.
    // returns Value changed by type.
    static int ChangeType(
        CGXDLMSVariant& value,
        DLMS_DATA_TYPE type,
        CGXDLMSVariant& newValue);

    /**
    * Parses the COSEM objects of the received data.
    *
    * data : Received data, from the device, as byte array.
    * objects : Collection of COSEM objects.
    * onlyKnownObjects : Only known objects are parsed.
    */
    int ParseObjects(
        CGXByteBuffer& data,
        CGXDLMSObjectCollection& objects,
        bool onlyKnownObjects);

    /*
    * Get Value from byte array received from the meter.
    */
    int UpdateValue(
        CGXDLMSObject& target,
        int attributeIndex,
        CGXDLMSVariant& value);

    /**
        * Get Value from byte array received from the meter.
        *
        * data
        *            Byte array received from the meter.
        * @return Received data.
        */
    int GetValue(
        CGXByteBuffer& data,
        CGXDLMSVariant& value);

    /**
    * Update list of values.
    *
    * list : List of read objects and atributes.
    * data : Received reply from the meter.
    */
    int UpdateValues(
        std::vector< std::pair<CGXDLMSObject*, int> >& list,
        CGXByteBuffer& data);

    /**
    * Generates a disconnect request.
    *
    * reply : Generated read message(s).
    * Returns error status.
    */
    int DisconnectRequest(
        std::vector<CGXByteBuffer>& packets);

    int GetData(
        CGXByteBuffer& reply,
        CGXReplyData& data);

    static std::string ObjectTypeToString(
        DLMS_OBJECT_TYPE type);

    /**
    * Reads the Association view from the device. This method is used to get
    * all objects in the device.
    *
    * reply : Generated read message(s).
    * Returns error status.
    */
    int GetObjectsRequest(
        std::vector<CGXByteBuffer>& reply);

    /**
    * Generates a read message.
    *
    * name : Short or Logical Name.
    * objectType : COSEM object type.
    * attributeOrdinal : Attribute index of the object.
    * reply : Generated read message(s).
    * Returns error status.
    */
    int Read(
        CGXDLMSVariant& name,
        DLMS_OBJECT_TYPE objectType,
        int attributeOrdinal,
        std::vector<CGXByteBuffer>& reply);

    /**
    * Generates a read message.
    *
    * @param pObject
    *            COSEM object to write.
    * @param attributeOrdinal
    *            Attribute index of the object.
    * @param reply
    *            Generated read message(s).
    * Returns error status.
    */
    int Read(
        CGXDLMSObject* pObject,
        int attributeOrdinal,
        std::vector<CGXByteBuffer>& reply);

    /**
    * Generates a write message.
    *
    * @param name
    *            Short or Logical Name.
    * @param objectType
    *            Object type.
    * @param index
    *            Attribute index where data is write.
    * @param value
    *            Data to Write.
    * @param reply
    *             Generated write message(s).
    * Returns error status.
    */
    int Write(
        CGXDLMSVariant& name,
        DLMS_OBJECT_TYPE objectType,
        int index,
        CGXDLMSVariant& data,
        std::vector<CGXByteBuffer>& reply);

    /**
     * Generates a write message.
     *
     * @param pObject
     *            COSEM object to write.
     * @param index
     *            Attribute index where data is write.
     * @param data
     *            Data to Write.
     * @param reply
     *            Generated write message(s).
     * Returns error status.
     */
    int Write(
        CGXDLMSObject* pObject,
        int index,
        CGXDLMSVariant& data,
        std::vector<CGXByteBuffer>& reply);

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
    int Method(
        CGXDLMSObject* item,
        int index,
        CGXDLMSVariant& data,
        std::vector<CGXByteBuffer>& reply);

    /**
    * Generate Method (Action) request..
    *
    * @param name
    *            Method object short name or Logical Name.
    * @param objectType
    *            Object type.
    * @param methodIndex
    *            Method index.
    * @param value
    *            Method data.
    * @param dataType
    *            Data type.
    * @return DLMS action message.
    */
    int Method(
        CGXDLMSVariant name,
        DLMS_OBJECT_TYPE objectType,
        int methodIndex,
        CGXDLMSVariant& data,
        std::vector<CGXByteBuffer>& reply);

    /**
    * Read rows by entry.
    *
    * @param pg
    *            Profile generic object to read.
    * @param index
    *            Zero bases start index.
    * @param count
    *            Rows count to read.
    * @return Read message as byte array.
    */
    int ReadRowsByEntry(
        CGXDLMSProfileGeneric* pg,
        int index,
        int count,
        std::vector<CGXByteBuffer>& reply);

    /**
     * Read rows by range. Use this method to read Profile Generic table between
     * dates.
     *
     * @param pg
     *            Profile generic object to read.
     * @param start
     *            Start time.
     * @param end
     *            End time.
     * @return Generated read message.
     */
    int ReadRowsByRange(
        CGXDLMSProfileGeneric* pg,
        struct tm* start,
        struct tm* end,
        std::vector<CGXByteBuffer>& reply);

    /**
     * Converts meter serial number to server address. Default formula is used.
     * All meters do not use standard formula or support serial number
     * addressing at all.
     *
     * @param serialNumber
     *            Meter serial number
     * @param formula
     *            Formula used to convert serial number to server address.
     *            Set to NULL if standard formula is used.
     * @return Server address.
     */

    static int GetServerAddress(
        unsigned long serialNumber,
        const char* formula = NULL);

    /**
     * Convert physical address and logical address to server address.
     *
     * @param logicalAddress
     *            Server logical address.
     * @param physicalAddress
     *            Server physical address.
     * @param addressSize
     *            Address size in bytes.
     * @return Server address.
     */
    static int  GetServerAddress(unsigned long logicalAddress,
                                 unsigned long physicalAddress,
                                 unsigned char addressSize = 0);
};
#endif //GXDLMSCLIENT_H
