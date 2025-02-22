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

#ifndef GXDLMSDLMS_SECURITYSETUP_H
#define GXDLMSDLMS_SECURITYSETUP_H

#include "GXIgnore.h"
#ifndef DLMS_IGNORE_SECURITY_SETUP
#include "GXDLMSObject.h"
#include "GXDLMSCertificateInfo.h"
#include "GXDLMSSecureClient.h"
#include "GXx509Certificate.h"

//Global key types.
typedef enum
{
    /**
    * Global unicast encryption key. <br>
    * Client and server uses this message to send Ephemeral Public Key to other
    * party.
    */
    DLMS_GLOBAL_KEY_TYPE_UNICAST_ENCRYPTION,
    /**
     * Global broadcast encryption key.
    */
    DLMS_GLOBAL_KEY_TYPE_BROADCAST_ENCRYPTION,
    /**
     * Authentication key.
    */
    DLMS_GLOBAL_KEY_TYPE_AUTHENTICATION,
    /**
     * Key Encrypting Key, also known as Master key.
    */
    DLMS_GLOBAL_KEY_TYPE_KEK
}DLMS_GLOBAL_KEY_TYPE;

/**
Online help:
http://www.gurux.fi/Gurux.DLMS.Objects.GXDLMSSecuritySetup
*/
class CGXDLMSSecuritySetup : public CGXDLMSObject
{
    DLMS_SECURITY_POLICY m_SecurityPolicy;
    DLMS_SECURITY_SUITE m_SecuritySuite;
    CGXByteBuffer m_ServerSystemTitle;
    CGXByteBuffer m_ClientSystemTitle;
    std::vector<CGXDLMSCertificateInfo*> m_Certificates;
public:
    //Constructor.
    CGXDLMSSecuritySetup();

    //SN Constructor.
    CGXDLMSSecuritySetup(std::string ln, unsigned short sn);


    //LN Constructor.
    CGXDLMSSecuritySetup(std::string ln);

    //Used security policy.
    DLMS_SECURITY_POLICY GetSecurityPolicy();

    //Used security policy.
    void SetSecurityPolicy(DLMS_SECURITY_POLICY value);

    //Used security suite.
    DLMS_SECURITY_SUITE GetSecuritySuite();

    //Used security suite.
    void SetSecuritySuite(DLMS_SECURITY_SUITE value);

    CGXByteBuffer& GetClientSystemTitle();

    void SetClientSystemTitle(CGXByteBuffer& value);

    CGXByteBuffer& GetServerSystemTitle();

    void SetServerSystemTitle(CGXByteBuffer& value);

    // Returns amount of attributes.
    int GetAttributeCount();

    // Returns amount of methods.
    int GetMethodCount();

    //Imports an X.509 v3 certificate of a public key.
    int ImportCertificate(
        CGXDLMSClient* client,
        CGXx509Certificate& certificate,
        std::vector<CGXByteBuffer>& reply);

    /////////////////////////////////////////////////////////////////////////
    /// Exports an X.509 v3 certificate from the server using entity information.
    /// 
    /// client: DLMS client that is used to generate action.
    /// entity: Certificate entity.
    /// type: Certificate type.
    /// systemTitle: System title.
    /// Returns Generated action.
    /////////////////////////////////////////////////////////////////////////
    int ExportCertificateByEntity(
        CGXDLMSClient* client,
        DLMS_CERTIFICATE_ENTITY entity,
        DLMS_CERTIFICATE_TYPE type,
        CGXByteBuffer& systemTitle,
        std::vector<CGXByteBuffer>& reply);

    /////////////////////////////////////////////////////////////////////////
    /// Exports an X.509 v3 certificate from the server using serial information.
    /// 
    /// client: DLMS client that is used to generate action.
    /// serialNumber: Serial number.
    /// issuer: Issuer
    /// Returns Generated action.
    /////////////////////////////////////////////////////////////////////////
    int ExportCertificateBySerial(
        CGXDLMSClient* client,
        CGXBigInteger& serialNumber,
        CGXByteBuffer& issuer,
        std::vector<CGXByteBuffer>& reply);

    /////////////////////////////////////////////////////////////////////////
    /// Removes X.509 v3 certificate from the server using entity.
    /// 
    /// client: DLMS client that is used to generate action.
    /// entity: Certificate entity type.
    /// type: Certificate type.
    /// systemTitle: System title.
    /// Returns Generated action.
    /////////////////////////////////////////////////////////////////////////
    int RemoveCertificateByEntity(
        CGXDLMSClient* client,
        DLMS_CERTIFICATE_ENTITY entity,
        DLMS_CERTIFICATE_TYPE type,
        CGXByteBuffer& systemTitle,
        std::vector<CGXByteBuffer>& reply);

    /////////////////////////////////////////////////////////////////////////
    /// Removes X.509 v3 certificate from the server using serial number.
    /// 
    /// client: DLMS client that is used to generate action.
    /// serialNumber: Serial number.
    /// issuer: Issuer.
    /// Returns Generated action.
    /////////////////////////////////////////////////////////////////////////
    int RemoveCertificateBySerial(
        CGXDLMSClient* client,
        CGXByteBuffer& serialNumber,
        CGXByteBuffer& issuer,
        std::vector<CGXByteBuffer>& reply);

    int Invoke(CGXDLMSSettings& settings, CGXDLMSValueEventArg& e);

    //Start to use new keys after reply is generated.
    int ApplyKeys(CGXDLMSSettings& settings, CGXDLMSValueEventArg& e);


    //Get attribute values of object.
    void GetValues(std::vector<std::string>& values);

    /////////////////////////////////////////////////////////////////////////
    // Returns collection of attributes to read.
    //
    // If attribute is static and already read or device is returned
    // HW error it is not returned.
    //
    // all: All items are returned even if they are read already.
    // attributes: Collection of attributes to read.
    void GetAttributeIndexToRead(bool all, std::vector<int>& attributes);

    int GetDataType(int index, DLMS_DATA_TYPE& type);

    // Returns value of given attribute.
    int GetValue(CGXDLMSSettings& settings, CGXDLMSValueEventArg& e);

    // Set value of given attribute.
    int SetValue(CGXDLMSSettings& settings, CGXDLMSValueEventArg& e);

    //Get certificates.
    std::vector<CGXDLMSCertificateInfo*>& GetCertificates();


    // Activates and strengthens the security policy.
    // client: DLMS client that is used to generate action.
    // security: New security level.
    // reply: Generated action.
    int Activate(
        CGXDLMSClient* client,
        DLMS_SECURITY security,
        std::vector<CGXByteBuffer>& reply);

    // Updates one or more global keys.
    // client: DLMS client that is used to generate action.
    // kek: Master key, also known as Key Encrypting Key.
    // list: List of Global key types and keys.
    // reply: Generated action.
    int GlobalKeyTransfer(
        CGXDLMSClient* client,
        CGXByteBuffer& kek,
        std::vector<std::pair<DLMS_GLOBAL_KEY_TYPE, CGXByteBuffer&> >& list,
        std::vector<CGXByteBuffer>& reply);


    /*
    * Agree on one or more symmetric keys using the key agreement algorithm.
    * client: DLMS client that is used to generate action.
    * list: List of keys.
    * reply: Generated action.
    * Returns Error code.
    */
    int KeyAgreement(
        CGXDLMSSecureClient* client,
        std::vector<std::pair<DLMS_GLOBAL_KEY_TYPE, CGXByteBuffer> > list,
        std::vector<CGXByteBuffer>& reply);
   
    /**
    * Generates an asymmetric key pair as required by the security suite.
    *
    * client: DLMS client that is used to generate action.
    * type: New certificate type.
    * reply: Generated action.
    * Returns Error code.
    */
    int GenerateKeyPair(
        CGXDLMSSecureClient* client,
        DLMS_CERTIFICATE_TYPE type,
        std::vector<CGXByteBuffer>& reply);

    /*
    * Ask Server sends the Certificate Signing Request(CSR) data.
    *
    client: DLMS client that is used to generate action.</param>
    type: identifies the key pair for which the certificate will be requested.</param>
    * reply: Generated action.
    * Returns Error code.
    */
    int GenerateCertificate(
        CGXDLMSSecureClient* client,
        DLMS_CERTIFICATE_TYPE type,
        std::vector<CGXByteBuffer>& reply);
};
#endif //DLMS_IGNORE_SECURITY_SETUP
#endif //GXDLMSDLMS_SECURITYSETUP_H