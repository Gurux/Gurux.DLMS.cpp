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

#include "../include/GXCryptoKeyParameter.h"

CGXCryptoKeyParameter::CGXCryptoKeyParameter()
{
    m_Command = 0;
    m_KeyType = DLMS_CRYPTO_KEY_TYPE_AUTHENTICATION;
    m_Operation = DLMS_EHS_OPERATION_GMAC_ENCRYPT;
    m_Security = DLMS_SECURITY_NONE;
    m_SecuritySuite = DLMS_SECURITY_SUITE_V0;
    m_SecurityPolicy = DLMS_SECURITY_POLICY_NOTHING;
    m_CertificateType = DLMS_CERTIFICATE_TYPE_DIGITAL_SIGNATURE;
    m_InvocationCounter = 0;
}

DLMS_EHS_OPERATION CGXCryptoKeyParameter::GetOperation() {
    return m_Operation;
}

void CGXCryptoKeyParameter::SetOperation(const DLMS_EHS_OPERATION value)
{
    m_Operation = value;
}

DLMS_SECURITY_SUITE CGXCryptoKeyParameter::GetSecuritySuite()
{
    return m_SecuritySuite;
}

void CGXCryptoKeyParameter::SetSecuritySuite(const DLMS_SECURITY_SUITE value)
{
    m_SecuritySuite = value;
}

DLMS_CERTIFICATE_TYPE CGXCryptoKeyParameter::GetCertificateType()
{
    return m_CertificateType;
}

void CGXCryptoKeyParameter::SetCertificateType(const DLMS_CERTIFICATE_TYPE value)
{
    m_CertificateType = value;
}

CGXByteBuffer& CGXCryptoKeyParameter::GetSystemTitle()
{
    return m_SystemTitle;
}

/**
 * @param value
 *            System title
 */
void CGXCryptoKeyParameter::SetSystemTitle(const CGXByteBuffer& value)
{
    m_SystemTitle = value;
}

CGXPrivateKey& CGXCryptoKeyParameter::GetPrivateKey()
{
    return m_PrivateKey;
}

void CGXCryptoKeyParameter::SetPrivateKey(CGXPrivateKey& value)
{
    m_PrivateKey = value;
}

CGXPublicKey& CGXCryptoKeyParameter::GetPublicKey()
{
    return m_PublicKey;
}

void CGXCryptoKeyParameter::SetPublicKey(const CGXPublicKey& value)
{
    m_PublicKey = value;
}

CGXByteBuffer& CGXCryptoKeyParameter::GetPlainText() {
    return m_PlainText;
}

void CGXCryptoKeyParameter::SetPlainText(const CGXByteBuffer& value)
{
    m_PlainText = value;
}

CGXByteBuffer& CGXCryptoKeyParameter::GetEncrypted()
{
    return m_Encrypted;
}

void CGXCryptoKeyParameter::SetEncrypted(const CGXByteBuffer& value)
{
    m_Encrypted = value;
}

DLMS_SECURITY_POLICY CGXCryptoKeyParameter::GetSecurityPolicy()
{
    return m_SecurityPolicy;
}

void CGXCryptoKeyParameter::SetSecurityPolicy(const DLMS_SECURITY_POLICY value)
{
    m_SecurityPolicy = value;
}

CGXByteBuffer& CGXCryptoKeyParameter::GetRecipientSystemTitle()
{
    return m_RecipientSystemTitle;
}

void CGXCryptoKeyParameter::SetRecipientSystemTitle(const CGXByteBuffer& value)
{
    m_RecipientSystemTitle = value;
}

CGXByteBuffer& CGXCryptoKeyParameter::GetBlockCipherKey()
{
    return m_BlockCipherKey;
}

void CGXCryptoKeyParameter::SetBlockCipherKey(const CGXByteBuffer& value)
{
    m_BlockCipherKey = value;
}

CGXByteBuffer& CGXCryptoKeyParameter::GetAuthenticationKey()
{
    return m_AuthenticationKey;
}

void CGXCryptoKeyParameter::SetAuthenticationKey(const CGXByteBuffer& value)
{
    m_AuthenticationKey = value;
}

uint32_t CGXCryptoKeyParameter::GetInvocationCounter()
{
    return m_InvocationCounter;
}

void CGXCryptoKeyParameter::SetInvocationCounter(const uint32_t value)
{
    m_InvocationCounter = value;
}

CGXByteBuffer& CGXCryptoKeyParameter::GetTransactionId()
{
    return m_TransactionId;
}

void CGXCryptoKeyParameter::SetTransactionId(CGXByteBuffer& value)
{
    m_TransactionId = value;
}

DLMS_CRYPTO_KEY_TYPE CGXCryptoKeyParameter::GetKeyType()
{
    return m_KeyType;
}

void CGXCryptoKeyParameter::SetKeyType(const DLMS_CRYPTO_KEY_TYPE value)
{
    m_KeyType = value;
}

int CGXCryptoKeyParameter::GetCommand()
{
    return m_Command;
}

void CGXCryptoKeyParameter::SetCommand(const int value)
{
    m_Command = value;
}

DLMS_SECURITY CGXCryptoKeyParameter::GetSecurity()
{
    return m_Security;
}

void CGXCryptoKeyParameter::SetSecurity(const DLMS_SECURITY value)
{
    m_Security = value;
}