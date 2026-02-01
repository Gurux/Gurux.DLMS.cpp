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

#ifndef CRYPTO_KEY_PARAMETER_H
#define CRYPTO_KEY_PARAMETER_H

#include "enums.h"
#include "GXBytebuffer.h"
#include "GXPrivateKey.h"
#include "GXPublicKey.h"
/*
 * Crypto key parameter is used to get public or private key.
 */
class CGXCryptoKeyParameter {
private:
    int m_Command;
    /*
     * Crypto key type.
     */
    DLMS_CRYPTO_KEY_TYPE m_KeyType;

    /*
     * Is data encrypted or decrypted.
     */
    DLMS_EHS_OPERATION m_Operation;

    /*
     * Encrypted data.
     */
    CGXByteBuffer m_Encrypted;

    /*
     * Decrypted data.
     */
    CGXByteBuffer m_PlainText;

    /*
     * Used security.
     */
    DLMS_SECURITY m_Security;

    /*
     * Used Security suite.
     */
    DLMS_SECURITY_SUITE m_SecuritySuite;

    /*
     * Used Security policy.
     */
    DLMS_SECURITY_POLICY m_SecurityPolicy;

    /*
     * Used certificate type.
     */
    DLMS_CERTIFICATE_TYPE m_CertificateType;

    /*
     * System title
     */
    CGXByteBuffer m_SystemTitle;

    /*
     * Recipient system title.
     */
    CGXByteBuffer m_RecipientSystemTitle;

    /*
     * Block cipher key.
     */
    CGXByteBuffer m_BlockCipherKey;

    /*
     * Authentication key.
     */
    CGXByteBuffer m_AuthenticationKey;

    /*
     * Frame counter. Invocation counter.
     */
    long m_InvocationCounter;

    /*
     * Transaction Id.
     */
    CGXByteBuffer m_TransactionId;

    /*
     * Private key to used to encrypt the data.
     */
    CGXPrivateKey m_PrivateKey;

    /*
     * Public key to used to decrypt the data.
     */
    CGXPublicKey m_PublicKey;

public:
    /*
     * Constructor.
     */
    CGXCryptoKeyParameter();

    /*
     * @return External Hardware Security Module operation type..
     */
    DLMS_EHS_OPERATION GetOperation();

    /*
     * @param value
     *            External Hardware Security Module operation.
     */
    void SetOperation(const DLMS_EHS_OPERATION value);

    /*
     * @return Used m_Security suite.
     */
    DLMS_SECURITY_SUITE GetSecuritySuite();

    /*
     * @param value
     *            Used m_Security suite.
     */
    void SetSecuritySuite(const DLMS_SECURITY_SUITE value);

    /*
     * @return Used certificate type.
     */
    DLMS_CERTIFICATE_TYPE GetCertificateType();

    /*
     * @param value
     *            Used certificate type.
     */
    void SetCertificateType(const DLMS_CERTIFICATE_TYPE value);

    /*
     * @return System title
     */
    CGXByteBuffer& GetSystemTitle();

    /*
     * @param value
     *            System title
     */
    void SetSystemTitle(const CGXByteBuffer& value);

    /*
     * @return Private key to used to encrypt the data.
     */
    CGXPrivateKey& GetPrivateKey();

    /*
     * @param value
     *            Private key to used to encrypt the data.
     */
    void SetPrivateKey(CGXPrivateKey& value);

    /*
     * @return Public key to used to decrypt the data.
     */
    CGXPublicKey& GetPublicKey();

    /*
     * @param value
     *            Public key to used to decrypt the data.
     */
    void SetPublicKey(const CGXPublicKey& value);

    /*
     * @return Decrypted data.
     */
    CGXByteBuffer& GetPlainText();

    /*
     * @param value
     *            Decrypted data.
     */
    void SetPlainText(const CGXByteBuffer& value);

    /*
     * @return Encrypted data.
     */
    CGXByteBuffer& GetEncrypted();

    /*
     * @param value
     *            Encrypted data.
     */
    void SetEncrypted(const CGXByteBuffer& value);

    /*
     * @return Used Security policy.
     */
    DLMS_SECURITY_POLICY GetSecurityPolicy();

    /*
     * @param value
     *            Used Security policy.
     */
    void SetSecurityPolicy(const DLMS_SECURITY_POLICY value);

    /*
     * @return Recipient system title.
     */
    CGXByteBuffer& GetRecipientSystemTitle();

    /*
     * @param value
     *            Recipient system title.
     */
    void SetRecipientSystemTitle(const CGXByteBuffer& value);

    /*
     * @return Block cipher key.
     */
    CGXByteBuffer& GetBlockCipherKey();

    /*
     * @param value
     *            Block cipher key.
     */
    void SetBlockCipherKey(const CGXByteBuffer& value);

    /*
     * @return Authentication key.
     */
    CGXByteBuffer& GetAuthenticationKey();

    /*
     * @param value
     *            Authentication key.
     */
    void SetAuthenticationKey(const CGXByteBuffer& value);

    /*
     * @return Frame counter. Invocation counter.
     */
    uint32_t GetInvocationCounter();

    /*
     * @param value
     *            Frame counter. Invocation counter.
     */
    void SetInvocationCounter(const uint32_t value);

    /*
     * @return Transaction Id.
     */
    CGXByteBuffer& GetTransactionId();

    /*
     * @param value
     *            Transaction Id.
     */
    void SetTransactionId(CGXByteBuffer& value);

    /*
     * @return Crypto key type.
     */
    DLMS_CRYPTO_KEY_TYPE GetKeyType();

    /*
     * @param value
     *            Crypto key type.
     */
    void SetKeyType(const DLMS_CRYPTO_KEY_TYPE value);

    /*
     * @return Command.
     */
    int GetCommand();

    /*
     * @param value
     *            Command.
     */
    void SetCommand(const int value);

    /*
     * @return Used security
     */
    DLMS_SECURITY GetSecurity();

    /*
     * @param value
     *            Used Security
     */
    void SetSecurity(const DLMS_SECURITY value);
};
#endif //CRYPTO_KEY_PARAMETER_H
