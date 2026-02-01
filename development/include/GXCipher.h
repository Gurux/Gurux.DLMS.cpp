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

#ifndef GXCIPHER_H
#define GXCIPHER_H

#include "GXBytebuffer.h"
#include "GXPrivateKey.h"
#include "GXPublicKey.h"
#include "GXx509Certificate.h"

#ifdef DLMS_USE_AES_HARDWARE_SECURITY_MODULE
#include "GXCryptoKeyParameter.h"
extern int OnCrypto(CGXCryptoKeyParameter& args);
#endif //DLMS_USE_AES_HARDWARE_SECURITY_MODULE

/**
 * Cipher class provides cryptographic operations for DLMS communication.
 *
 * This class implements AES-GCM encryption/decryption and authentication
 * mechanisms required for secure DLMS communication. It supports multiple
 * security levels (None, Authentication, Encryption, Authentication+Encryption)
 * and security suites (V0, V1, V2).
 *
 * Key features:
 * - AES-128 and AES-256 encryption (depending on security suite)
 * - Galois/Counter Mode (GCM) for authenticated encryption
 * - Frame counter (invocation counter) management
 * - Support for dedicated keys and key agreement
 * - X.509 certificate management
 */
class CGXCipher
{
private:
    /**
     * Security level used for DLMS communication.
     */
    DLMS_SECURITY m_Security;

    /**
     * System title (8 bytes) uniquely identifying the device.
     */
    CGXByteBuffer m_SystemTitle;

    /**
     * Indicates whether data encryption is enabled.
     */
    bool m_Encrypt;

    /**
     * Block cipher key used for encryption operations.
     * Size: 16 bytes for Suite 0/1, 32 bytes for Suite 2.
     */
    CGXByteBuffer m_BlockCipherKey;

    /**
     * Authentication key used for message authentication.
     * Size: 16 bytes for Suite 0/1, 32 bytes for Suite 2.
     */
    CGXByteBuffer m_AuthenticationKey;

    /**
     * Dedicated key for specific security associations.
     */
    CGXByteBuffer m_DedicatedKey;

    /**
     * Frame counter (also known as Invocation counter).
     * Incremented with each encrypted message to prevent replay attacks.
     */
    unsigned long m_FrameCounter;

    /**
     * Security suite version (V0, V1, or V2).
     * Determines key sizes and cryptographic algorithms.
     */
    DLMS_SECURITY_SUITE m_SecuritySuite;

    /**
     * Key agreement key pair for ECDH key exchange.
     */
    std::pair<CGXPublicKey, CGXPrivateKey> m_KeyAgreementKeyPair;

    /**
     * Signing key pair for digital signatures.
     */
    std::pair<CGXPublicKey, CGXPrivateKey> m_SigningKeyPair;

    /**
     * Collection of X.509 certificates for authentication.
     */
    std::vector<CGXx509Certificate> m_Certificates;

    /**
     * Internal initialization method.
     *
     * @param systemTitle System title buffer.
     * @param count Length of system title (must be 8).
     */
    void Init(
        unsigned char* systemTitle,
        unsigned char count);

#ifndef DLMS_USE_AES_HARDWARE_SECURITY_MODULE

    /**
     * Initialize AES round keys.
     *
     * @param rk Output buffer for round keys.
     * @param cipherKey Input cipher key.
     * @param keyBits Key size in bits (128 or 256).
     * @return Error code or 0 on success.
     */
    static int Int(uint32_t* rk,
        const unsigned char* cipherKey,
        unsigned short keyBits);

    /**
     * XOR operation for 128-bit blocks.
     *
     * @param dst Destination buffer (modified in place).
     * @param src Source buffer.
     */
    static void Xor(
        unsigned char* dst,
        const unsigned char* src);

    /**
     * Right shift a 128-bit block by one bit.
     *
     * @param v Block to shift.
     */
    static void shift_right_block(unsigned char* v);

    /**
     * Multiply two values in the Galois field (GF(2^128)).
     *
     * @param x First operand.
     * @param y Second operand.
     * @param z Result buffer.
     */
    static void MultiplyH(
        const unsigned char* x,
        const unsigned char* y,
        unsigned char* z);

    /**
     * Calculate GHASH for GCM authentication.
     *
     * @param h Hash subkey.
     * @param x Input data.
     * @param xlen Length of input data.
     * @param y Output GHASH value (updated in place).
     */
    static void GetGHash(
        const unsigned char* h,
        const unsigned char* x,
        int xlen,
        unsigned char* y);

    /**
     * Initialize J0 block for GCM counter mode.
     *
     * @param iv Initialization vector (nonce).
     * @param len Length of IV.
     * @param H Hash subkey.
     * @param J0 Output J0 block.
     */
    static void Init_j0(
        const unsigned char* iv,
        unsigned char len,
        const unsigned char* H,
        unsigned char* J0);

    /**
     * Increment the rightmost 32 bits of a block.
     *
     * @param block Block to increment.
     */
    static void Inc32(unsigned char* block);

    /**
     * Galois counter mode encryption/decryption.
     *
     * @param aes AES round keys.
     * @param icb Initial counter block.
     * @param in Input data.
     * @param len Length of input.
     * @param out Output buffer (NULL for in-place operation).
     */
    static void Gctr(
        unsigned int* aes,
        const unsigned char* icb,
        unsigned char* in,
        int len,
        unsigned char* out);

    /**
     * GCM counter mode operation with J0 initialization.
     *
     * @param aes AES round keys.
     * @param J0 J0 counter block.
     * @param in Input data.
     * @param len Length of input.
     * @param out Output buffer.
     */
    static void AesGcmGctr(
        unsigned int* aes,
        const unsigned char* J0,
        unsigned char* in,
        int len,
        unsigned char* out);

    /**
     * Calculate GCM authentication tag (GHASH).
     *
     * @param H Hash subkey.
     * @param aad Additional authenticated data.
     * @param aad_len Length of AAD.
     * @param crypt Ciphertext.
     * @param crypt_len Length of ciphertext.
     * @param S Output authentication tag.
     */
    static void AesGcmGhash(
        const unsigned char* H,
        const unsigned char* aad,
        int aad_len,
        const unsigned char* crypt,
        int crypt_len,
        unsigned char* S);

    /**
     * AES block encryption.
     *
     * @param rk Round keys.
     * @param Nr Number of rounds.
     * @param pt Plaintext block (16 bytes).
     * @param ct Ciphertext output (16 bytes).
     */
    static void AesEncrypt(
        const unsigned int* rk,
        unsigned int Nr,
        const unsigned char* pt,
        unsigned char* ct);
#endif //DLMS_USE_AES_HARDWARE_SECURITY_MODULE
public:
    /**
     * Constructor.
     *
     * @param systemTitle System title as byte buffer (must be 8 bytes).
     */
    CGXCipher(CGXByteBuffer& systemTitle);

    /**
     * Constructor.
     *
     * @param systemTitle System title as C-string.
     */
    CGXCipher(const char* systemTitle);

    /**
     * Constructor.
     *
     * @param systemTitle System title as byte array.
     * @param count Length of system title (must be 8).
     */
    CGXCipher(
        unsigned char* systemTitle,
        unsigned char count);

    /**
     * Destructor.
     */
    ~CGXCipher();


    /**
     * Encrypt PDU using AES-GCM.
     *
     * @param suite Security suite (V0, V1, or V2).
     * @param security Security level.
     * @param type Count type (tag, data, or packet).
     * @param frameCounter Frame counter value.
     * @param tag DLMS command tag.
     * @param systemTitle System title.
     * @param key Encryption/authentication key.
     * @param input Data to encrypt (modified in place).
     * @param encrypt True to encrypt, false to decrypt.
     * @return Error code or 0 on success.
     */
    int Encrypt(
        DLMS_SECURITY_SUITE suite,
        DLMS_SECURITY security,
        DLMS_COUNT_TYPE type,
        unsigned long frameCounter,
        unsigned char tag,
        CGXByteBuffer& systemTitle,
        CGXByteBuffer& key,
        CGXByteBuffer& input,
        bool encrypt);

    /**
     * Decrypt data using AES-GCM.
     *
     * @param title System title.
     * @param key Decryption/authentication key.
     * @param data Encrypted data (modified in place).
     * @param security Output: detected security level.
     * @param suite Output: detected security suite.
     * @param InvocationCounter Output: invocation counter from message.
     * @return Error code or 0 on success.
     */
    int Decrypt(
        CGXByteBuffer& title,
        CGXByteBuffer& key,
        CGXByteBuffer& data,
        DLMS_SECURITY& security,
        DLMS_SECURITY_SUITE& suite,
        uint64_t& InvocationCounter);

    /**
     * Encrypt data using simplified AES-128.
     *
     * @param data Data to encrypt (modified in place).
     * @param offset Offset in data buffer.
     * @param secret AES-128 key (16 bytes).
     * @return Error code or 0 on success.
     */
    static int Aes1Encrypt(
        CGXByteBuffer& data,
        unsigned short offset,
        CGXByteBuffer& secret);

    /**
     * Decrypt data using simplified AES-128.
     *
     * @param data Data to decrypt (modified in place).
     * @param secret AES-128 key (16 bytes).
     * @return Error code or 0 on success.
     */
    static int Aes1Decrypt(
        CGXByteBuffer& data,
        CGXByteBuffer& secret);

    /**
     * Check if ciphering is enabled.
     *
     * @return True if security is not NONE.
     */
    bool IsCiphered();

    /**
     * Get the current security level.
     *
     * @return Security level.
     */
    DLMS_SECURITY GetSecurity();

    /**
     * Set the security level.
     *
     * @param value Security level.
     */
    void SetSecurity(DLMS_SECURITY value);

    /**
     * Get the security suite version.
     *
     * @return Security suite.
     */
    DLMS_SECURITY_SUITE GetSecuritySuite();

    /**
     * Set the security suite version.
     *
     * @param value Security suite.
     */
    void SetSecuritySuite(DLMS_SECURITY_SUITE value);

    /**
     * Get the system title.
     *
     * @return System title (8 bytes).
     */
    CGXByteBuffer& GetSystemTitle();

    /**
     * Set the system title.
     *
     * @param value System title (must be 8 bytes).
     * @return Error code or 0 on success.
     */
    int SetSystemTitle(CGXByteBuffer& value);

    /**
     * Get the block cipher key.
     *
     * @return Block cipher key (16 or 32 bytes).
     */
    CGXByteBuffer& GetBlockCipherKey();

    /**
     * Set the block cipher key.
     *
     * @param value Block cipher key (16 bytes for Suite 0/1, 32 bytes for Suite 2).
     * @return Error code or 0 on success.
     */
    int SetBlockCipherKey(CGXByteBuffer& value);

    /**
     * Get the authentication key.
     *
     * @return Authentication key (16 or 32 bytes).
     */
    CGXByteBuffer& GetAuthenticationKey();

    /**
     * Set the authentication key.
     *
     * @param value Authentication key (16 bytes for Suite 0/1, 32 bytes for Suite 2).
     * @return Error code or 0 on success.
     */
    int SetAuthenticationKey(CGXByteBuffer& value);

    /**
     * Get the frame counter.
     *
     * @return Frame counter value.
     */
    unsigned long GetFrameCounter();

    /**
     * Set the frame counter.
     *
     * @param value Frame counter value.
     */
    void SetFrameCounter(unsigned long value);

    /**
     * Get the invocation counter (alias for frame counter).
     *
     * @return Invocation counter value.
     */
    unsigned long GetInvocationCounter();

    /**
     * Set the invocation counter (alias for frame counter).
     *
     * @param value Invocation counter value.
     */
    void SetInvocationCounter(unsigned long value);

    /**
     * Reset cipher state.
     */
    void Reset();

    /**
     * Get the dedicated key.
     *
     * @return Dedicated key.
     */
    CGXByteBuffer& GetDedicatedKey();

    /**
     * Set the dedicated key.
     *
     * @param value Dedicated key.
     */
    void SetDedicatedKey(CGXByteBuffer& value);

    /**
     * Get the key agreement key pair for ECDH.
     *
     * @return Key agreement key pair.
     */
    std::pair<CGXPublicKey, CGXPrivateKey>& GetKeyAgreementKeyPair();

    /**
     * Set the key agreement key pair for ECDH.
     *
     * @param value Key agreement key pair.
     */
    void SetKeyAgreementKeyPair(std::pair<CGXPublicKey, CGXPrivateKey>& value);

    /**
     * Get the signing key pair.
     *
     * @return Signing key pair.
     */
    std::pair<CGXPublicKey, CGXPrivateKey>& GetSigningKeyPair();

    /**
     * Set the signing key pair.
     *
     * @param value Signing key pair.
     */
    void SetSigningKeyPair(std::pair<CGXPublicKey, CGXPrivateKey>& value);

    /**
     * Get the available X.509 certificates.
     *
     * @return Vector of certificates.
     */
    std::vector<CGXx509Certificate>& GetCertificates();

    /**
     * Set the available X.509 certificates.
     *
     * @param value Vector of certificates.
     */
    void SetCertificates(std::vector<CGXx509Certificate>& value);
};
#endif //GXCIPHER_H
