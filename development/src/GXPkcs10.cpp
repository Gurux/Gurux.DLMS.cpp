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

#include "../include/GXPkcs10.h"
#include "../include/GXEcdsa.h"
#if defined(_WIN32) || defined(_WIN64)//Windows includes
#include <Winsock.h> //Add support for sockets
#endif
#if defined(__linux__)//linux includes
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

int CGXPkcs10::GetData(
    CGXAsn1Sequence* value)
{
    int ret;
    CGXAsn1ObjectIdentifier* alg =
        new CGXAsn1ObjectIdentifier(
            m_PublicKey.GetScheme() == ECC_P256 ?
            "1.2.840.10045.3.1.7" :
            "1.3.132.0.34");
    CGXByteBuffer bb;
    m_PublicKey.m_RawValue.ToByteBuffer(bb);
    CGXAsn1BitString* subjectPKInfo =
        new CGXAsn1BitString(bb, 0);
    CGXAsn1Sequence* tmp = new CGXAsn1Sequence();
    tmp->GetValues()->push_back(new CGXAsn1ObjectIdentifier("1.2.840.10045.2.1"));
    tmp->GetValues()->push_back(alg);
    CGXAsn1Context* attributes = new CGXAsn1Context();
    for (std::vector< std::pair<DLMS_PKCS_OBJECT_IDENTIFIER, std::vector<CGXAsn1Base*> > >::iterator it = m_Attributes.begin();
        it != m_Attributes.end(); ++it)
    {
        CGXAsn1Sequence* s = new CGXAsn1Sequence();
        s->GetValues()->push_back(new CGXAsn1ObjectIdentifier(CGXDLMSConverter::ToString(it->first)));
        //Convert object array to list.
        CGXAsn1Sequence* values = new CGXAsn1Sequence();
        for (std::vector<CGXAsn1Base*>::iterator v = it->second.begin(); v != it->second.end(); ++v)
        {
            values->GetValues()->push_back(*v);
        }
        s->GetValues()->push_back(new CGXAsn1Set(values, NULL));
        attributes->GetValues()->push_back(s);
    }
    CGXAsn1Sequence* list = new CGXAsn1Sequence();
    ret = CGXAsn1Converter::EncodeSubject(m_Subject, list);
    if (ret == 0)
    {
        value->GetValues()->push_back(new CGXAsn1Variant((char)m_Version));
        value->GetValues()->push_back(list);
        CGXAsn1Sequence* tmp2 = new CGXAsn1Sequence();
        tmp2->GetValues()->push_back(tmp);
        tmp2->GetValues()->push_back(subjectPKInfo);
        value->GetValues()->push_back(tmp2);
        value->GetValues()->push_back(attributes);
    }
    else
    {
        delete subjectPKInfo;
        delete tmp;
        delete attributes;
        delete list;
    }
    return ret;
}

int CGXPkcs10::Init(
    CGXByteBuffer& data)
{
    m_RawData = data;
    CGXAsn1Base* value = NULL;
    int ret = CGXAsn1Converter::FromByteArray(data, value);
    if (ret == 0)
    {
        if (CGXAsn1Sequence* seq = dynamic_cast<CGXAsn1Sequence*>(value))
        {
            if (seq->GetValues()->size() < 3)
            {
#ifdef _DEBUG
                printf("Wrong number of elements in sequence.");
#endif //_DEBUG
                ret = DLMS_ERROR_CODE_INVALID_DATA_FORMAT;
            }
            if (CGXAsn1Sequence* reqInfo = dynamic_cast<CGXAsn1Sequence*>(seq->GetValues()->at(0)))
            {
                if (CGXAsn1Variant* tmp = dynamic_cast<CGXAsn1Variant*>(reqInfo->GetValues()->at(0)))
                {
                    m_Version = (DLMS_CERTIFICATE_VERSION)tmp->GetValue().cVal;
                    if (CGXAsn1Sequence* tmp = dynamic_cast<CGXAsn1Sequence*>(reqInfo->GetValues()->at(1)))
                    {
                        ret = CGXAsn1Converter::GetSubject(tmp, m_Subject);
                    }
                    if (CGXAsn1Sequence* subjectPKInfo = dynamic_cast<CGXAsn1Sequence*>(reqInfo->GetValues()->at(2)))
                    {
                        if (reqInfo->GetValues()->size() > 3)
                        {
                            //PkcsObjectIdentifier
                            if (CGXAsn1Context* tmp = dynamic_cast<CGXAsn1Context*>(reqInfo->GetValues()->at(3)))
                            {
                                for (std::vector<CGXAsn1Base*>::iterator item = tmp->GetValues()->begin();
                                    item != tmp->GetValues()->end(); ++item)
                                {
                                    if (CGXAsn1Sequence* it = dynamic_cast<CGXAsn1Sequence*>(*item))
                                    {
                                        std::vector<CGXAsn1Base*> values;
                                        if (CGXAsn1Set* it2 = dynamic_cast<CGXAsn1Set*>(it->GetValues()->at(1)))
                                        {
                                            values.push_back(it2->GetKey());
                                        }
                                        else
                                        {
                                            ret = DLMS_ERROR_CODE_INVALID_DATA_FORMAT;
                                        }
                                        CGXAsn1Base* tmp = it->GetValues()->at(0);
                                        DLMS_PKCS_OBJECT_IDENTIFIER tmp2 = CGXDLMSConverter::ValueOfPKCSObjectIdentifier(tmp->ToString().c_str());
                                        m_Attributes.push_back(std::pair<DLMS_PKCS_OBJECT_IDENTIFIER, std::vector<CGXAsn1Base*> >(tmp2, values));
                                    }
                                    else
                                    {
                                        ret = DLMS_ERROR_CODE_INVALID_DATA_FORMAT;
                                    }
                                }
                            }
                        }
                        if (CGXAsn1Sequence* it = dynamic_cast<CGXAsn1Sequence*>(subjectPKInfo->GetValues()->at(0)))
                        {
                            m_Algorithm = CGXDLMSConverter::ValueOfX9Identifier(it->GetValues()->at(0)->ToString().c_str());
                            if (m_Algorithm == DLMS_X9_OBJECT_IDENTIFIER_ID_EC_PUBLIC_KEY)
                            {
                                if (CGXAsn1BitString* pk = dynamic_cast<CGXAsn1BitString*>(subjectPKInfo->GetValues()->at(1)))
                                {
                                    ret = CGXPublicKey::FromRawBytes(pk->GetValue(),
                                        m_PublicKey);
                                    if (ret == 0)
                                    {
                                        ret = CGXEcdsa::Validate(m_PublicKey);
                                    }
                                    if (ret == 0)
                                    {
                                        if (CGXAsn1Sequence* sign = dynamic_cast<CGXAsn1Sequence*>(seq->GetValues()->at(1)))
                                        {
                                            m_SignatureAlgorithm = CGXDLMSConverter::ValueOfHashAlgorithm(sign->GetValues()->at(0)->ToString().c_str());
                                            if (m_SignatureAlgorithm != DLMS_HASH_ALGORITHM_SHA_256_WITH_ECDSA &&
                                                m_SignatureAlgorithm != DLMS_HASH_ALGORITHM_SHA_384_WITH_ECDSA)
                                            {
#ifdef _DEBUG
                                                printf("Invalid signature algorithm. %s\n",
                                                    sign->GetValues()->at(0)->ToString().c_str());
#endif //_DEBUG
                                                ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                                            }
                                        }
                                        if (CGXAsn1BitString* signature = dynamic_cast<CGXAsn1BitString*>(seq->GetValues()->at(2)))
                                        {
                                            //Get raw data.
                                            CGXDLMSVariant value;
                                            unsigned long count;
                                            CGXByteBuffer tmp2;
                                            data.SetPosition(0);
                                            ret = tmp2.Set(data.GetData(), data.Available());
                                            ret = CGXAsn1Converter::GetNext(tmp2, value);
                                            tmp2.SetSize(tmp2.GetPosition());
                                            tmp2.SetPosition(1);
                                            ret = GXHelpers::GetObjectCount(tmp2, count);
                                            //Get signature.
                                            m_Signature = signature->GetValue();
                                            CGXEcdsa e(m_PublicKey);
                                            CGXAsn1Base* tmp3;
                                            CGXByteBuffer bb, bb2;
                                            m_Signature.ToByteBuffer(bb);
                                            ret = CGXAsn1Converter::FromByteArray(bb, tmp3);
                                            bb.Clear();
                                            int size = m_SignatureAlgorithm == DLMS_HASH_ALGORITHM_SHA_256_WITH_ECDSA ? 32 : 48;
                                            //Some implementations might add extra byte. It must removed.
                                            if (CGXAsn1Sequence* tmp4 = dynamic_cast<CGXAsn1Sequence*>(tmp3))
                                            {
                                                if (CGXAsn1Variant* tmp5 = dynamic_cast<CGXAsn1Variant*>(tmp4->GetValues()->at(0)))
                                                {
                                                    ret = bb.Set(tmp5->GetValue().byteArr + (tmp5->GetValue().GetSize() == size ? 0 : 1), size);
                                                    if (CGXAsn1Variant* tmp6 = dynamic_cast<CGXAsn1Variant*>(tmp4->GetValues()->at(1)))
                                                    {
                                                        ret = bb.Set(tmp6->GetValue().byteArr + (tmp6->GetValue().GetSize() == size ? 0 : 1), size);
                                                        ret = tmp2.SubArray(tmp2.GetPosition(), tmp2.Available(), bb2);
                                                        data.SetPosition(0);
                                                        bool verify;
                                                        if (e.Verify(bb, bb2, verify) != 0 ||
                                                            verify != true)
                                                        {
#ifdef _DEBUG
                                                            printf("Invalid Signature.\n");
#endif //_DEBUG
                                                            ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                                                    }
                                                }
                                                else
                                                {
                                                    ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                                                }

                                            }
                                            else
                                            {
                                                ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                                            }
                                        }
                                        else
                                        {
                                            ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                                        }
                                    }
                                }
                                else
                                {
                                    ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                                }
                            }
                            else
                            {
                                ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                            }
                        }
                        else
                        {
                            ret = DLMS_ERROR_CODE_INVALID_DATA_FORMAT;
                        }
                    }
                    else
                    {
                        ret = DLMS_ERROR_CODE_INVALID_DATA_FORMAT;
                    }
                }
                else
                {
                    ret = DLMS_ERROR_CODE_INVALID_DATA_FORMAT;
                }
            }
        }
        else
        {
            ret = DLMS_ERROR_CODE_INVALID_DATA_FORMAT;
        }
    }
    delete value;
    return ret;
}

CGXPkcs10::CGXPkcs10()
{
    m_Algorithm = DLMS_X9_OBJECT_IDENTIFIER_ID_EC_PUBLIC_KEY;
    m_Version = DLMS_CERTIFICATE_VERSION_1;
}

int CGXPkcs10::FromHexString(std::string& data,
    CGXPkcs10& cert)
{
    CGXByteBuffer bb;
    GXHelpers::HexToBytes(data, bb);
    return cert.Init(bb);
}

int CGXPkcs10::FromByteArray(const unsigned char* data,
    uint16_t length,
    CGXPkcs10& cert)
{
    CGXByteBuffer bb;
    bb.Set(data, length);
    return cert.Init(bb);
}


int CGXPkcs10::FromByteArray(CGXByteBuffer& data,
    CGXPkcs10& cert)
{
    return cert.Init(data);
}

int CGXPkcs10::FromPem(std::string data,
    CGXPkcs10& cert)
{
    std::string START = "CERTIFICATE REQUEST-----\n";
    std::string END = "-----END CERTIFICATE REQUEST";
    GXHelpers::Replace(data, "\r\n", "\n");
    size_t start = data.find(START);
    if (start == std::string::npos)
    {
#ifdef _DEBUG
        printf("Invalid PEM file.");
#endif //_DEBUG
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    data = data.substr(start + START.length());
    size_t end = data.find(END);
    if (end == std::string::npos)
    {
#ifdef _DEBUG
        printf("Invalid PEM file.");
#endif //_DEBUG
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    data = data.substr(0, end);
    return FromDer(data, cert);
}

int CGXPkcs10::FromDer(std::string& data,
    CGXPkcs10& cert)
{
    int ret;
    CGXByteBuffer bb;
    if ((ret = bb.FromBase64(data)) == 0)
    {
        ret = cert.Init(bb);
    }
    return ret;
}

int CGXPkcs10::FromHexString(CGXByteBuffer& data,
    CGXPkcs10& cert) {
    return cert.Init(data);
}

DLMS_CERTIFICATE_VERSION CGXPkcs10::GetVersion()
{
    return m_Version;
}

void CGXPkcs10::SetVersion(DLMS_CERTIFICATE_VERSION value)
{
    m_Version = value;
}

std::string& CGXPkcs10::GetSubject()
{
    return m_Subject;
}

void CGXPkcs10::SetSubject(std::string& value)
{
    m_Subject = value;
}

CGXPublicKey& CGXPkcs10::GetPublicKey()
{
    return m_PublicKey;
}

void CGXPkcs10::SetPublicKey(CGXPublicKey& value)
{
    m_PublicKey = value;
}

DLMS_X9_OBJECT_IDENTIFIER CGXPkcs10::GetAlgorithm()
{
    return m_Algorithm;
}

void CGXPkcs10::SetAlgorithm(DLMS_X9_OBJECT_IDENTIFIER value)
{
    m_Algorithm = value;
}

DLMS_HASH_ALGORITHM CGXPkcs10::GetSignatureAlgorithm()
{
    return m_SignatureAlgorithm;
}

void CGXPkcs10::SetSignatureAlgorithm(DLMS_HASH_ALGORITHM value)
{
    m_SignatureAlgorithm = value;
}

CGXByteArray& CGXPkcs10::GetSignature()
{
    return m_Signature;
}

void CGXPkcs10::SetSignature(CGXByteBuffer& value)
{
    m_Signature = value;
}

std::string CGXPkcs10::ToString()
{
    std::string bb;
    bb += "PKCS #10 certificate request:";
    bb += "\n";
    bb += "Version: ";
    bb += std::to_string(1 + m_Version);
    bb += "\n";
    bb += "Subject: ";
    bb += m_Subject;
    bb += "\n";
    bb += "Algorithm: ";
    bb += CGXDLMSConverter::ToString(m_Algorithm);
    bb += "\n";
    bb += "Public Key: ";
    bb += m_PublicKey.ToString();
    bb += "\n";
    bb += "Signature m_Algorithm: ";
    bb += CGXDLMSConverter::ToString(m_SignatureAlgorithm);
    bb += "\n";
    bb += "Signature: ";
    bb += m_Signature.ToHexString();
    bb += "\n";
    return 0;
}

int CGXPkcs10::GetEncoded(CGXByteBuffer& value)
{
    if (m_RawData.GetSize() != 0)
    {
        return m_RawData.ToByteBuffer(value);
    }
    if (m_Signature.GetSize() == 0)
    {
#ifdef _DEBUG
        printf("Sign first.");
#endif //_DEBUG
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    // Certification request info.
    // subject Public key info.
    CGXAsn1Sequence list;
    CGXAsn1Sequence* data = new CGXAsn1Sequence();
    int ret = GetData(data);
    list.GetValues()->push_back(data);
    if (ret == 0)
    {
        CGXAsn1ObjectIdentifier* sa = new CGXAsn1ObjectIdentifier(CGXDLMSConverter::ToString(m_SignatureAlgorithm));
        CGXAsn1Sequence* s2 = new CGXAsn1Sequence();
        s2->GetValues()->push_back(sa);
        list.GetValues()->push_back(s2);
        list.GetValues()->push_back(new CGXAsn1BitString(m_Signature, 0));
        ret = CGXAsn1Converter::ToByteArray(&list, value);
        if (ret == 0)
        {
            m_RawData = value;
        }
    }
    return ret;
}

int CGXPkcs10::Sign(
    CGXPrivateKey& key,
    DLMS_HASH_ALGORITHM hashAlgorithm)
{
    CGXByteBuffer data;
    CGXAsn1Sequence s;
    int ret = GetData(&s);
    if (ret == 0)
    {
        ret = CGXAsn1Converter::ToByteArray(&s, data);
        if (ret == 0)
        {
            CGXEcdsa e(key);
            m_SignatureAlgorithm = hashAlgorithm;
            CGXByteBuffer signature, bb;
            ret = e.Sign(data, signature);
            if (ret == 0)
            {
                int size = hashAlgorithm == DLMS_HASH_ALGORITHM_SHA_256_WITH_ECDSA ? 32 : 48;
                CGXAsn1Sequence s;
                ret = signature.SubArray(0, size, bb);
                if (ret == 0)
                {
                    s.GetValues()->push_back(new CGXAsn1Integer(bb));
                    bb.Clear();
                    ret = signature.SubArray(size, size, bb);
                    if (ret == 0)
                    {
                        s.GetValues()->push_back(new CGXAsn1Integer(bb));
                        bb.Clear();
                        ret = CGXAsn1Converter::ToByteArray(&s, bb);
                        m_Signature = bb;
                    }
                }
            }
        }
    }
    return ret;
}

int CGXPkcs10::CreateCertificateSigningRequest(
    std::pair<CGXPublicKey, CGXPrivateKey>& kp,
    std::string& subject,
    CGXPkcs10& pkc10)
{
    if (kp.first.m_RawValue.m_Size == 0)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    if (kp.second.m_RawValue.m_Size == 0)
    {
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    pkc10.m_Algorithm = DLMS_X9_OBJECT_IDENTIFIER_ID_EC_PUBLIC_KEY;
    pkc10.m_PublicKey = kp.first;
    pkc10.m_Subject = subject;
    DLMS_HASH_ALGORITHM algorithm;
    if (kp.second.m_RawValue.m_Size < 70)
    {
        algorithm = DLMS_HASH_ALGORITHM_SHA_256_WITH_ECDSA;
    }
    else
    {
        algorithm = DLMS_HASH_ALGORITHM_SHA_384_WITH_ECDSA;
    }
    int ret = pkc10.Sign(kp.second, algorithm);
    if (ret == 0)
    {
        //Update raw data.
        CGXByteBuffer bb;
        ret = pkc10.GetEncoded(bb);
    }
    return ret;
}

int CGXPkcs10::GetCertificate(
    std::vector<CGXCertificateRequest>& certifications,
    std::vector <CGXx509Certificate>& certificates)
{
    const char* address = "certificates.gurux.fi";
    std::string usage;
    for (std::vector<CGXCertificateRequest>::iterator it = certifications.begin();
        it != certifications.end(); ++it)
    {
        if (usage.size() != 0) {
            usage.append(", ");
        }
        usage.append("{\"KeyUsage\":");
        switch (it->GetCertificateType())
        {
        case DLMS_CERTIFICATE_TYPE_DIGITAL_SIGNATURE:
            usage.append(
                std::to_string(DLMS_KEY_USAGE_DIGITAL_SIGNATURE));
            break;
        case DLMS_CERTIFICATE_TYPE_KEY_AGREEMENT:
            usage.append(std::to_string(DLMS_KEY_USAGE_KEY_AGREEMENT));
            break;
        case DLMS_CERTIFICATE_TYPE_TLS:
            usage.append(
                std::to_string(DLMS_KEY_USAGE_DIGITAL_SIGNATURE |
                    DLMS_KEY_USAGE_KEY_AGREEMENT));
            break;
        default:
#ifdef _DEBUG
            printf("Invalid type.");
#endif //_DEBUG
            return DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        if (it->GetExtendedKeyUsage() != DLMS_EXTENDED_KEY_USAGE_NONE)
        {
            usage.append(", \"ExtendedDLMS_KEY_USAGE\":");
            usage.append(std::to_string(it->GetExtendedKeyUsage()));
        }
        usage.append(", \"CSR\":\"");
        std::string der;
        int ret = it->GetCertificate()->ToDer(der);
        if (ret != 0)
        {
            return ret;
        }
        usage.append(der);
        usage.append("\"}");
    }
    std::string input = "{\"Certificates\":[";
    input.append(usage);
    input.append("]}");
    int conn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct hostent* host = NULL;
    if (inet_addr(address) == INADDR_NONE)
    {
        host = gethostbyname(address);
    }
    else
    {
        unsigned int addr = inet_addr(address);
        host = gethostbyaddr((char*)&addr, sizeof(addr), AF_INET);
    }
    if (host == NULL)
    {
#if defined(_WIN32) || defined(_WIN64)//Windows includes
        closesocket(conn);
#else
        close(conn);
#endif
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    struct sockaddr_in server;
    server.sin_addr.s_addr = *((unsigned long*)host->h_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(80);
    if (connect(conn,
        (struct sockaddr*)&server,
        sizeof(server)))
    {
#if defined(_WIN32) || defined(_WIN64)//Windows includes
        closesocket(conn);
#else
        close(conn);
#endif
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    std::string data = "POST /api/CertificateGenerator HTTP/1.1\r\n";
    data += "Content-Type: application/json\r\n";
    data += "Host: ";
    data += address;
    data += "\r\nContent-Length:";
    data += std::to_string(input.size());
    data += "\r\n";
    data += "Expect: 100-continue\r\n";
    data += "\r\n";
    char buffer[1024];
    int ret = send(conn, data.c_str(), data.size(), 0);
    ret = recv(conn, buffer, sizeof(buffer), 0);
    //Wait continue msg from the server.
    if (ret <= 0)
    {
#ifdef _DEBUG
        printf("Failed to get reply from the Gurux server.\r\n");
#endif //_DEBUG
#if defined(_WIN32) || defined(_WIN64)//Windows includes
        closesocket(conn);
#else
        close(conn);
#endif
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    std::string reply;
    reply.append(buffer, ret);
    if (reply != "HTTP/1.1 100 Continue\r\n\r\n")
    {
#ifdef _DEBUG
        printf("Failed to get reply from the Gurux server.\r\n");
#endif //_DEBUG
#if defined(_WIN32) || defined(_WIN64)//Windows includes
        closesocket(conn);
#else
        close(conn);
#endif
        return DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    reply.clear();
    ret = send(conn, input.c_str(), input.size(), 0);
    do
    {
        ret = recv(conn, buffer, sizeof(buffer), 0);
        if (ret <= 0)
        {
            break;
        }
        reply.append(buffer, ret);
    } while (reply.rfind("\r\n0\r\n\r\n") == std::string::npos);
    if (reply.find("200 OK\r\n") == std::string::npos)
    {
#ifdef _DEBUG
        printf("Failed to get certificates from the server.\r\n %s.\r\n", reply.c_str());
#endif //_DEBUG
        ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
    }
    else
    {
        size_t pos = reply.find("[");
        if (pos == std::string::npos)
        {
#ifdef _DEBUG
            printf("Certificates are missing.\r\n");
#endif //_DEBUG
            ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
        }
        else
        {
            reply = reply.substr(pos + 2);
            pos = reply.rfind("]");
            if (pos == std::string::npos)
            {
#ifdef _DEBUG
                printf("Certificates are missing.\r\n");
#endif //_DEBUG
                ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
            }
            else
            {
                reply = reply.substr(0, pos - 1);
                std::vector< std::string > list = GXHelpers::Split(reply, "\",", true);
                pos = 0;
                for (std::vector< std::string >::iterator it = list.begin();
                    it != list.end(); ++it)
                {
                    CGXx509Certificate cert;
                    ret = CGXx509Certificate::FromDer(*it, cert);
                    if (ret != 0)
                    {
                        break;
                    }
                    if (!certifications.at(pos).m_Certificate->m_PublicKey.m_RawValue.Compare(
                        cert.m_PublicKey.m_RawValue.m_Data, cert.m_PublicKey.m_RawValue.m_Size))
                    {
#ifdef _DEBUG
                        printf("Create certificate signingRequest generated wrong public key.\r\n");
#endif //_DEBUG
                        ret = DLMS_ERROR_CODE_INVALID_PARAMETER;
                        break;
                    }
                    ++pos;
                    certificates.push_back(cert);

                }
            }
        }
    }
#if defined(_WIN32) || defined(_WIN64)
    closesocket(conn);
#else
    close(conn);
#endif
    return ret;
}

#if defined(_WIN32) || defined(_WIN64) || defined(__linux__)
int CGXPkcs10::Load(std::string& path,
    CGXPkcs10& cert)
{
    std::string text;
    int ret = GXHelpers::Load(path, text);
    if (ret != 0)
    {
        return ret;
    }
    return FromPem(text, cert);
}

int CGXPkcs10::Load(const char* path,
    CGXPkcs10& cert)
{
    std::string tmp = path;
    return Load(tmp, cert);
}

int CGXPkcs10::Save(std::string& path)
{
    std::string text;
    int ret = ToPem(text);
    if (ret != 0)
    {
        return ret;
    }
    return GXHelpers::Save(path, text);
}

int CGXPkcs10::Save(const char* path)
{
    std::string tmp = path;
    return Save(tmp);
}
#endif //defined(_WIN32) || defined(_WIN64) || defined(__linux__)

int CGXPkcs10::ToPem(std::string& value)
{
    value.clear();
    std::string der;
    int ret = ToDer(der);
    if (ret == 0)
    {
        value += "-----BEGIN CERTIFICATE REQUEST-----\n";
        value += der;
        value += "\n-----END CERTIFICATE REQUEST-----\n";
    }
    return ret;
}

int CGXPkcs10::ToDer(std::string& value)
{
    int ret;
    value.clear();
    if (m_RawData.GetSize() != 0)
    {
        ret = m_RawData.ToBase64(value);
    }
    else
    {
        CGXByteBuffer bb;
        ret = GetEncoded(bb);
        if (ret == 0)
        {
            ret = bb.ToBase64(value);
        }
    }
    return ret;
}

bool CGXPkcs10::Equals(CGXPkcs10& cert)
{
    return m_RawData.Compare(
        cert.m_RawData.GetData(),
        cert.m_RawData.GetSize());
}