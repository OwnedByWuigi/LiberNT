/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Verify MSIX package signature and signed block-map digest
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#define COBJMACROS
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <mssip.h>
#include <xmllite.h>
#include <minizip/ioapi.h>
#include <minizip/iowin32.h>
#include <minizip/unzip.h>
#include "package_trust.h"

struct package_hash_method
{
    PCWSTR uri;
    PCWSTR algorithm;
    PCSTR oid;
    ULONG digest_length;
};

static const struct package_hash_method hash_methods[] =
{
    {L"http://www.w3.org/2001/04/xmlenc#sha256", BCRYPT_SHA256_ALGORITHM, szOID_NIST_sha256, 32},
    {L"http://www.w3.org/2001/04/xmldsig-more#sha384", BCRYPT_SHA384_ALGORITHM, szOID_NIST_sha384, 48},
    {L"http://www.w3.org/2001/04/xmlenc#sha512", BCRYPT_SHA512_ALGORITHM, szOID_NIST_sha512, 64},
};

static HRESULT read_archive_entry(unzFile archive, PCSTR name, BYTE **data, ULONG *length)
{
    unz_file_info64 info;
    BYTE *buffer;
    ZPOS64_T remaining;
    int result;

    *data = NULL;
    *length = 0;
    if (unzLocateFile(archive, name, 1) != UNZ_OK)
        return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
    if (unzGetCurrentFileInfo64(archive, &info, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK ||
        !info.uncompressed_size || info.uncompressed_size > MAXDWORD)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    buffer = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)info.uncompressed_size);
    if (!buffer)
        return E_OUTOFMEMORY;
    result = unzOpenCurrentFile(archive);
    if (result != UNZ_OK)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }
    remaining = info.uncompressed_size;
    {
        BYTE *cursor = buffer;
        while (remaining)
        {
            UINT request = remaining > 64 * 1024 ? 64 * 1024 : (UINT)remaining;
            int read = unzReadCurrentFile(archive, cursor, request);

            if (read <= 0 || (UINT)read > request)
            {
                unzCloseCurrentFile(archive);
                HeapFree(GetProcessHeap(), 0, buffer);
                return HRESULT_FROM_WIN32(ERROR_CRC);
            }
            cursor += read;
            remaining -= read;
        }
    }
    if (unzCloseCurrentFile(archive) != UNZ_OK)
    {
        HeapFree(GetProcessHeap(), 0, buffer);
        return HRESULT_FROM_WIN32(ERROR_CRC);
    }
    *data = buffer;
    *length = (ULONG)info.uncompressed_size;
    return S_OK;
}

static HRESULT get_hash_method(const BYTE *data, ULONG length, const struct package_hash_method **method)
{
    HGLOBAL memory;
    IStream *stream = NULL;
    IXmlReader *reader = NULL;
    XmlNodeType node_type;
    HRESULT hr;
    ULONG index;

    *method = NULL;
    memory = GlobalAlloc(GMEM_MOVEABLE, length);
    if (!memory)
        return E_OUTOFMEMORY;
    hr = CreateStreamOnHGlobal(memory, TRUE, &stream);
    if (FAILED(hr))
    {
        GlobalFree(memory);
        return hr;
    }
    {
        ULONG written = 0;
        hr = IStream_Write(stream, data, length, &written);
        if (FAILED(hr) || written != length)
        {
            IStream_Release(stream);
            return FAILED(hr) ? hr : E_FAIL;
        }
    }
    {
        LARGE_INTEGER zero = {0};
        hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    }
    if (SUCCEEDED(hr))
        hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL);
    if (SUCCEEDED(hr))
        hr = IXmlReader_SetInput(reader, (IUnknown *)stream);
    IStream_Release(stream);
    if (FAILED(hr))
        goto done;

    for (;;)
    {
        const WCHAR *element;
        UINT element_length;

        hr = IXmlReader_Read(reader, &node_type);
        if (hr == S_FALSE || (SUCCEEDED(hr) && node_type == XmlNodeType_None))
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            goto done;
        }
        if (FAILED(hr))
            goto done;
        if (node_type != XmlNodeType_Element)
            continue;
        hr = IXmlReader_GetLocalName(reader, &element, &element_length);
        if (FAILED(hr))
            goto done;
        if (element_length != ARRAYSIZE(L"BlockMap") - 1 || _wcsnicmp(element, L"BlockMap", element_length))
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            goto done;
        }
        hr = IXmlReader_MoveToFirstAttribute(reader);
        while (hr == S_OK)
        {
            const WCHAR *name, *value;
            UINT name_length, value_length;

            hr = IXmlReader_GetLocalName(reader, &name, &name_length);
            if (FAILED(hr))
                goto done;
            if (name_length == ARRAYSIZE(L"HashMethod") - 1 && !_wcsnicmp(name, L"HashMethod", name_length))
            {
                hr = IXmlReader_GetValue(reader, &value, &value_length);
                if (FAILED(hr))
                    goto done;
                for (index = 0; index < ARRAYSIZE(hash_methods); index++)
                {
                    if (wcslen(hash_methods[index].uri) == value_length &&
                        !wcsncmp(value, hash_methods[index].uri, value_length))
                    {
                        *method = &hash_methods[index];
                        hr = S_OK;
                        goto done;
                    }
                }
                hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
                goto done;
            }
            hr = IXmlReader_MoveToNextAttribute(reader);
        }
        if (hr != S_FALSE && FAILED(hr))
            goto done;
        hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        goto done;
    }

done:
    if (reader)
        IXmlReader_Release(reader);
    return hr;
}

HRESULT package_archive_verify_signature(PCWSTR path, const struct package_identity *identity)
{
    static const DWORD signature_magic = 0x58434b50;
    static const char indirect_data_oid[] = "1.3.6.1.4.1.311.2.1.4";
    zlib_filefunc64_def file_functions;
    unzFile archive;
    BYTE *signature = NULL, *block_map = NULL;
    ULONG signature_length = 0, block_map_length = 0;
    DWORD encoding, content_type, format_type, signer_size, content_size, indirect_size;
    HCERTSTORE store = NULL;
    HCRYPTMSG message = NULL;
    PCCERT_CONTEXT certificate = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    SIP_INDIRECT_DATA *indirect = NULL;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BYTE *signer_data = NULL, *content = NULL;
    const struct package_hash_method *hash_method = NULL;
    const BYTE *signed_block_map_hash = NULL;
    CERT_NAME_BLOB expected_subject;
    BYTE *expected_subject_data = NULL;
    DWORD expected_subject_length = 0;
    HRESULT hr = E_FAIL;
    ULONG offset;

    if (!path || !identity || !identity->publisher)
        return E_INVALIDARG;
    fill_win32_filefunc64W(&file_functions);
    archive = unzOpen2_64(path, &file_functions);
    if (!archive)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    hr = read_archive_entry(archive, "AppxSignature.p7x", &signature, &signature_length);
    if (SUCCEEDED(hr))
        hr = read_archive_entry(archive, "AppxBlockMap.xml", &block_map, &block_map_length);
    unzClose(archive);
    if (FAILED(hr))
        goto done;
    if (signature_length <= sizeof(signature_magic) ||
        *(const DWORD *)signature != signature_magic)
    {
        hr = TRUST_E_NOSIGNATURE;
        goto done;
    }
    hr = get_hash_method(block_map, block_map_length, &hash_method);
    if (FAILED(hr))
        goto done;
    {
        CRYPT_DATA_BLOB blob;
        blob.cbData = signature_length - sizeof(signature_magic);
        blob.pbData = signature + sizeof(signature_magic);
        if (!CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &blob,
                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                              CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content_type, &format_type,
                              &store, &message, NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto done;
        }
    }
    signer_size = 0;
    if (!CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &signer_size) || !signer_size)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    signer_data = HeapAlloc(GetProcessHeap(), 0, signer_size);
    if (!signer_data)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if (!CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, signer_data, &signer_size))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    certificate = CertFindCertificateInStore(store, encoding, 0, CERT_FIND_SUBJECT_CERT,
                                              (PCERT_INFO)signer_data, NULL);
    if (!certificate)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    {
        CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA parameters = {0};
        parameters.cbSize = sizeof(parameters);
        parameters.dwSignerType = CMSG_VERIFY_SIGNER_CERT;
        parameters.pvSigner = (PVOID)certificate;
        if (!CryptMsgControl(message, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &parameters))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto done;
        }
    }
    if (!CertStrToNameW(X509_ASN_ENCODING, identity->publisher, CERT_X500_NAME_STR, NULL,
                        NULL, &expected_subject_length, NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    expected_subject_data = HeapAlloc(GetProcessHeap(), 0, expected_subject_length);
    if (!expected_subject_data)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if (!CertStrToNameW(X509_ASN_ENCODING, identity->publisher, CERT_X500_NAME_STR, NULL,
                        expected_subject_data, &expected_subject_length, NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    expected_subject.cbData = expected_subject_length;
    expected_subject.pbData = expected_subject_data;
    if (!CertCompareCertificateName(X509_ASN_ENCODING, &expected_subject, &certificate->pCertInfo->Subject))
    {
        hr = TRUST_E_SUBJECT_NOT_TRUSTED;
        goto done;
    }
    {
        CERT_CHAIN_PARA parameters = {0};
        CERT_CHAIN_POLICY_PARA policy_parameters = {0};
        CERT_CHAIN_POLICY_STATUS policy_status = {0};

        parameters.cbSize = sizeof(parameters);
        if (!CertGetCertificateChain(NULL, certificate, NULL, store, &parameters,
                                     CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, &chain))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto done;
        }
        policy_parameters.cbSize = sizeof(policy_parameters);
        policy_status.cbSize = sizeof(policy_status);
        if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE, chain,
                                              &policy_parameters, &policy_status))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto done;
        }
        if (chain->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR || policy_status.dwError)
        {
            hr = HRESULT_FROM_WIN32(policy_status.dwError ? policy_status.dwError : ERROR_ACCESS_DENIED);
            goto done;
        }
    }
    if (!CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, NULL, &content_size) || !content_size)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    content = HeapAlloc(GetProcessHeap(), 0, content_size);
    if (!content)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    if (!CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, content, &content_size))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, indirect_data_oid, content, content_size,
                             CRYPT_DECODE_ALLOC_FLAG, NULL, &indirect, &indirect_size))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    if (!indirect->DigestAlgorithm.pszObjId ||
        strcmp(indirect->DigestAlgorithm.pszObjId, hash_method->oid) ||
        indirect->Digest.cbData < 4 + hash_method->digest_length ||
        memcmp(indirect->Digest.pbData, "APPX", 4))
    {
        hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        goto done;
    }
    for (offset = 4; offset + 4 + hash_method->digest_length <= indirect->Digest.cbData; offset++)
    {
        if (!memcmp(indirect->Digest.pbData + offset, "AXBM", 4))
        {
            signed_block_map_hash = indirect->Digest.pbData + offset + 4;
            break;
        }
    }
    if (!signed_block_map_hash)
    {
        hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        goto done;
    }
    if (BCryptOpenAlgorithmProvider(&algorithm, hash_method->algorithm, NULL, 0) < 0)
    {
        hr = E_FAIL;
        goto done;
    }
    {
        BYTE actual_hash[64];
        NTSTATUS status = BCryptHash(algorithm, NULL, 0, block_map, block_map_length,
                                     actual_hash, hash_method->digest_length);
        if (status < 0)
        {
            hr = HRESULT_FROM_NT(status);
            goto done;
        }
        if (memcmp(actual_hash, signed_block_map_hash, hash_method->digest_length))
        {
            hr = TRUST_E_BAD_DIGEST;
            goto done;
        }
    }
    hr = S_OK;

done:
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (indirect) LocalFree(indirect);
    if (chain) CertFreeCertificateChain(chain);
    if (certificate) CertFreeCertificateContext(certificate);
    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    if (expected_subject_data) HeapFree(GetProcessHeap(), 0, expected_subject_data);
    if (content) HeapFree(GetProcessHeap(), 0, content);
    if (signer_data) HeapFree(GetProcessHeap(), 0, signer_data);
    if (block_map) HeapFree(GetProcessHeap(), 0, block_map);
    if (signature) HeapFree(GetProcessHeap(), 0, signature);
    return hr;
}
