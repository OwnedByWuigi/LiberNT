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
#include <string.h>
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

static HRESULT get_xml_attribute(IXmlReader *reader, PCWSTR wanted, WCHAR **value)
{
    const WCHAR *name, *text;
    UINT name_length, text_length;
    HRESULT hr;

    *value = NULL;
    hr = IXmlReader_MoveToFirstAttribute(reader);
    if (hr == S_FALSE) return S_FALSE;
    if (FAILED(hr)) return hr;
    do
    {
        hr = IXmlReader_GetLocalName(reader, &name, &name_length);
        if (FAILED(hr)) return hr;
        if (wcslen(wanted) == name_length && !_wcsnicmp(name, wanted, name_length))
        {
            hr = IXmlReader_GetValue(reader, &text, &text_length);
            if (FAILED(hr)) return hr;
            *value = HeapAlloc(GetProcessHeap(), 0, ((SIZE_T)text_length + 1) * sizeof(WCHAR));
            if (!*value) return E_OUTOFMEMORY;
            CopyMemory(*value, text, text_length * sizeof(WCHAR));
            (*value)[text_length] = UNICODE_NULL;
            return S_OK;
        }
        hr = IXmlReader_MoveToNextAttribute(reader);
    } while (hr == S_OK);
    return FAILED(hr) ? hr : S_FALSE;
}

static HRESULT parse_decimal_u64(PCWSTR text, ULONGLONG *value)
{
    ULONGLONG result = 0;

    if (!text || !*text) return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    while (*text)
    {
        if (*text < L'0' || *text > L'9' || result > (~(ULONGLONG)0 - (*text - L'0')) / 10)
            return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        result = result * 10 + *text++ - L'0';
    }
    *value = result;
    return S_OK;
}

struct block_map_entry
{
    WCHAR *name;
    BOOL seen;
};

static HRESULT add_block_map_entry(struct block_map_entry **entries, ULONG *count, ULONG *capacity,
                                   WCHAR *name)
{
    struct block_map_entry *new_entries;
    ULONG index, new_capacity;

    for (index = 0; index < *count; index++)
        if (!_wcsicmp((*entries)[index].name, name))
            return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    if (*count == *capacity)
    {
        new_capacity = *capacity ? *capacity * 2 : 32;
        if (new_capacity < *capacity || new_capacity > MAXDWORD / sizeof(**entries))
            return E_OUTOFMEMORY;
        new_entries = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *entries,
                                  new_capacity * sizeof(**entries));
        if (!new_entries)
        {
            new_entries = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, new_capacity * sizeof(**entries));
            if (!new_entries) return E_OUTOFMEMORY;
            if (*entries)
            {
                CopyMemory(new_entries, *entries, *count * sizeof(**entries));
                HeapFree(GetProcessHeap(), 0, *entries);
            }
        }
        *entries = new_entries;
        *capacity = new_capacity;
    }
    (*entries)[*count].name = name;
    (*entries)[*count].seen = FALSE;
    (*count)++;
    return S_OK;
}

static HRESULT verify_block_map_payload(PCWSTR path, const BYTE *data, ULONG length,
                                        const struct package_hash_method *method,
                                        package_is_cancelled_callback is_cancelled, void *context)
{
    zlib_filefunc64_def file_functions;
    struct block_map_entry *entries = NULL;
    ULONG entry_count = 0, entry_capacity = 0;
    ULONGLONG block_count = 0;
    ULONGLONG current_size = 0, bytes_read = 0;
    BYTE input[65536], digest[64], expected_digest[64];
    HGLOBAL memory = NULL;
    IStream *stream = NULL;
    IXmlReader *reader = NULL;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    unzFile archive = NULL;
    XmlNodeType node_type;
    HRESULT hr;
    BOOL current_file = FALSE;
    int result;
    ULONG index;

    memory = GlobalAlloc(GMEM_MOVEABLE, length);
    if (!memory) return E_OUTOFMEMORY;
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
            hr = FAILED(hr) ? hr : E_FAIL;
            goto done;
        }
    }
    {
        LARGE_INTEGER zero = {0};
        hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    }
    if (SUCCEEDED(hr)) hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL);
    if (SUCCEEDED(hr)) hr = IXmlReader_SetInput(reader, (IUnknown *)stream);
    if (FAILED(hr)) goto done;
    if (BCryptOpenAlgorithmProvider(&algorithm, method->algorithm, NULL, 0) < 0)
    {
        hr = E_FAIL;
        goto done;
    }
    fill_win32_filefunc64W(&file_functions);
    archive = unzOpen2_64(path, &file_functions);
    if (!archive)
    {
        hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        goto done;
    }

    for (;;)
    {
        const WCHAR *element;
        UINT element_length, depth;

        if (is_cancelled && is_cancelled(context))
        {
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            goto done;
        }
        hr = IXmlReader_Read(reader, &node_type);
        if (FAILED(hr) || hr == S_FALSE) break;
        if (node_type == XmlNodeType_None) break;
        if (node_type != XmlNodeType_Element && node_type != XmlNodeType_EndElement) continue;
        if (FAILED(hr = IXmlReader_GetDepth(reader, &depth)) ||
            FAILED(hr = IXmlReader_GetLocalName(reader, &element, &element_length))) goto done;
        if (node_type == XmlNodeType_Element && depth == 1 && element_length == ARRAYSIZE(L"File") - 1 &&
            !_wcsnicmp(element, L"File", element_length))
        {
            WCHAR *name = NULL, *size_text = NULL;
            WCHAR *header_size_text = NULL;
            CHAR *utf8_name = NULL;
            int utf8_length;
            unz_file_info64 info;
            ULONGLONG parsed_size;
            ULONGLONG header_size;
            BOOL empty_element;

            if (current_file)
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            hr = get_xml_attribute(reader, L"Name", &name);
            if (SUCCEEDED(hr)) hr = get_xml_attribute(reader, L"Size", &size_text);
            if (SUCCEEDED(hr)) hr = get_xml_attribute(reader, L"LfhSize", &header_size_text);
            if (hr != S_OK || FAILED(parse_decimal_u64(size_text, &parsed_size)) ||
                FAILED(parse_decimal_u64(header_size_text, &header_size)) || header_size < 30 || header_size > 65536)
            {
                if (name) HeapFree(GetProcessHeap(), 0, name);
                if (size_text) HeapFree(GetProcessHeap(), 0, size_text);
                if (header_size_text) HeapFree(GetProcessHeap(), 0, header_size_text);
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            HeapFree(GetProcessHeap(), 0, size_text);
            HeapFree(GetProcessHeap(), 0, header_size_text);
            for (index = 0; name[index]; index++)
                if (name[index] == L'\\') name[index] = L'/';
            utf8_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, NULL, 0, NULL, NULL);
            if (!utf8_length || utf8_length > 32768)
            {
                HeapFree(GetProcessHeap(), 0, name);
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            utf8_name = HeapAlloc(GetProcessHeap(), 0, utf8_length);
            if (!utf8_name)
            {
                HeapFree(GetProcessHeap(), 0, name);
                hr = E_OUTOFMEMORY;
                goto done;
            }
            if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, utf8_name,
                                     utf8_length, NULL, NULL) ||
                unzLocateFile(archive, utf8_name, 1) != UNZ_OK ||
                unzGetCurrentFileInfo64(archive, &info, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK ||
                info.uncompressed_size != parsed_size || unzOpenCurrentFile(archive) != UNZ_OK)
            {
                HeapFree(GetProcessHeap(), 0, utf8_name);
                HeapFree(GetProcessHeap(), 0, name);
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            HeapFree(GetProcessHeap(), 0, utf8_name);
            hr = add_block_map_entry(&entries, &entry_count, &entry_capacity, name);
            if (FAILED(hr))
            {
                unzCloseCurrentFile(archive);
                HeapFree(GetProcessHeap(), 0, name);
                goto done;
            }
            current_size = parsed_size;
            bytes_read = 0;
            block_count = 0;
            current_file = TRUE;
            hr = IXmlReader_MoveToElement(reader);
            if (FAILED(hr))
            {
                goto done;
            }
            empty_element = IXmlReader_IsEmptyElement(reader);
            if (empty_element)
            {
                if (current_size)
                {
                    hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                    goto done;
                }
                result = unzCloseCurrentFile(archive);
                current_file = FALSE;
                if (result != UNZ_OK)
                {
                    hr = HRESULT_FROM_WIN32(ERROR_CRC);
                    goto done;
                }
            }
        }
        else if (node_type == XmlNodeType_Element && depth == 2 && element_length == ARRAYSIZE(L"Block") - 1 &&
                 !_wcsnicmp(element, L"Block", element_length))
        {
            WCHAR *hash_text = NULL;
            DWORD expected_length = sizeof(expected_digest);
            ULONGLONG block_length;
            NTSTATUS status;
            int read;
            DWORD decoded_length;

            if (!current_file || bytes_read >= current_size)
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            hr = get_xml_attribute(reader, L"Hash", &hash_text);
            if (hr != S_OK || !CryptStringToBinaryW(hash_text, 0, CRYPT_STRING_BASE64, expected_digest,
                                                    &expected_length, NULL, NULL) ||
                expected_length != method->digest_length)
            {
                if (hash_text) HeapFree(GetProcessHeap(), 0, hash_text);
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            HeapFree(GetProcessHeap(), 0, hash_text);
            block_length = current_size - bytes_read;
            if (block_length > sizeof(input)) block_length = sizeof(input);
            decoded_length = 0;
            while (decoded_length < block_length)
            {
                if (is_cancelled && is_cancelled(context))
                {
                    hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
                    goto done;
                }
                read = unzReadCurrentFile(archive, input + decoded_length, (UINT)(block_length - decoded_length));
                if (read <= 0)
                {
                    hr = HRESULT_FROM_WIN32(ERROR_CRC);
                    goto done;
                }
                decoded_length += read;
            }
            status = BCryptHash(algorithm, NULL, 0, input, decoded_length, digest, method->digest_length);
            if (status < 0)
            {
                hr = HRESULT_FROM_NT(status);
                goto done;
            }
            if (memcmp(digest, expected_digest, method->digest_length))
            {
                hr = TRUST_E_BAD_DIGEST;
                goto done;
            }
            bytes_read += block_length;
            block_count++;
        }
        else if (node_type == XmlNodeType_EndElement && depth == 1 && element_length == ARRAYSIZE(L"File") - 1 &&
                 !_wcsnicmp(element, L"File", element_length))
        {
            ULONGLONG expected_blocks = current_size / sizeof(input) + !!(current_size % sizeof(input));

            if (!current_file || bytes_read != current_size || block_count != expected_blocks)
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            result = unzCloseCurrentFile(archive);
            current_file = FALSE;
            if (result != UNZ_OK)
            {
                hr = HRESULT_FROM_WIN32(ERROR_CRC);
                goto done;
            }
        }
    }
    if (FAILED(hr) || current_file || !entry_count)
    {
        if (SUCCEEDED(hr)) hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        goto done;
    }
    if (unzGoToFirstFile(archive) != UNZ_OK)
    {
        hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        goto done;
    }
    {
        ULONG archive_file_count = 0;
        for (;;)
        {
            unz_file_info64 info;
            CHAR *archive_name;
            WCHAR *wide_name;
            int wide_length;
            BOOL is_directory;

            if (is_cancelled && is_cancelled(context))
            {
                hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
                goto done;
            }
            if (unzGetCurrentFileInfo64(archive, &info, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK ||
                !info.size_filename || info.size_filename > MAXDWORD - 1)
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            archive_name = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)info.size_filename + 1);
            if (!archive_name)
            {
                hr = E_OUTOFMEMORY;
                goto done;
            }
            if (unzGetCurrentFileInfo64(archive, &info, archive_name, (uLong)info.size_filename + 1,
                                        NULL, 0, NULL, 0) != UNZ_OK)
            {
                HeapFree(GetProcessHeap(), 0, archive_name);
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            archive_name[info.size_filename] = 0;
            is_directory = archive_name[info.size_filename - 1] == '/' || archive_name[info.size_filename - 1] == '\\';
            if (is_directory)
            {
                HeapFree(GetProcessHeap(), 0, archive_name);
                goto next_archive_entry;
            }
            if (!_stricmp(archive_name, "AppxBlockMap.xml") || !_stricmp(archive_name, "AppxSignature.p7x"))
            {
                HeapFree(GetProcessHeap(), 0, archive_name);
                goto next_archive_entry;
            }
            wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, archive_name, -1, NULL, 0);
            if (!wide_length)
            {
                HeapFree(GetProcessHeap(), 0, archive_name);
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            wide_name = HeapAlloc(GetProcessHeap(), 0, wide_length * sizeof(WCHAR));
            if (!wide_name)
            {
                HeapFree(GetProcessHeap(), 0, archive_name);
                hr = E_OUTOFMEMORY;
                goto done;
            }
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, archive_name, -1, wide_name, wide_length);
            HeapFree(GetProcessHeap(), 0, archive_name);
            for (index = 0; index < entry_count; index++)
            {
                if (!_wcsicmp(entries[index].name, wide_name))
                {
                    if (entries[index].seen)
                    {
                        HeapFree(GetProcessHeap(), 0, wide_name);
                        hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                        goto done;
                    }
                    entries[index].seen = TRUE;
                    archive_file_count++;
                    break;
                }
            }
            HeapFree(GetProcessHeap(), 0, wide_name);
            if (index == entry_count)
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
next_archive_entry:
            result = unzGoToNextFile(archive);
            if (result == UNZ_END_OF_LIST_OF_FILE) break;
            if (result != UNZ_OK)
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
        }
        if (archive_file_count != entry_count)
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            goto done;
        }
    }
    hr = S_OK;

done:
    if (current_file && archive) unzCloseCurrentFile(archive);
    if (archive) unzClose(archive);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (reader) IXmlReader_Release(reader);
    if (stream) IStream_Release(stream);
    for (index = 0; index < entry_count; index++) HeapFree(GetProcessHeap(), 0, entries[index].name);
    if (entries) HeapFree(GetProcessHeap(), 0, entries);
    return hr;
}

HRESULT package_archive_verify_signature(PCWSTR path, const struct package_identity *identity,
                                         package_is_cancelled_callback is_cancelled, void *context)
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
    if (is_cancelled && is_cancelled(context)) return HRESULT_FROM_WIN32(ERROR_CANCELLED);
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
    {
        DWORD signature_prefix = 0;
        if (signature_length >= sizeof(signature_prefix))
            CopyMemory(&signature_prefix, signature, sizeof(signature_prefix));
        if (signature_length <= sizeof(signature_prefix) || signature_prefix != signature_magic)
        {
            hr = TRUST_E_NOSIGNATURE;
            goto done;
        }
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
    hr = verify_block_map_payload(path, block_map, block_map_length, hash_method, is_cancelled, context);
    if (FAILED(hr))
        goto done;
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
