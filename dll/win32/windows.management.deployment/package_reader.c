/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Read package identity from an MSIX archive manifest
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#define COBJMACROS
#include <windows.h>
#include <stdint.h>
#include <xmllite.h>
#include <appmodel.h>
#include <minizip/ioapi.h>
#include <minizip/iowin32.h>
#include <minizip/unzip.h>
#include "package_reader.h"

static HRESULT copy_xml_attribute(IXmlReader *reader, PCWSTR wanted_name, WCHAR **value)
{
    const WCHAR *name, *text;
    UINT name_length, text_length;
    HRESULT hr;

    *value = NULL;
    hr = IXmlReader_MoveToFirstAttribute(reader);
    if (hr == S_FALSE)
        return S_FALSE;
    if (FAILED(hr))
        return hr;
    for (;;)
    {
        if (FAILED(hr = IXmlReader_GetLocalName(reader, &name, &name_length)))
            return hr;
        if (wcslen(wanted_name) == name_length && !_wcsnicmp(name, wanted_name, name_length))
        {
            if (FAILED(hr = IXmlReader_GetValue(reader, &text, &text_length)))
                return hr;
            if ((SIZE_T)text_length + 1 > SIZE_MAX / sizeof(WCHAR))
                return E_OUTOFMEMORY;
            *value = HeapAlloc(GetProcessHeap(), 0, ((SIZE_T)text_length + 1) * sizeof(WCHAR));
            if (!*value)
                return E_OUTOFMEMORY;
            CopyMemory(*value, text, text_length * sizeof(WCHAR));
            (*value)[text_length] = UNICODE_NULL;
            return S_OK;
        }
        hr = IXmlReader_MoveToNextAttribute(reader);
        if (hr == S_FALSE)
            return S_FALSE;
        if (FAILED(hr))
            return hr;
    }
}

static HRESULT read_manifest(unzFile archive, IStream **stream)
{
    unz_file_info64 info;
    HGLOBAL memory;
    HRESULT hr;
    int result;

    if (unzLocateFile(archive, "AppxManifest.xml", 1) != UNZ_OK)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    if (unzGetCurrentFileInfo64(archive, &info, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK ||
        !info.uncompressed_size || info.uncompressed_size > SIZE_MAX)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    memory = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)info.uncompressed_size);
    if (!memory)
        return E_OUTOFMEMORY;
    hr = CreateStreamOnHGlobal(memory, TRUE, stream);
    if (FAILED(hr))
    {
        GlobalFree(memory);
        return hr;
    }
    result = unzOpenCurrentFile(archive);
    if (result != UNZ_OK)
    {
        IStream_Release(*stream);
        *stream = NULL;
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }

    {
        BYTE buffer[64 * 1024];
        ZPOS64_T remaining = info.uncompressed_size;

        while (remaining)
        {
            UINT request = remaining > sizeof(buffer) ? sizeof(buffer) : (UINT)remaining;
            int read = unzReadCurrentFile(archive, buffer, request);
            ULONG written = 0;

            if (read <= 0 || (UINT)read > request || FAILED(hr = IStream_Write(*stream, buffer, read, &written)) || written != (ULONG)read)
            {
                unzCloseCurrentFile(archive);
                IStream_Release(*stream);
                *stream = NULL;
                return FAILED(hr) ? hr : HRESULT_FROM_WIN32(ERROR_CRC);
            }
            remaining -= read;
        }
    }

    result = unzCloseCurrentFile(archive);
    if (result != UNZ_OK)
    {
        IStream_Release(*stream);
        *stream = NULL;
        return HRESULT_FROM_WIN32(ERROR_CRC);
    }
    LARGE_INTEGER zero = {0};
    return IStream_Seek(*stream, zero, STREAM_SEEK_SET, NULL);
}

static HRESULT parse_version(PCWSTR text, PACKAGE_VERSION *version)
{
    USHORT components[4] = {0};
    UINT component = 0, digits = 0;

    for (; *text; text++)
    {
        if (*text == L'.')
        {
            if (!digits || component == ARRAYSIZE(components) - 1)
                return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            component++;
            digits = 0;
        }
        else if (*text >= L'0' && *text <= L'9')
        {
            UINT value = components[component] * 10 + *text - L'0';

            if (value > 0xffff)
                return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            components[component] = value;
            digits++;
        }
        else
        {
            return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        }
    }
    if (component != ARRAYSIZE(components) - 1 || !digits)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    version->Major = components[0];
    version->Minor = components[1];
    version->Build = components[2];
    version->Revision = components[3];
    return S_OK;
}

static HRESULT parse_architecture(PCWSTR text, UINT32 *architecture)
{
    static const struct
    {
        PCWSTR name;
        UINT32 value;
    } architectures[] =
    {
        {L"x86", PROCESSOR_ARCHITECTURE_INTEL},
        {L"arm", PROCESSOR_ARCHITECTURE_ARM},
        {L"x64", PROCESSOR_ARCHITECTURE_AMD64},
        {L"neutral", PROCESSOR_ARCHITECTURE_NEUTRAL},
        {L"arm64", PROCESSOR_ARCHITECTURE_ARM64},
        {L"x86a64", PROCESSOR_ARCHITECTURE_IA32_ON_ARM64},
    };
    UINT index;

    for (index = 0; index < ARRAYSIZE(architectures); index++)
    {
        if (!_wcsicmp(text, architectures[index].name))
        {
            *architecture = architectures[index].value;
            return S_OK;
        }
    }
    return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
}

void package_identity_clear(struct package_identity *identity)
{
    if (!identity)
        return;
    if (identity->full_name) HeapFree(GetProcessHeap(), 0, identity->full_name);
    if (identity->family_name) HeapFree(GetProcessHeap(), 0, identity->family_name);
    if (identity->name) HeapFree(GetProcessHeap(), 0, identity->name);
    if (identity->publisher) HeapFree(GetProcessHeap(), 0, identity->publisher);
    if (identity->version) HeapFree(GetProcessHeap(), 0, identity->version);
    if (identity->architecture) HeapFree(GetProcessHeap(), 0, identity->architecture);
    if (identity->resource_id) HeapFree(GetProcessHeap(), 0, identity->resource_id);
    ZeroMemory(identity, sizeof(*identity));
}

HRESULT package_archive_read_identity(PCWSTR path, struct package_identity *identity)
{
    zlib_filefunc64_def file_functions;
    IStream *stream = NULL;
    IXmlReader *reader = NULL;
    unzFile archive;
    XmlNodeType node_type;
    HRESULT hr;
    BOOL found_identity = FALSE;
    PACKAGE_ID package_id = {0};
    UINT32 length;

    if (!path || !identity)
        return E_INVALIDARG;
    ZeroMemory(identity, sizeof(*identity));
    fill_win32_filefunc64W(&file_functions);
    archive = unzOpen2_64(path, &file_functions);
    if (!archive)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);

    hr = read_manifest(archive, &stream);
    unzClose(archive);
    if (FAILED(hr))
        return hr;
    hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL);
    if (SUCCEEDED(hr))
        hr = IXmlReader_SetInput(reader, (IUnknown *)stream);
    IStream_Release(stream);
    if (FAILED(hr))
        goto done;

    for (;;)
    {
        const WCHAR *name;
        UINT name_length, depth;

        hr = IXmlReader_Read(reader, &node_type);
        if (hr == S_FALSE || (SUCCEEDED(hr) && node_type == XmlNodeType_None))
            break;
        if (FAILED(hr))
            goto done;
        if (node_type != XmlNodeType_Element)
            continue;
        if (FAILED(hr = IXmlReader_GetDepth(reader, &depth)))
            goto done;
        if (depth != 1)
            continue;
        if (FAILED(hr = IXmlReader_GetLocalName(reader, &name, &name_length)))
            goto done;
        if (name_length != ARRAYSIZE(L"Identity") - 1 || _wcsnicmp(name, L"Identity", name_length))
            continue;
        if (found_identity)
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            goto done;
        }
        found_identity = TRUE;
        hr = copy_xml_attribute(reader, L"Name", &identity->name);
        if (hr == S_FALSE) hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        if (FAILED(hr)) goto done;
        hr = copy_xml_attribute(reader, L"Publisher", &identity->publisher);
        if (hr == S_FALSE) hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        if (FAILED(hr)) goto done;
        hr = copy_xml_attribute(reader, L"Version", &identity->version);
        if (hr == S_FALSE) hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        if (FAILED(hr)) goto done;
        hr = copy_xml_attribute(reader, L"ProcessorArchitecture", &identity->architecture);
        if (hr == S_FALSE)
        {
            identity->architecture = HeapAlloc(GetProcessHeap(), 0, sizeof(L"neutral"));
            if (!identity->architecture)
            {
                hr = E_OUTOFMEMORY;
                goto done;
            }
            CopyMemory(identity->architecture, L"neutral", sizeof(L"neutral"));
            hr = S_OK;
        }
        if (FAILED(hr)) goto done;
        hr = copy_xml_attribute(reader, L"ResourceId", &identity->resource_id);
        if (hr == S_FALSE)
            hr = S_OK;
        if (FAILED(hr)) goto done;
        if (identity->resource_id && !identity->resource_id[0])
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            goto done;
        }
    }
    if (!found_identity)
    {
        hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        goto done;
    }

    package_id.name = identity->name;
    package_id.publisher = identity->publisher;
    package_id.resourceId = identity->resource_id;
    hr = parse_version(identity->version, &package_id.version);
    if (FAILED(hr)) goto done;
    hr = parse_architecture(identity->architecture, &package_id.processorArchitecture);
    if (FAILED(hr)) goto done;

    length = 0;
    hr = PackageFullNameFromId(&package_id, &length, NULL);
    if (hr != ERROR_INSUFFICIENT_BUFFER)
    {
        hr = HRESULT_FROM_WIN32(hr);
        goto done;
    }
    identity->full_name = HeapAlloc(GetProcessHeap(), 0, length * sizeof(WCHAR));
    if (!identity->full_name)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    hr = HRESULT_FROM_WIN32(PackageFullNameFromId(&package_id, &length, identity->full_name));
    if (FAILED(hr)) goto done;

    length = 0;
    hr = PackageFamilyNameFromId(&package_id, &length, NULL);
    if (hr != ERROR_INSUFFICIENT_BUFFER)
    {
        hr = HRESULT_FROM_WIN32(hr);
        goto done;
    }
    identity->family_name = HeapAlloc(GetProcessHeap(), 0, length * sizeof(WCHAR));
    if (!identity->family_name)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    hr = HRESULT_FROM_WIN32(PackageFamilyNameFromId(&package_id, &length, identity->family_name));

done:
    if (reader) IXmlReader_Release(reader);
    if (FAILED(hr)) package_identity_clear(identity);
    return hr;
}
