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
        if (wcslen(wanted_name) == name_length && !wcsncmp(name, wanted_name, name_length))
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

static HRESULT archive_entry_path(PCWSTR root, const char *entry, BOOL is_directory, WCHAR **path)
{
    int length;
    WCHAR *name, *result, *cursor;
    SIZE_T root_length = wcslen(root), name_length;

    *path = NULL;
    length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, entry, -1, NULL, 0);
    if (!length)
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    name = HeapAlloc(GetProcessHeap(), 0, length * sizeof(WCHAR));
    if (!name)
        return E_OUTOFMEMORY;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, entry, -1, name, length))
    {
        HeapFree(GetProcessHeap(), 0, name);
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }
    name_length = wcslen(name);
    if (is_directory && name_length && name[name_length - 1] == L'/')
    {
        name[--name_length] = UNICODE_NULL;
        if (!name_length)
        {
            HeapFree(GetProcessHeap(), 0, name);
            return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        }
    }
    if (!name_length || name[0] == L'/' || name[0] == L'\\' ||
        (name_length > 1 && name[1] == L':'))
    {
        HeapFree(GetProcessHeap(), 0, name);
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }
    for (cursor = name; *cursor; cursor++)
    {
        if (*cursor == L'\\')
            *cursor = L'/';
        if (*cursor < 0x20 || *cursor == L':')
        {
            HeapFree(GetProcessHeap(), 0, name);
            return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        }
    }
    cursor = name;
    while (*cursor)
    {
        WCHAR *component = cursor;
        SIZE_T component_length;
        WCHAR device[5] = {0};
        while (*cursor && *cursor != L'/') cursor++;
        component_length = cursor - component;
        if (cursor == component || (cursor - component == 1 && component[0] == L'.') ||
            (cursor - component == 2 && component[0] == L'.' && component[1] == L'.') ||
            cursor[-1] == L'.' || cursor[-1] == L' ')
        {
            HeapFree(GetProcessHeap(), 0, name);
            return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
        }
        if (component_length >= 3 && component_length <= 4)
        {
            SIZE_T index;
            for (index = 0; index < component_length && component[index] != L'.'; index++)
                device[index] = component[index];
            if (!_wcsicmp(device, L"CON") || !_wcsicmp(device, L"PRN") ||
                !_wcsicmp(device, L"AUX") || !_wcsicmp(device, L"NUL") ||
                (!_wcsnicmp(device, L"COM", 3) && device[3] >= L'1' && device[3] <= L'9') ||
                (!_wcsnicmp(device, L"LPT", 3) && device[3] >= L'1' && device[3] <= L'9'))
            {
                HeapFree(GetProcessHeap(), 0, name);
                return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            }
        }
        for (cursor = component; cursor < component + component_length; cursor++)
        {
            if (*cursor == L'<' || *cursor == L'>' || *cursor == L'"' || *cursor == L'|' ||
                *cursor == L'?' || *cursor == L'*')
            {
                HeapFree(GetProcessHeap(), 0, name);
                return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            }
        }
        if (*cursor) cursor++;
    }
    result = HeapAlloc(GetProcessHeap(), 0, (root_length + name_length + 2) * sizeof(WCHAR));
    if (!result)
    {
        HeapFree(GetProcessHeap(), 0, name);
        return E_OUTOFMEMORY;
    }
    swprintf(result, root_length + name_length + 2, L"%s\\%s", root, name);
    for (cursor = result + root_length + 1; *cursor; cursor++)
        if (*cursor == L'/') *cursor = L'\\';
    HeapFree(GetProcessHeap(), 0, name);
    *path = result;
    return S_OK;
}

static HRESULT create_archive_directory(PCWSTR path)
{
    WCHAR *copy, *cursor;
    DWORD attributes;

    copy = HeapAlloc(GetProcessHeap(), 0, (wcslen(path) + 1) * sizeof(WCHAR));
    if (!copy) return E_OUTOFMEMORY;
    wcscpy(copy, path);
    for (cursor = copy + 3; *cursor; cursor++)
    {
        if (*cursor != L'\\') continue;
        *cursor = UNICODE_NULL;
        if (!CreateDirectoryW(copy, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        {
            DWORD error = GetLastError();
            HeapFree(GetProcessHeap(), 0, copy);
            return HRESULT_FROM_WIN32(error);
        }
        attributes = GetFileAttributesW(copy);
        if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        {
            HeapFree(GetProcessHeap(), 0, copy);
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        }
        *cursor = L'\\';
    }
    if (!CreateDirectoryW(copy, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        DWORD error = GetLastError();
        HeapFree(GetProcessHeap(), 0, copy);
        return HRESULT_FROM_WIN32(error);
    }
    attributes = GetFileAttributesW(copy);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
    {
        HeapFree(GetProcessHeap(), 0, copy);
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }
    HeapFree(GetProcessHeap(), 0, copy);
    return S_OK;
}

HRESULT package_archive_stage(PCWSTR archive_path, PCWSTR stage_path,
                              package_is_cancelled_callback is_cancelled, void *context)
{
    zlib_filefunc64_def file_functions;
    unz_file_info64 info;
    unzFile archive;
    WCHAR *path = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE buffer[64 * 1024];
    HRESULT hr = S_OK;
    int result;

    if (!archive_path || !stage_path) return E_INVALIDARG;
    fill_win32_filefunc64W(&file_functions);
    archive = unzOpen2_64(archive_path, &file_functions);
    if (!archive) return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    if (unzGoToFirstFile(archive) != UNZ_OK)
    {
        unzClose(archive);
        return HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    }
    for (;;)
    {
        char *entry = NULL;
        DWORD entry_length;
        BOOL is_directory;
        ZPOS64_T remaining;
        DWORD unix_type;

        if (is_cancelled && is_cancelled(context))
        {
            hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            break;
        }
        if (unzGetCurrentFileInfo64(archive, &info, NULL, 0, NULL, 0, NULL, 0) != UNZ_OK ||
            !info.size_filename || info.size_filename > MAXDWORD - 1 || info.uncompressed_size > MAXLONGLONG)
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            break;
        }
        entry_length = (DWORD)info.size_filename + 1;
        entry = HeapAlloc(GetProcessHeap(), 0, entry_length);
        if (!entry)
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        if (unzGetCurrentFileInfo64(archive, &info, entry, entry_length, NULL, 0, NULL, 0) != UNZ_OK)
        {
            HeapFree(GetProcessHeap(), 0, entry);
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            break;
        }
        entry[info.size_filename] = 0;
        is_directory = info.size_filename && (entry[info.size_filename - 1] == '/' || entry[info.size_filename - 1] == '\\');
        result = archive_entry_path(stage_path, entry, is_directory, &path);
        HeapFree(GetProcessHeap(), 0, entry);
        if (FAILED(result))
        {
            hr = result;
            break;
        }
        if (is_directory)
        {
            hr = create_archive_directory(path);
            HeapFree(GetProcessHeap(), 0, path);
            path = NULL;
            if (FAILED(hr)) break;
            goto next_archive_entry;
        }
        unix_type = (info.external_fa >> 16) & 0170000;
        if (unix_type && unix_type != (is_directory ? 0040000 : 0100000))
        {
            hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
            break;
        }
        {
            WCHAR *slash = wcsrchr(path, L'\\');
            if (slash)
            {
                *slash = UNICODE_NULL;
                hr = create_archive_directory(path);
                *slash = L'\\';
                if (FAILED(hr)) break;
            }
        }
        file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (file == INVALID_HANDLE_VALUE)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            break;
        }
        if (unzOpenCurrentFile(archive) != UNZ_OK)
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            break;
        }
        remaining = info.uncompressed_size;
        while (remaining)
        {
            UINT request = remaining > sizeof(buffer) ? sizeof(buffer) : (UINT)remaining;
            int read = unzReadCurrentFile(archive, buffer, request);
            DWORD output;

            if (is_cancelled && is_cancelled(context))
            {
                hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
                break;
            }
            if (read <= 0 || (UINT)read > request || !WriteFile(file, buffer, read, &output, NULL) || output != (DWORD)read)
            {
                hr = HRESULT_FROM_WIN32(read < 0 ? ERROR_CRC : GetLastError());
                break;
            }
            remaining -= read;
        }
        if (SUCCEEDED(hr) && unzCloseCurrentFile(archive) != UNZ_OK)
            hr = HRESULT_FROM_WIN32(ERROR_CRC);
        else if (FAILED(hr))
            unzCloseCurrentFile(archive);
        CloseHandle(file);
        file = INVALID_HANDLE_VALUE;
        HeapFree(GetProcessHeap(), 0, path);
        path = NULL;
        if (FAILED(hr)) break;
next_archive_entry:
        result = unzGoToNextFile(archive);
        if (result == UNZ_END_OF_LIST_OF_FILE) break;
        if (result != UNZ_OK)
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            break;
        }
    }
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (path) HeapFree(GetProcessHeap(), 0, path);
    result = unzClose(archive);
    if (SUCCEEDED(hr) && result != UNZ_OK) hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
    return hr;
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
    UINT manifest_namespace = 0;
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
        const WCHAR *namespace_uri;
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
        if (!depth)
        {
            static const WCHAR windows8_namespace[] = L"http://schemas.microsoft.com/appx/2010/manifest";
            static const WCHAR windows10_namespace[] = L"http://schemas.microsoft.com/appx/manifest/foundation/windows10";

            if (FAILED(hr = IXmlReader_GetLocalName(reader, &name, &name_length)))
                goto done;
            if (name_length != ARRAYSIZE(L"Package") - 1 || wcsncmp(name, L"Package", name_length))
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            if (FAILED(hr = IXmlReader_GetNamespaceUri(reader, &namespace_uri, &name_length)))
                goto done;
            if (name_length == ARRAYSIZE(windows8_namespace) - 1 &&
                !wcsncmp(namespace_uri, windows8_namespace, name_length))
                manifest_namespace = 1;
            else if (name_length == ARRAYSIZE(windows10_namespace) - 1 &&
                     !wcsncmp(namespace_uri, windows10_namespace, name_length))
                manifest_namespace = 2;
            else
            {
                hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
                goto done;
            }
            continue;
        }
        if (depth != 1)
            continue;
        if (FAILED(hr = IXmlReader_GetLocalName(reader, &name, &name_length)))
            goto done;
        if (name_length != ARRAYSIZE(L"Identity") - 1 || wcsncmp(name, L"Identity", name_length))
            continue;
        if (FAILED(hr = IXmlReader_GetNamespaceUri(reader, &namespace_uri, &name_length)))
            goto done;
        if ((manifest_namespace == 1 &&
             (name_length != ARRAYSIZE(L"http://schemas.microsoft.com/appx/2010/manifest") - 1 ||
              wcsncmp(namespace_uri, L"http://schemas.microsoft.com/appx/2010/manifest", name_length))) ||
            (manifest_namespace == 2 &&
             (name_length != ARRAYSIZE(L"http://schemas.microsoft.com/appx/manifest/foundation/windows10") - 1 ||
              wcsncmp(namespace_uri, L"http://schemas.microsoft.com/appx/manifest/foundation/windows10", name_length))) ||
            !manifest_namespace)
        {
            hr = HRESULT_FROM_WIN32(ERROR_BAD_FORMAT);
            goto done;
        }
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
