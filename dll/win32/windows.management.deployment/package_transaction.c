/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Stage and register an MSIX package transactionally
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <windows.h>
#include <shlwapi.h>
#include <strsafe.h>
#include "package_transaction.h"
#include "package_trust.h"

struct installed_dependency
{
    WCHAR *full_name;
    WCHAR *path;
};

static HRESULT package_uri_to_path(IUriRuntimeClass *uri, WCHAR **path)
{
    HSTRING scheme = NULL, absolute_uri = NULL;
    const WCHAR *text;
    WCHAR *result;
    DWORD length = 32768;
    HRESULT hr;

    *path = NULL;
    if (!uri) return E_INVALIDARG;
    hr = IUriRuntimeClass_get_SchemeName(uri, &scheme);
    if (FAILED(hr)) goto done;
    text = WindowsGetStringRawBuffer(scheme, NULL);
    if (!text || _wcsicmp(text, L"file"))
    {
        hr = E_INVALIDARG;
        goto done;
    }
    hr = IUriRuntimeClass_get_AbsoluteUri(uri, &absolute_uri);
    if (FAILED(hr)) goto done;
    result = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)length * sizeof(WCHAR));
    if (!result)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    hr = PathCreateFromUrlW(WindowsGetStringRawBuffer(absolute_uri, NULL), result, &length, 0);
    if (FAILED(hr))
    {
        HeapFree(GetProcessHeap(), 0, result);
        goto done;
    }
    *path = result;

done:
    if (absolute_uri) WindowsDeleteString(absolute_uri);
    if (scheme) WindowsDeleteString(scheme);
    return hr;
}

static HRESULT get_package_volume_root(WCHAR **root)
{
    DWORD length;
    WCHAR *program_files, *path;
    HRESULT hr;

    *root = NULL;
    length = GetEnvironmentVariableW(L"ProgramFiles", NULL, 0);
    if (!length) return HRESULT_FROM_WIN32(GetLastError());
    program_files = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)length * sizeof(WCHAR));
    if (!program_files) return E_OUTOFMEMORY;
    if (GetEnvironmentVariableW(L"ProgramFiles", program_files, length) >= length)
    {
        HeapFree(GetProcessHeap(), 0, program_files);
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
    }
    path = HeapAlloc(GetProcessHeap(), 0, ((SIZE_T)length + ARRAYSIZE(L"\\WindowsApps")) * sizeof(WCHAR));
    if (!path)
    {
        HeapFree(GetProcessHeap(), 0, program_files);
        return E_OUTOFMEMORY;
    }
    hr = StringCchPrintfW(path, length + ARRAYSIZE(L"\\WindowsApps"), L"%s\\WindowsApps", program_files);
    HeapFree(GetProcessHeap(), 0, program_files);
    if (FAILED(hr))
    {
        HeapFree(GetProcessHeap(), 0, path);
        return hr;
    }
    *root = path;
    return S_OK;
}

static void remove_package_tree(PCWSTR path)
{
    WIN32_FIND_DATAW find;
    WCHAR *pattern;
    SIZE_T path_length, pattern_length;
    HANDLE search;

    path_length = wcslen(path);
    pattern_length = path_length + ARRAYSIZE(L"\\*");
    pattern = HeapAlloc(GetProcessHeap(), 0, pattern_length * sizeof(WCHAR));
    if (!pattern) return;
    if (FAILED(StringCchPrintfW(pattern, pattern_length, L"%s\\*", path)))
    {
        HeapFree(GetProcessHeap(), 0, pattern);
        return;
    }
    search = FindFirstFileW(pattern, &find);
    HeapFree(GetProcessHeap(), 0, pattern);
    if (search != INVALID_HANDLE_VALUE)
    {
        do
        {
            WCHAR *child;
            SIZE_T child_length;

            if (!wcscmp(find.cFileName, L".") || !wcscmp(find.cFileName, L"..")) continue;
            child_length = path_length + wcslen(find.cFileName) + 2;
            child = HeapAlloc(GetProcessHeap(), 0, child_length * sizeof(WCHAR));
            if (!child) continue;
            if (SUCCEEDED(StringCchPrintfW(child, child_length, L"%s\\%s", path, find.cFileName)))
            {
                if ((find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    !(find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                {
                    remove_package_tree(child);
                    RemoveDirectoryW(child);
                }
                else
                {
                    SetFileAttributesW(child, FILE_ATTRIBUTE_NORMAL);
                    if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryW(child);
                    else DeleteFileW(child);
                }
            }
            HeapFree(GetProcessHeap(), 0, child);
        } while (FindNextFileW(search, &find));
        FindClose(search);
    }
    RemoveDirectoryW(path);
}

static HRESULT ensure_package_volume(PCWSTR path)
{
    DWORD attributes = GetFileAttributesW(path);

    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        if (!CreateDirectoryW(path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
            return HRESULT_FROM_WIN32(GetLastError());
        attributes = GetFileAttributesW(path);
    }
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    return S_OK;
}

static HRESULT install_package_archive(PCWSTR archive_path, struct package_identity *identity,
                                       WCHAR **installed_path,
                                       package_is_cancelled_callback is_cancelled, void *context)
{
    WCHAR *volume = NULL, *destination = NULL, *staging = NULL;
    WCHAR guid_text[40];
    GUID guid;
    SIZE_T path_length;
    HRESULT hr;
    DWORD attributes;

    *installed_path = NULL;
    hr = package_archive_read_identity(archive_path, identity);
    if (FAILED(hr)) return hr;
    if (is_cancelled && is_cancelled(context))
    {
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        goto done;
    }
    hr = package_archive_verify_signature(archive_path, identity, is_cancelled, context);
    if (FAILED(hr)) goto done;
    if (is_cancelled && is_cancelled(context))
    {
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        goto done;
    }
    hr = get_package_volume_root(&volume);
    if (FAILED(hr)) goto done;
    hr = ensure_package_volume(volume);
    if (FAILED(hr)) goto done;
    path_length = wcslen(volume) + 1 + wcslen(identity->full_name) +
                  ARRAYSIZE(L".LiberNT-{00000000-0000-0000-0000-000000000000}");
    destination = HeapAlloc(GetProcessHeap(), 0, path_length * sizeof(WCHAR));
    staging = HeapAlloc(GetProcessHeap(), 0, path_length * sizeof(WCHAR));
    if (!destination || !staging)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    hr = StringCchPrintfW(destination, path_length, L"%s\\%s", volume, identity->full_name);
    if (FAILED(hr)) goto done;
    attributes = GetFileAttributesW(destination);
    if (attributes != INVALID_FILE_ATTRIBUTES)
    {
        hr = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
        goto done;
    }
    hr = CoCreateGuid(&guid);
    if (FAILED(hr)) goto done;
    if (!StringFromGUID2(&guid, guid_text, ARRAYSIZE(guid_text)))
    {
        hr = E_FAIL;
        goto done;
    }
    hr = StringCchPrintfW(staging, path_length, L"%s\\%s.LiberNT-%s", volume, identity->full_name, guid_text);
    if (FAILED(hr)) goto done;
    if (!CreateDirectoryW(staging, NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto done;
    }
    hr = package_archive_stage(archive_path, staging, is_cancelled, context);
    if (FAILED(hr)) goto rollback;
    if (is_cancelled && is_cancelled(context))
    {
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        goto rollback;
    }
    if (!MoveFileExW(staging, destination, MOVEFILE_WRITE_THROUGH))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto rollback;
    }
    if (is_cancelled && is_cancelled(context))
    {
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        remove_package_tree(destination);
        goto done;
    }
    hr = package_store_register(identity->full_name, destination);
    if (FAILED(hr))
    {
        remove_package_tree(destination);
        goto done;
    }
    *installed_path = destination;
    destination = NULL;
    hr = S_OK;
    goto done;

rollback:
    remove_package_tree(staging);

done:
    if (volume) HeapFree(GetProcessHeap(), 0, volume);
    if (destination) HeapFree(GetProcessHeap(), 0, destination);
    if (staging) HeapFree(GetProcessHeap(), 0, staging);
    if (FAILED(hr)) package_identity_clear(identity);
    return hr;
}

static void rollback_dependencies(struct installed_dependency *installed, ULONG count)
{
    while (count)
    {
        struct installed_dependency *dependency = &installed[--count];
        if (SUCCEEDED(package_store_unregister(dependency->full_name, dependency->path)))
            remove_package_tree(dependency->path);
        HeapFree(GetProcessHeap(), 0, dependency->full_name);
        HeapFree(GetProcessHeap(), 0, dependency->path);
    }
    if (installed) HeapFree(GetProcessHeap(), 0, installed);
}

HRESULT package_transaction_add(IUriRuntimeClass *uri, IIterable_Uri *dependencies, DeploymentOptions options,
                                package_is_cancelled_callback is_cancelled, void *context)
{
    struct installed_dependency *installed = NULL;
    ULONG installed_count = 0, installed_capacity = 0;
    IUriRuntimeClass *dependency_uri = NULL;
    IIterator_Uri *iterator = NULL;
    HRESULT hr;
    BOOLEAN has_current;
    WCHAR *archive_path = NULL, *root_path = NULL;
    struct package_identity identity;
    WCHAR *installed_path = NULL;
    ULONG index;

    if (!uri) return E_INVALIDARG;
    if (options & DeploymentOptions_DevelopmentMode) return E_INVALIDARG;
    if (is_cancelled && is_cancelled(context)) return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    if (dependencies)
    {
        hr = IIterable_Uri_First(dependencies, &iterator);
        if (FAILED(hr)) goto done;
        for (;;)
        {
            if (is_cancelled && is_cancelled(context))
            {
                hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
                break;
            }
            hr = IIterator_Uri_get_HasCurrent(iterator, &has_current);
            if (FAILED(hr) || !has_current) break;
            hr = IIterator_Uri_get_Current(iterator, &dependency_uri);
            if (FAILED(hr)) break;
            hr = package_uri_to_path(dependency_uri, &archive_path);
            IUriRuntimeClass_Release(dependency_uri);
            dependency_uri = NULL;
            if (FAILED(hr)) break;
            ZeroMemory(&identity, sizeof(identity));
            hr = package_archive_read_identity(archive_path, &identity);
            if (FAILED(hr))
            {
                HeapFree(GetProcessHeap(), 0, archive_path);
                archive_path = NULL;
                break;
            }
            hr = package_store_get_path(identity.full_name, &root_path);
            if (SUCCEEDED(hr))
            {
                HeapFree(GetProcessHeap(), 0, archive_path);
                archive_path = NULL;
                HeapFree(GetProcessHeap(), 0, root_path);
                root_path = NULL;
                package_identity_clear(&identity);
                hr = IIterator_Uri_MoveNext(iterator, &has_current);
                if (FAILED(hr) || !has_current) break;
                continue;
            }
            if (hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) && hr != HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND))
            {
                HeapFree(GetProcessHeap(), 0, archive_path);
                archive_path = NULL;
                package_identity_clear(&identity);
                break;
            }
            package_identity_clear(&identity);
            ZeroMemory(&identity, sizeof(identity));
            hr = install_package_archive(archive_path, &identity, &installed_path, is_cancelled, context);
            HeapFree(GetProcessHeap(), 0, archive_path);
            archive_path = NULL;
            if (FAILED(hr)) break;
            if (installed_count == installed_capacity)
            {
                ULONG capacity = installed_capacity ? installed_capacity * 2 : 4;
                struct installed_dependency *new_installed = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                                           installed, capacity * sizeof(*installed));
                if (!new_installed)
                {
                    new_installed = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, capacity * sizeof(*installed));
                    if (!new_installed)
                    {
                        package_store_unregister(identity.full_name, installed_path);
                        remove_package_tree(installed_path);
                        HeapFree(GetProcessHeap(), 0, installed_path);
                        package_identity_clear(&identity);
                        hr = E_OUTOFMEMORY;
                        break;
                    }
                    if (installed)
                    {
                        CopyMemory(new_installed, installed, installed_count * sizeof(*installed));
                        HeapFree(GetProcessHeap(), 0, installed);
                    }
                }
                installed = new_installed;
                installed_capacity = capacity;
            }
            installed[installed_count].full_name = identity.full_name;
            installed[installed_count].path = installed_path;
            identity.full_name = NULL;
            installed_path = NULL;
            installed_count++;
            package_identity_clear(&identity);
            hr = IIterator_Uri_MoveNext(iterator, &has_current);
            if (FAILED(hr) || !has_current) break;
        }
        IIterator_Uri_Release(iterator);
        iterator = NULL;
        if (FAILED(hr)) goto done;
    }
    if (is_cancelled && is_cancelled(context))
    {
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        goto done;
    }
    hr = package_uri_to_path(uri, &archive_path);
    if (FAILED(hr)) goto done;
    ZeroMemory(&identity, sizeof(identity));
    hr = install_package_archive(archive_path, &identity, &installed_path, is_cancelled, context);
    if (SUCCEEDED(hr))
    {
        HeapFree(GetProcessHeap(), 0, installed_path);
        package_identity_clear(&identity);
    }

done:
    if (iterator) IIterator_Uri_Release(iterator);
    if (dependency_uri) IUriRuntimeClass_Release(dependency_uri);
    if (archive_path) HeapFree(GetProcessHeap(), 0, archive_path);
    if (root_path) HeapFree(GetProcessHeap(), 0, root_path);
    if (installed_path) HeapFree(GetProcessHeap(), 0, installed_path);
    if (FAILED(hr)) rollback_dependencies(installed, installed_count);
    else
    {
        for (index = 0; index < installed_count; index++)
        {
            HeapFree(GetProcessHeap(), 0, installed[index].full_name);
            HeapFree(GetProcessHeap(), 0, installed[index].path);
        }
        if (installed) HeapFree(GetProcessHeap(), 0, installed);
    }
    return hr;
}
