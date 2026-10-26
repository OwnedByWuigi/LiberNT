/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Per-user package repository operations
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <windows.h>
#include <appmodel.h>
#include <strsafe.h>
#include "package_store.h"

static const WCHAR package_repository_key[] =
    L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages";

static HRESULT validate_full_name(PCWSTR full_name)
{
    WCHAR family_name[PACKAGE_FAMILY_NAME_MAX_LENGTH + 1];
    UINT32 length = ARRAYSIZE(family_name);
    LONG error;

    if (!full_name || !full_name[0]) return E_INVALIDARG;
    error = PackageFamilyNameFromFullName(full_name, &length, family_name);
    return error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);
}

static HRESULT open_package_key(PCWSTR full_name, REGSAM access, HKEY *key)
{
    WCHAR path[ARRAYSIZE(package_repository_key) + 1 + PACKAGE_FULL_NAME_MAX_LENGTH];
    HRESULT hr;
    LONG error;

    *key = NULL;
    if (FAILED(hr = validate_full_name(full_name))) return hr;
    if (FAILED(hr = StringCchPrintfW(path, ARRAYSIZE(path), L"%s\\%s", package_repository_key, full_name)))
        return hr;
    error = RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, access, key);
    return error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);
}

HRESULT package_store_register(PCWSTR full_name, PCWSTR root_path)
{
    WCHAR pending_name[PACKAGE_FULL_NAME_MAX_LENGTH + 48] = {0}, guid_text[40];
    DWORD attributes;
    HKEY repository = NULL, pending = NULL;
    GUID guid;
    HRESULT hr;
    LONG error;

    if (!root_path || !root_path[0]) return E_INVALIDARG;
    if (FAILED(hr = validate_full_name(full_name))) return hr;
    attributes = GetFileAttributesW(root_path);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return HRESULT_FROM_WIN32(attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_INVALID_PARAMETER);
    error = RegCreateKeyExW(HKEY_CURRENT_USER, package_repository_key, 0, NULL, 0,
                            KEY_WRITE | KEY_ENUMERATE_SUB_KEYS, NULL, &repository, NULL);
    if (error != ERROR_SUCCESS) return HRESULT_FROM_WIN32(error);
    hr = CoCreateGuid(&guid);
    if (FAILED(hr)) goto done;
    if (!StringFromGUID2(&guid, guid_text, ARRAYSIZE(guid_text)))
    {
        hr = E_FAIL;
        goto done;
    }
    hr = StringCchPrintfW(pending_name, ARRAYSIZE(pending_name), L"%s.LiberNT-%s", full_name, guid_text);
    if (FAILED(hr)) goto done;
    error = RegCreateKeyExW(repository, pending_name, 0, NULL, REG_OPTION_NON_VOLATILE,
                            KEY_SET_VALUE, NULL, &pending, NULL);
    if (error != ERROR_SUCCESS)
    {
        hr = HRESULT_FROM_WIN32(error);
        goto done;
    }
    error = RegSetValueExW(pending, L"PackageRootFolder", 0, REG_SZ, (const BYTE *)root_path,
                           ((DWORD)wcslen(root_path) + 1) * sizeof(WCHAR));
    if (error != ERROR_SUCCESS)
    {
        hr = HRESULT_FROM_WIN32(error);
        goto done;
    }
    RegCloseKey(pending);
    pending = NULL;
    error = RegRenameKey(repository, pending_name, full_name);
    hr = error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);

done:
    if (pending) RegCloseKey(pending);
    if (FAILED(hr) && pending_name[0]) RegDeleteKeyW(repository, pending_name);
    RegCloseKey(repository);
    return hr;
}

HRESULT package_store_get_path(PCWSTR full_name, WCHAR **root_path)
{
    HKEY key = NULL;
    DWORD type, size;
    WCHAR *path;
    HRESULT hr;
    LONG error;

    if (!root_path) return E_POINTER;
    *root_path = NULL;
    if (FAILED(hr = open_package_key(full_name, KEY_QUERY_VALUE, &key))) return hr;
    error = RegQueryValueExW(key, L"PackageRootFolder", NULL, &type, NULL, &size);
    if (error != ERROR_SUCCESS || type != REG_SZ || !size || size % sizeof(WCHAR))
    {
        hr = HRESULT_FROM_WIN32(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        goto done;
    }
    path = HeapAlloc(GetProcessHeap(), 0, size);
    if (!path)
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    error = RegQueryValueExW(key, L"PackageRootFolder", NULL, &type, (BYTE *)path, &size);
    if (error != ERROR_SUCCESS || type != REG_SZ || !size || size % sizeof(WCHAR) ||
        path[size / sizeof(WCHAR) - 1] != UNICODE_NULL)
    {
        HeapFree(GetProcessHeap(), 0, path);
        hr = HRESULT_FROM_WIN32(error != ERROR_SUCCESS ? error : ERROR_INVALID_DATA);
        goto done;
    }
    *root_path = path;
    hr = S_OK;

done:
    RegCloseKey(key);
    return hr;
}

HRESULT package_store_unregister(PCWSTR full_name, PCWSTR expected_path)
{
    WCHAR *registered_path = NULL;
    HKEY repository = NULL;
    HRESULT hr;
    LONG error;

    if (FAILED(hr = validate_full_name(full_name))) return hr;
    if (FAILED(hr = package_store_get_path(full_name, &registered_path))) return hr;
    if (expected_path && CompareStringOrdinal(registered_path, -1, expected_path, -1, TRUE) != CSTR_EQUAL)
    {
        HeapFree(GetProcessHeap(), 0, registered_path);
        return HRESULT_FROM_WIN32(ERROR_RETRY);
    }
    HeapFree(GetProcessHeap(), 0, registered_path);
    error = RegOpenKeyExW(HKEY_CURRENT_USER, package_repository_key, 0, KEY_WRITE, &repository);
    if (error != ERROR_SUCCESS) return HRESULT_FROM_WIN32(error);
    error = RegDeleteKeyW(repository, full_name);
    RegCloseKey(repository);
    return error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);
}
