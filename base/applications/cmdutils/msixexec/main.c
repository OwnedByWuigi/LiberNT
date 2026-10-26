/*
 * PROJECT:     LiberNT MSIX installer
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Install an AppX or MSIX package through Windows Runtime deployment
 * COPYRIGHT:   Copyright 2026 wuggy <ownedbywuigi@gmail.com>
 */

#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <roapi.h>
#include <shlwapi.h>

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#define WIDL_using_Windows_ApplicationModel
#define WIDL_using_Windows_ApplicationModel_Core
#define WIDL_using_Windows_Management_Deployment
#define WIDL_using_Windows_Storage
#include <windows.foundation.h>
#include <windows.applicationmodel.h>
#include <windows.management.deployment.h>

#include <stdio.h>
#include <wchar.h>

static void print_usage(void)
{
    fwprintf(stderr, L"Usage: msixexec <package.appx|package.msix|package.appxbundle|package.msixbundle>\n");
}

static HRESULT create_package_uri(const WCHAR *path, IUriRuntimeClass **uri)
{
    IUriRuntimeClassFactory *uri_factory = NULL;
    IActivationFactory *activation = NULL;
    WCHAR full_path[32768], url[32768];
    DWORD full_path_length;
    DWORD url_length = ARRAYSIZE(url);
    HSTRING class_name = NULL, url_string = NULL;
    HRESULT hr;

    full_path_length = GetFullPathNameW(path, ARRAYSIZE(full_path), full_path, NULL);
    if (!full_path_length)
        return HRESULT_FROM_WIN32(GetLastError());
    if (full_path_length >= ARRAYSIZE(full_path))
        return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    if (FAILED(hr = UrlCreateFromPathW(full_path, url, &url_length, 0))) return hr;
    if (FAILED(hr = WindowsCreateString(RuntimeClass_Windows_Foundation_Uri,
                                        wcslen(RuntimeClass_Windows_Foundation_Uri), &class_name)))
        goto done;
    if (FAILED(hr = RoGetActivationFactory(class_name, &IID_IActivationFactory, (void **)&activation)))
        goto done;
    if (FAILED(hr = IActivationFactory_QueryInterface(activation, &IID_IUriRuntimeClassFactory,
                                                       (void **)&uri_factory)))
        goto done;
    if (FAILED(hr = WindowsCreateString(url, wcslen(url), &url_string)))
        goto done;
    hr = IUriRuntimeClassFactory_CreateUri(uri_factory, url_string, uri);

done:
    if (url_string) WindowsDeleteString(url_string);
    if (uri_factory) IUriRuntimeClassFactory_Release(uri_factory);
    if (activation) IActivationFactory_Release(activation);
    if (class_name) WindowsDeleteString(class_name);
    return hr;
}

static HRESULT install_package(const WCHAR *path)
{
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *operation = NULL;
    IDeploymentResult *result = NULL;
    IUriRuntimeClass *uri = NULL;
    IInspectable *instance = NULL;
    IPackageManager *manager = NULL;
    AsyncStatus status;
    HRESULT hr, deployment_hr;
    HSTRING class_name = NULL, error_text = NULL;

    if (FAILED(hr = WindowsCreateString(RuntimeClass_Windows_Management_Deployment_PackageManager,
                                        wcslen(RuntimeClass_Windows_Management_Deployment_PackageManager),
                                        &class_name)))
        goto done;
    if (FAILED(hr = RoActivateInstance(class_name, &instance)))
        goto done;
    if (FAILED(hr = IInspectable_QueryInterface(instance, &IID_IPackageManager, (void **)&manager)))
        goto done;
    if (FAILED(hr = create_package_uri(path, &uri)))
        goto done;
    if (FAILED(hr = IPackageManager_AddPackageAsync(manager, uri, NULL, DeploymentOptions_None, &operation)))
        goto done;

    IUriRuntimeClass_Release(uri);
    uri = NULL;
    IPackageManager_Release(manager);
    manager = NULL;
    IInspectable_Release(instance);
    instance = NULL;
    WindowsDeleteString(class_name);
    class_name = NULL;

    for (;;)
    {
        IAsyncInfo *async_info = NULL;
        hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_QueryInterface(
                 operation, &IID_IAsyncInfo, (void **)&async_info);
        if (FAILED(hr)) goto done;
        hr = IAsyncInfo_get_Status(async_info, &status);
        IAsyncInfo_Release(async_info);
        if (FAILED(hr)) goto done;
        if (status != Started) break;
        Sleep(100);
    }

    if (status == Error)
    {
        IAsyncInfo *async_info = NULL;
        if (SUCCEEDED(IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_QueryInterface(
                          operation, &IID_IAsyncInfo, (void **)&async_info)))
        {
            HRESULT async_error;
            hr = IAsyncInfo_get_ErrorCode(async_info, &async_error);
            IAsyncInfo_Release(async_info);
            if (SUCCEEDED(hr)) hr = async_error;
        }
        else
            hr = E_FAIL;
        goto done;
    }
    if (status == Canceled)
    {
        hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        goto done;
    }

    hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_GetResults(operation, &result);
    if (FAILED(hr)) goto done;
    hr = IDeploymentResult_get_ExtendedErrorCode(result, &deployment_hr);
    if (SUCCEEDED(hr)) hr = deployment_hr;
    if (FAILED(hr) && SUCCEEDED(IDeploymentResult_get_ErrorText(result, &error_text)) && error_text)
        fwprintf(stderr, L"%ls\n", WindowsGetStringRawBuffer(error_text, NULL));

done:
    if (error_text) WindowsDeleteString(error_text);
    if (result) IDeploymentResult_Release(result);
    if (operation) IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(operation);
    if (uri) IUriRuntimeClass_Release(uri);
    if (manager) IPackageManager_Release(manager);
    if (instance) IInspectable_Release(instance);
    if (class_name) WindowsDeleteString(class_name);
    return hr;
}

int wmain(int argc, WCHAR **argv)
{
    HRESULT hr;

    if (argc != 2 || !argv[1][0])
    {
        print_usage();
        return ERROR_INVALID_PARAMETER;
    }

    hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr))
    {
        fwprintf(stderr, L"msixexec: Windows Runtime initialization failed (0x%08lx).\n", hr);
        return 1;
    }

    hr = install_package(argv[1]);
    if (FAILED(hr))
        fwprintf(stderr, L"msixexec: package installation failed (0x%08lx).\n", hr);
    else
        wprintf(L"Package installed successfully.\n");

    RoUninitialize();
    return FAILED(hr) ? 1 : 0;
}
