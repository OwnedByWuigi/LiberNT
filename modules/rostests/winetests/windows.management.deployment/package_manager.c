/*
 * PROJECT:     LiberNT API tests
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Test PackageManager WinRT activation and inspectable contract
 * COPYRIGHT:   Copyright 2026 Ahmed ARIF <arif.ing@outlook.com>
 */

#define COBJMACROS
#include <initguid.h>
#include <windef.h>
#include <winbase.h>
#include <winstring.h>
#include <roapi.h>
#include <shlwapi.h>
#include <wchar.h>

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#define WIDL_using_Windows_ApplicationModel
#define WIDL_using_Windows_Management_Deployment
#include <windows.foundation.h>
#include <windows.applicationmodel.h>
#include <windows.management.deployment.h>

#include <wine/test.h>

static void check_iids_queryable(IUnknown *object, const IID *iids, ULONG iid_count)
{
    IUnknown *interface;
    ULONG i;
    HRESULT hr;

    for (i = 0; i < iid_count; i++)
    {
        interface = NULL;
        hr = IUnknown_QueryInterface(object, &iids[i], (void **)&interface);
        ok(hr == S_OK, "QueryInterface for GetIids entry %lu returned %#lx\n", i, hr);
        ok(interface != NULL, "QueryInterface for GetIids entry %lu returned NULL\n", i);
        if (interface) IUnknown_Release(interface);
    }
}

static void test_add_package_async(IPackageManager *manager)
{
    WCHAR temp_path[MAX_PATH], path[MAX_PATH], uri_text[MAX_PATH * 3];
    HSTRING class_name = NULL, uri_string = NULL;
    IUriRuntimeClassFactory *factory = NULL;
    IUriRuntimeClass *uri = NULL;
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *operation = NULL;
    IDeploymentResult *result = NULL;
    IAsyncInfo *info = NULL;
    IID *iids = NULL;
    static const BYTE empty_archive[] =
    {
        0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    HANDLE file;
    ULONG iid_count, i;
    BOOL found_operation, found_info, cancellation_finished = FALSE;
    UINT32 id;
    AsyncStatus status = Started;
    HRESULT extended_error, operation_error = E_UNEXPECTED, hr;
    DWORD length, temp_path_length;
    UINT retries;

    temp_path_length = GetTempPathW(ARRAYSIZE(temp_path), temp_path);
    if (!temp_path_length || temp_path_length >= ARRAYSIZE(temp_path))
    {
        ok(FALSE, "GetTempPathW failed with %lu\n", GetLastError());
        return;
    }
    if (!GetTempFileNameW(temp_path, L"uwp", 0, path))
    {
        ok(FALSE, "GetTempFileNameW failed with %lu\n", GetLastError());
        return;
    }
    DeleteFileW(path);
    if (!PathRenameExtensionW(path, L".msix"))
    {
        ok(FALSE, "PathRenameExtensionW failed\n");
        return;
    }
    length = ARRAYSIZE(uri_text);
    hr = UrlCreateFromPathW(path, uri_text, &length, 0);
    ok(hr == S_OK, "UrlCreateFromPathW returned %#lx\n", hr);
    if (FAILED(hr)) return;

    hr = WindowsCreateString(L"Windows.Foundation.Uri", ARRAYSIZE(L"Windows.Foundation.Uri") - 1,
                             &class_name);
    ok(hr == S_OK, "WindowsCreateString returned %#lx\n", hr);
    if (FAILED(hr)) return;
    hr = RoGetActivationFactory(class_name, &IID_IUriRuntimeClassFactory, (void **)&factory);
    WindowsDeleteString(class_name);
    ok(hr == S_OK, "RoGetActivationFactory(Uri) returned %#lx\n", hr);
    if (FAILED(hr)) return;

    hr = WindowsCreateString(uri_text, wcslen(uri_text), &uri_string);
    ok(hr == S_OK, "WindowsCreateString returned %#lx\n", hr);
    if (SUCCEEDED(hr)) hr = IUriRuntimeClassFactory_CreateUri(factory, uri_string, &uri);
    if (uri_string) WindowsDeleteString(uri_string);
    IUriRuntimeClassFactory_Release(factory);
    ok(hr == S_OK, "CreateUri returned %#lx\n", hr);
    if (FAILED(hr)) return;

    hr = IPackageManager_AddPackageAsync(manager, uri, NULL, DeploymentOptions_None, &operation);
    ok(hr == S_OK, "AddPackageAsync returned %#lx\n", hr);
    ok(operation != NULL, "AddPackageAsync returned a NULL operation\n");
    if (FAILED(hr) || !operation)
    {
        if (operation) IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(operation);
        IUriRuntimeClass_Release(uri);
        return;
    }

    hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_GetIids(
            operation, &iid_count, &iids);
    ok(hr == S_OK, "operation GetIids returned %#lx\n", hr);
    found_operation = found_info = FALSE;
    if (SUCCEEDED(hr))
    {
        for (i = 0; i < iid_count; i++)
        {
            if (IsEqualGUID(&iids[i], &IID_IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress))
                found_operation = TRUE;
            if (IsEqualGUID(&iids[i], &IID_IAsyncInfo)) found_info = TRUE;
        }
        ok(found_operation, "operation GetIids omitted its typed interface\n");
        ok(found_info, "operation GetIids omitted IAsyncInfo\n");
        check_iids_queryable((IUnknown *)operation, iids, iid_count);
    }
    CoTaskMemFree(iids);

    hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_QueryInterface(
            operation, &IID_IAsyncInfo, (void **)&info);
    ok(hr == S_OK, "QueryInterface(IAsyncInfo) returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        hr = IAsyncInfo_get_Id(info, &id);
        ok(hr == S_OK, "IAsyncInfo::get_Id returned %#lx\n", hr);
        hr = IAsyncInfo_get_ErrorCode(info, &operation_error);
        ok(hr == S_OK, "IAsyncInfo::get_ErrorCode returned %#lx\n", hr);
        hr = IAsyncInfo_get_Status(info, &status);
        ok(hr == S_OK, "IAsyncInfo::get_Status returned %#lx\n", hr);
        for (retries = 0; SUCCEEDED(hr) && status == Started && retries < 1000; retries++)
        {
            Sleep(10);
            hr = IAsyncInfo_get_Status(info, &status);
        }
        ok(hr == S_OK, "IAsyncInfo::get_Status returned %#lx\n", hr);
        ok(status == Completed, "deployment ended with status %u\n", status);
        if (status == Completed)
            ok(operation_error == S_OK, "operation error code is %#lx\n", operation_error);
        if (status == Completed)
        {
            hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_GetResults(
                    operation, &result);
            ok(hr == S_OK, "GetResults returned %#lx\n", hr);
            ok(result != NULL, "GetResults returned a NULL result\n");
            if (SUCCEEDED(hr) && result)
            {
                hr = IDeploymentResult_get_ExtendedErrorCode(result, &extended_error);
                ok(hr == S_OK, "get_ExtendedErrorCode returned %#lx\n", hr);
                if (SUCCEEDED(hr)) ok(FAILED(extended_error), "expected a deployment error, got %#lx\n", extended_error);
                IDeploymentResult_Release(result);
                hr = IAsyncInfo_Close(info);
                ok(hr == S_OK, "IAsyncInfo::Close returned %#lx\n", hr);
                hr = IAsyncInfo_get_Status(info, &status);
                ok(hr == E_ILLEGAL_METHOD_CALL, "get_Status after Close returned %#lx\n", hr);
            }
        }
        IAsyncInfo_Release(info);
    }
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(operation);

    operation = NULL;
    info = NULL;
    hr = IPackageManager_AddPackageAsync(manager, uri, NULL, DeploymentOptions_None, &operation);
    ok(hr == S_OK, "AddPackageAsync for cancellation returned %#lx\n", hr);
    ok(operation != NULL, "AddPackageAsync for cancellation returned a NULL operation\n");
    if (SUCCEEDED(hr) && operation)
    {
        hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_QueryInterface(
                operation, &IID_IAsyncInfo, (void **)&info);
        ok(hr == S_OK, "QueryInterface(IAsyncInfo) returned %#lx\n", hr);
        if (SUCCEEDED(hr))
        {
            hr = IAsyncInfo_Cancel(info);
            ok(hr == S_OK, "IAsyncInfo::Cancel returned %#lx\n", hr);
            status = Started;
            for (retries = 0; SUCCEEDED(hr) && status == Started && retries < 1000; retries++)
            {
                Sleep(10);
                hr = IAsyncInfo_get_Status(info, &status);
            }
            ok(hr == S_OK, "IAsyncInfo::get_Status returned %#lx\n", hr);
            ok(status == Canceled || status == Completed,
               "canceled deployment ended with status %u\n", status);
            cancellation_finished = SUCCEEDED(hr) && status != Started;
            IAsyncInfo_Release(info);
        }
        IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(operation);
    }
    else if (operation)
        IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(operation);

    if (cancellation_finished)
    {
        file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        ok(file != INVALID_HANDLE_VALUE, "CreateFileW for empty MSIX returned %lu\n", GetLastError());
        if (file != INVALID_HANDLE_VALUE)
        {
            DWORD written = 0;

            ok(WriteFile(file, empty_archive, sizeof(empty_archive), &written, NULL),
               "WriteFile for empty MSIX returned %lu\n", GetLastError());
            ok(written == sizeof(empty_archive), "empty archive write was short: %lu bytes\n", written);
            CloseHandle(file);

            operation = NULL;
            info = NULL;
            result = NULL;
            hr = IPackageManager_AddPackageAsync(manager, uri, NULL, DeploymentOptions_None, &operation);
            ok(hr == S_OK, "AddPackageAsync for empty MSIX returned %#lx\n", hr);
            if (SUCCEEDED(hr) && operation)
            {
                hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_QueryInterface(
                        operation, &IID_IAsyncInfo, (void **)&info);
                ok(hr == S_OK, "QueryInterface(IAsyncInfo) for empty MSIX returned %#lx\n", hr);
                if (SUCCEEDED(hr))
                {
                    status = Started;
                    for (retries = 0; SUCCEEDED(hr) && status == Started && retries < 1000; retries++)
                    {
                        Sleep(10);
                        hr = IAsyncInfo_get_Status(info, &status);
                    }
                    ok(hr == S_OK, "IAsyncInfo::get_Status for empty MSIX returned %#lx\n", hr);
                    ok(status == Completed, "empty MSIX deployment ended with status %u\n", status);
                    if (status == Completed)
                    {
                        hr = IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_GetResults(
                                operation, &result);
                        ok(hr == S_OK, "GetResults for empty MSIX returned %#lx\n", hr);
                        if (SUCCEEDED(hr) && result)
                        {
                            hr = IDeploymentResult_get_ExtendedErrorCode(result, &extended_error);
                            ok(hr == S_OK, "get_ExtendedErrorCode for empty MSIX returned %#lx\n", hr);
                            if (SUCCEEDED(hr))
                                ok(FAILED(extended_error), "empty MSIX deployment succeeded\n");
                            IDeploymentResult_Release(result);
                        }
                    }
                    IAsyncInfo_Release(info);
                }
                IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(operation);
            }
            else if (operation)
                IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(operation);
        }
    }
    DeleteFileW(path);
    IUriRuntimeClass_Release(uri);
}

static void test_package_manager(void)
{
    const WCHAR *class_name = RuntimeClass_Windows_Management_Deployment_PackageManager;
    IPackageManager2 *manager2;
    IPackageManager *manager;
    IActivationFactory *factory;
    IInspectable *instance = NULL;
    HSTRING class_string = NULL, runtime_class = NULL;
    IID *iids = NULL;
    void *unknown = (void *)0xdeadbeef;
    IUriRuntimeClassFactory *uri_factory;
    IUriRuntimeClass *uri;
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *operation;
    static const DeploymentOptions invalid_options[] =
    {
        DeploymentOptions_DevelopmentMode,
        DeploymentOptions_InstallAllResources,
        DeploymentOptions_ForceTargetApplicationShutdown,
        DeploymentOptions_RequiredContentGroupOnly,
        DeploymentOptions_ForceUpdateFromAnyVersion,
        DeploymentOptions_RetainFilesOnFailure,
        DeploymentOptions_StageInPlace,
    };
    unsigned int option_index;
    ULONG iid_count = 0, i;
    TrustLevel trust_level;
    BOOL found_factory = FALSE, found_manager = FALSE, found_manager2 = FALSE;
    HRESULT hr;

    hr = WindowsCreateString(class_name, wcslen(class_name), &class_string);
    ok(hr == S_OK, "WindowsCreateString returned %#lx\n", hr);
    if (FAILED(hr)) return;

    hr = RoGetActivationFactory(class_string, &IID_IActivationFactory, (void **)&factory);
    ok(hr == S_OK, "RoGetActivationFactory returned %#lx\n", hr);
    if (FAILED(hr))
    {
        WindowsDeleteString(class_string);
        return;
    }

    hr = IActivationFactory_QueryInterface(factory, &IID_IActivationFactory, (void **)&unknown);
    ok(hr == S_OK, "Factory QueryInterface(IActivationFactory) returned %#lx\n", hr);
    if (SUCCEEDED(hr)) IActivationFactory_Release((IActivationFactory *)unknown);

    hr = IActivationFactory_GetRuntimeClassName(factory, &runtime_class);
    ok(hr == S_OK, "Factory GetRuntimeClassName returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ok(!wcscmp(WindowsGetStringRawBuffer(runtime_class, NULL), class_name),
           "factory runtime class name did not match\n");
        WindowsDeleteString(runtime_class);
        runtime_class = NULL;
    }

    hr = IActivationFactory_GetTrustLevel(factory, &trust_level);
    ok(hr == S_OK, "Factory GetTrustLevel returned %#lx\n", hr);
    if (SUCCEEDED(hr)) ok(trust_level == BaseTrust, "factory got trust level %u\n", trust_level);

    hr = IActivationFactory_GetIids(factory, &iid_count, &iids);
    ok(hr == S_OK, "Factory GetIids returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        for (i = 0; i < iid_count; i++)
            if (IsEqualGUID(&iids[i], &IID_IActivationFactory)) found_factory = TRUE;
        ok(found_factory, "Factory GetIids omitted IActivationFactory\n");
        check_iids_queryable((IUnknown *)factory, iids, iid_count);
    }
    CoTaskMemFree(iids);
    iids = NULL;
    iid_count = 0;

    hr = IActivationFactory_GetIids(factory, NULL, &iids);
    ok(hr == E_POINTER, "Factory GetIids with NULL count returned %#lx\n", hr);
    hr = IActivationFactory_GetIids(factory, &iid_count, NULL);
    ok(hr == E_POINTER, "Factory GetIids with NULL array returned %#lx\n", hr);
    hr = IActivationFactory_GetRuntimeClassName(factory, NULL);
    ok(hr == E_POINTER, "Factory GetRuntimeClassName with NULL output returned %#lx\n", hr);
    hr = IActivationFactory_GetTrustLevel(factory, NULL);
    ok(hr == E_POINTER, "Factory GetTrustLevel with NULL output returned %#lx\n", hr);

    hr = IActivationFactory_ActivateInstance(factory, &instance);
    ok(hr == S_OK, "ActivateInstance returned %#lx\n", hr);
    IActivationFactory_Release(factory);
    WindowsDeleteString(class_string);
    if (FAILED(hr)) return;

    hr = IInspectable_QueryInterface(instance, &IID_IPackageManager, (void **)&manager);
    ok(hr == S_OK, "QueryInterface(IPackageManager) returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        HSTRING uri_text = NULL;

        hr = WindowsCreateString(L"file:///unused.msix", ARRAYSIZE(L"file:///unused.msix") - 1, &uri_text);
        ok(hr == S_OK, "WindowsCreateString returned %#lx\n", hr);
        if (SUCCEEDED(hr))
        {
            hr = WindowsCreateString(L"Windows.Foundation.Uri", ARRAYSIZE(L"Windows.Foundation.Uri") - 1,
                                     &class_string);
            ok(hr == S_OK, "WindowsCreateString returned %#lx\n", hr);
            if (SUCCEEDED(hr))
            {
                hr = RoGetActivationFactory(class_string, &IID_IUriRuntimeClassFactory, (void **)&uri_factory);
                WindowsDeleteString(class_string);
                class_string = NULL;
                ok(hr == S_OK, "RoGetActivationFactory(Uri) returned %#lx\n", hr);
                if (SUCCEEDED(hr))
                {
                    hr = IUriRuntimeClassFactory_CreateUri(uri_factory, uri_text, &uri);
                    ok(hr == S_OK, "CreateUri returned %#lx\n", hr);
                    if (SUCCEEDED(hr))
                    {
                        for (option_index = 0; option_index < ARRAYSIZE(invalid_options); option_index++)
                        {
                            operation = (void *)0xdeadbeef;
                            hr = IPackageManager_AddPackageAsync(manager, uri, NULL,
                                    invalid_options[option_index], &operation);
                            ok(hr == E_INVALIDARG, "AddPackageAsync with options %#x returned %#lx\n",
                               invalid_options[option_index], hr);
                            ok(!operation, "AddPackageAsync with options %#x returned operation %p\n",
                               invalid_options[option_index], operation);
                        }
                        IUriRuntimeClass_Release(uri);
                    }
                    IUriRuntimeClassFactory_Release(uri_factory);
                }
            }
            WindowsDeleteString(uri_text);
        }
        test_add_package_async(manager);
        IPackageManager_Release(manager);
    }

    hr = IInspectable_QueryInterface(instance, &IID_IPackageManager2, (void **)&manager2);
    ok(hr == S_OK, "QueryInterface(IPackageManager2) returned %#lx\n", hr);
    if (SUCCEEDED(hr)) IPackageManager2_Release(manager2);

    hr = IInspectable_QueryInterface(instance, &IID_IUnknown, &unknown);
    ok(hr == S_OK, "QueryInterface(IUnknown) returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        void *manager_unknown = NULL;

        hr = IInspectable_QueryInterface(instance, &IID_IUnknown, &manager_unknown);
        ok(hr == S_OK, "QueryInterface(IUnknown) returned %#lx\n", hr);
        if (SUCCEEDED(hr))
        {
            ok(unknown == manager_unknown, "IUnknown identity changed across interfaces\n");
            IUnknown_Release((IUnknown *)manager_unknown);
        }
        IUnknown_Release((IUnknown *)unknown);
    }

    unknown = (void *)0xdeadbeef;
    hr = IInspectable_QueryInterface(instance, &IID_IUriRuntimeClass, &unknown);
    ok(hr == E_NOINTERFACE, "QueryInterface(unrelated interface) returned %#lx\n", hr);
    ok(!unknown, "QueryInterface(unrelated interface) returned %p\n", unknown);

    hr = IInspectable_GetRuntimeClassName(instance, &runtime_class);
    ok(hr == S_OK, "GetRuntimeClassName returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        ok(!wcscmp(WindowsGetStringRawBuffer(runtime_class, NULL), class_name),
           "runtime class name did not match\n");
        WindowsDeleteString(runtime_class);
    }

    hr = IInspectable_GetTrustLevel(instance, &trust_level);
    ok(hr == S_OK, "GetTrustLevel returned %#lx\n", hr);
    if (SUCCEEDED(hr)) ok(trust_level == BaseTrust, "got trust level %u\n", trust_level);

    hr = IInspectable_GetIids(instance, &iid_count, &iids);
    ok(hr == S_OK, "GetIids returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        for (i = 0; i < iid_count; i++)
        {
            if (IsEqualGUID(&iids[i], &IID_IPackageManager)) found_manager = TRUE;
            if (IsEqualGUID(&iids[i], &IID_IPackageManager2)) found_manager2 = TRUE;
        }
        ok(found_manager, "GetIids omitted IPackageManager\n");
        ok(found_manager2, "GetIids omitted IPackageManager2\n");
        check_iids_queryable((IUnknown *)instance, iids, iid_count);
    }
    CoTaskMemFree(iids);

    hr = IInspectable_GetIids(instance, NULL, &iids);
    ok(hr == E_POINTER, "GetIids with NULL count returned %#lx\n", hr);
    hr = IInspectable_GetIids(instance, &iid_count, NULL);
    ok(hr == E_POINTER, "GetIids with NULL array returned %#lx\n", hr);

    hr = IInspectable_GetRuntimeClassName(instance, NULL);
    ok(hr == E_POINTER, "GetRuntimeClassName with NULL output returned %#lx\n", hr);
    hr = IInspectable_GetTrustLevel(instance, NULL);
    ok(hr == E_POINTER, "GetTrustLevel with NULL output returned %#lx\n", hr);

    IInspectable_Release(instance);
}

START_TEST(package_manager)
{
    HRESULT hr = RoInitialize(RO_INIT_MULTITHREADED);

    ok(SUCCEEDED(hr), "RoInitialize returned %#lx\n", hr);
    if (SUCCEEDED(hr))
    {
        test_package_manager();
        RoUninitialize();
    }
}
