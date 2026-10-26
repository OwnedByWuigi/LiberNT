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
#include <wchar.h>

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#define WIDL_using_Windows_ApplicationModel
#define WIDL_using_Windows_Management_Deployment
#include <windows.foundation.h>
#include <windows.applicationmodel.h>
#include <windows.management.deployment.h>

#include <wine/test.h>

static void test_package_manager(void)
{
    const WCHAR *class_name = RuntimeClass_Windows_Management_Deployment_PackageManager;
    IPackageManager2 *manager2;
    IPackageManager *manager;
    IActivationFactory *factory;
    IInspectable *instance = NULL;
    HSTRING class_string = NULL, runtime_class = NULL;
    IID *iids = NULL;
    ULONG iid_count = 0, i;
    TrustLevel trust_level;
    BOOL found_manager = FALSE, found_manager2 = FALSE;
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
    hr = IActivationFactory_ActivateInstance(factory, &instance);
    ok(hr == S_OK, "ActivateInstance returned %#lx\n", hr);
    IActivationFactory_Release(factory);
    WindowsDeleteString(class_string);
    if (FAILED(hr)) return;

    hr = IInspectable_QueryInterface(instance, &IID_IPackageManager, (void **)&manager);
    ok(hr == S_OK, "QueryInterface(IPackageManager) returned %#lx\n", hr);
    if (SUCCEEDED(hr)) IPackageManager_Release(manager);

    hr = IInspectable_QueryInterface(instance, &IID_IPackageManager2, (void **)&manager2);
    ok(hr == S_OK, "QueryInterface(IPackageManager2) returned %#lx\n", hr);
    if (SUCCEEDED(hr)) IPackageManager2_Release(manager2);

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
    }
    CoTaskMemFree(iids);

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
