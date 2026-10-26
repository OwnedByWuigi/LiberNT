/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     PackageManager runtime class and interface implementation
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <initguid.h>
#include "private.h"

struct package_manager
{
    IPackageManager IPackageManager_iface;
    IPackageManager2 IPackageManager2_iface;
    LONG ref;
};

static inline struct package_manager *impl_from_IPackageManager(IPackageManager *iface)
{
    return CONTAINING_RECORD(iface, struct package_manager, IPackageManager_iface);
}

static inline struct package_manager *impl_from_IPackageManager2(IPackageManager2 *iface)
{
    return CONTAINING_RECORD(iface, struct package_manager, IPackageManager2_iface);
}

static HRESULT WINAPI manager_QueryInterface(IPackageManager *iface, REFIID iid, void **out)
{
    struct package_manager *impl = impl_from_IPackageManager(iface);

    if (!out)
        return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IPackageManager))
        *out = &impl->IPackageManager_iface;
    else if (IsEqualGUID(iid, &IID_IPackageManager2))
        *out = &impl->IPackageManager2_iface;
    else
        return E_NOINTERFACE;
    IUnknown_AddRef((IUnknown *)*out);
    return S_OK;
}

static ULONG WINAPI manager_AddRef(IPackageManager *iface)
{
    return InterlockedIncrement(&impl_from_IPackageManager(iface)->ref);
}

static ULONG WINAPI manager_Release(IPackageManager *iface)
{
    struct package_manager *impl = impl_from_IPackageManager(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
        free(impl);
    return ref;
}

static HRESULT WINAPI manager_GetIids(IPackageManager *iface, ULONG *count, IID **iids)
{
    if (!count || !iids)
        return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(2 * sizeof(**iids))))
        return E_OUTOFMEMORY;
    (*iids)[0] = IID_IPackageManager;
    (*iids)[1] = IID_IPackageManager2;
    *count = 2;
    return S_OK;
}

static HRESULT WINAPI manager_GetRuntimeClassName(IPackageManager *iface, HSTRING *class_name)
{
    return WindowsCreateString(RuntimeClass_Windows_Management_Deployment_PackageManager,
                               ARRAYSIZE(RuntimeClass_Windows_Management_Deployment_PackageManager) - 1,
                               class_name);
}

static HRESULT WINAPI manager_GetTrustLevel(IPackageManager *iface, TrustLevel *level)
{
    return trust_level(level);
}

#define PACKAGE_MANAGER_UNSUPPORTED(name, signature, output) \
    static HRESULT WINAPI name signature { if (!(output)) return E_POINTER; *(output) = NULL; return E_NOTIMPL; }

static HRESULT WINAPI manager_AddPackageAsync(IPackageManager *iface, IUriRuntimeClass *uri,
        IIterable_Uri *dependencies, DeploymentOptions options,
        IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation)
{
    return deployment_operation_add_package(uri, dependencies, options, operation);
}
PACKAGE_MANAGER_UNSUPPORTED(manager_UpdatePackageAsync,
    (IPackageManager *iface, IUriRuntimeClass *uri, IIterable_Uri *dependencies, DeploymentOptions options,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager_RemovePackageAsync,
    (IPackageManager *iface, HSTRING name,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager_StagePackageAsync,
    (IPackageManager *iface, IUriRuntimeClass *uri, IIterable_Uri *dependencies,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager_RegisterPackageAsync,
    (IPackageManager *iface, IUriRuntimeClass *uri, IIterable_Uri *dependencies, DeploymentOptions options,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackages,
    (IPackageManager *iface, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackagesByUserSecurityId,
    (IPackageManager *iface, HSTRING sid, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackagesByNamePublisher,
    (IPackageManager *iface, HSTRING name, HSTRING publisher, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackagesByUserSecurityIdNamePublisher,
    (IPackageManager *iface, HSTRING sid, HSTRING name, HSTRING publisher, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindUsers,
    (IPackageManager *iface, HSTRING name, IIterable_PackageUserInformation **users), users)
static HRESULT WINAPI manager_SetPackageState(IPackageManager *iface, HSTRING name, PackageState state)
{
    return E_NOTIMPL;
}
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackageByPackageFullName,
    (IPackageManager *iface, HSTRING name, IPackage **package), package)
PACKAGE_MANAGER_UNSUPPORTED(manager_CleanupPackageForUserAsync,
    (IPackageManager *iface, HSTRING name, HSTRING sid,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackagesByPackageFamilyName,
    (IPackageManager *iface, HSTRING family_name, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackagesByUserSecurityIdPackageFamilyName,
    (IPackageManager *iface, HSTRING sid, HSTRING family_name, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager_FindPackageByUserSecurityIdPackageFullName,
    (IPackageManager *iface, HSTRING sid, HSTRING name, IPackage **package), package)

static const IPackageManagerVtbl manager_vtbl =
{
    manager_QueryInterface,
    manager_AddRef,
    manager_Release,
    manager_GetIids,
    manager_GetRuntimeClassName,
    manager_GetTrustLevel,
    manager_AddPackageAsync,
    manager_UpdatePackageAsync,
    manager_RemovePackageAsync,
    manager_StagePackageAsync,
    manager_RegisterPackageAsync,
    manager_FindPackages,
    manager_FindPackagesByUserSecurityId,
    manager_FindPackagesByNamePublisher,
    manager_FindPackagesByUserSecurityIdNamePublisher,
    manager_FindUsers,
    manager_SetPackageState,
    manager_FindPackageByPackageFullName,
    manager_CleanupPackageForUserAsync,
    manager_FindPackagesByPackageFamilyName,
    manager_FindPackagesByUserSecurityIdPackageFamilyName,
    manager_FindPackageByUserSecurityIdPackageFullName,
};

static HRESULT WINAPI manager2_QueryInterface(IPackageManager2 *iface, REFIID iid, void **out)
{
    return manager_QueryInterface(&impl_from_IPackageManager2(iface)->IPackageManager_iface, iid, out);
}

static ULONG WINAPI manager2_AddRef(IPackageManager2 *iface)
{
    return manager_AddRef(&impl_from_IPackageManager2(iface)->IPackageManager_iface);
}

static ULONG WINAPI manager2_Release(IPackageManager2 *iface)
{
    return manager_Release(&impl_from_IPackageManager2(iface)->IPackageManager_iface);
}

static HRESULT WINAPI manager2_GetIids(IPackageManager2 *iface, ULONG *count, IID **iids)
{
    return manager_GetIids(&impl_from_IPackageManager2(iface)->IPackageManager_iface, count, iids);
}

static HRESULT WINAPI manager2_GetRuntimeClassName(IPackageManager2 *iface, HSTRING *class_name)
{
    return manager_GetRuntimeClassName(&impl_from_IPackageManager2(iface)->IPackageManager_iface, class_name);
}

static HRESULT WINAPI manager2_GetTrustLevel(IPackageManager2 *iface, TrustLevel *level)
{
    return manager_GetTrustLevel(&impl_from_IPackageManager2(iface)->IPackageManager_iface, level);
}

PACKAGE_MANAGER_UNSUPPORTED(manager2_RemovePackageWithOptionsAsync,
    (IPackageManager2 *iface, HSTRING name, RemovalOptions options,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager2_StagePackageWithOptionsAsync,
    (IPackageManager2 *iface, IUriRuntimeClass *uri, IIterable_Uri *dependencies, DeploymentOptions options,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager2_RegisterPackageByFullNameAsync,
    (IPackageManager2 *iface, HSTRING name, IIterable_HSTRING *dependencies, DeploymentOptions options,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)
PACKAGE_MANAGER_UNSUPPORTED(manager2_FindPackagesWithPackageTypes,
    (IPackageManager2 *iface, PackageTypes types, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager2_FindPackagesByUserSecurityIdWithPackageTypes,
    (IPackageManager2 *iface, HSTRING sid, PackageTypes types, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager2_FindPackagesByNamePublisherWithPackageTypes,
    (IPackageManager2 *iface, HSTRING name, HSTRING publisher, PackageTypes types, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager2_FindPackagesByUserSecurityIdNamePublisherWithPackageTypes,
    (IPackageManager2 *iface, HSTRING sid, HSTRING name, HSTRING publisher, PackageTypes types,
     IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager2_FindPackagesByPackageFamilyNameWithPackageTypes,
    (IPackageManager2 *iface, HSTRING family_name, PackageTypes types, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager2_FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes,
    (IPackageManager2 *iface, HSTRING sid, HSTRING family_name, PackageTypes types, IIterable_Package **packages), packages)
PACKAGE_MANAGER_UNSUPPORTED(manager2_StageUserDataAsync,
    (IPackageManager2 *iface, HSTRING name,
     IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation), operation)

static const IPackageManager2Vtbl manager2_vtbl =
{
    manager2_QueryInterface,
    manager2_AddRef,
    manager2_Release,
    manager2_GetIids,
    manager2_GetRuntimeClassName,
    manager2_GetTrustLevel,
    manager2_RemovePackageWithOptionsAsync,
    manager2_StagePackageWithOptionsAsync,
    manager2_RegisterPackageByFullNameAsync,
    manager2_FindPackagesWithPackageTypes,
    manager2_FindPackagesByUserSecurityIdWithPackageTypes,
    manager2_FindPackagesByNamePublisherWithPackageTypes,
    manager2_FindPackagesByUserSecurityIdNamePublisherWithPackageTypes,
    manager2_FindPackagesByPackageFamilyNameWithPackageTypes,
    manager2_FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes,
    manager2_StageUserDataAsync,
};

HRESULT package_manager_create(IInspectable **instance)
{
    struct package_manager *impl;

    if (!instance)
        return E_POINTER;
    *instance = NULL;
    if (!(impl = calloc(1, sizeof(*impl))))
        return E_OUTOFMEMORY;
    impl->IPackageManager_iface.lpVtbl = &manager_vtbl;
    impl->IPackageManager2_iface.lpVtbl = &manager2_vtbl;
    impl->ref = 1;
    *instance = (IInspectable *)&impl->IPackageManager_iface;
    return S_OK;
}
