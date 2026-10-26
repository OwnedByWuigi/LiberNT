/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Package deployment runtime activation
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <initguid.h>
#include "private.h"

struct activation_factory
{
    IActivationFactory IActivationFactory_iface;
    LONG ref;
};

static inline struct activation_factory *impl_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct activation_factory, IActivationFactory_iface);
}

static HRESULT WINAPI factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    if (!out)
        return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) && !IsEqualGUID(iid, &IID_IInspectable) &&
        !IsEqualGUID(iid, &IID_IAgileObject) && !IsEqualGUID(iid, &IID_IActivationFactory))
        return E_NOINTERFACE;
    *out = iface;
    IActivationFactory_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI factory_AddRef(IActivationFactory *iface)
{
    return InterlockedIncrement(&impl_from_IActivationFactory(iface)->ref);
}

static ULONG WINAPI factory_Release(IActivationFactory *iface)
{
    return InterlockedDecrement(&impl_from_IActivationFactory(iface)->ref);
}

HRESULT get_iids(REFIID iid, ULONG *count, IID **iids)
{
    if (!count || !iids)
        return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids))))
        return E_OUTOFMEMORY;
    **iids = *iid;
    *count = 1;
    return S_OK;
}

static HRESULT WINAPI factory_GetIids(IActivationFactory *iface, ULONG *count, IID **iids)
{
    return get_iids(&IID_IActivationFactory, count, iids);
}

static HRESULT WINAPI factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *class_name)
{
    return WindowsCreateString(RuntimeClass_Windows_Management_Deployment_PackageManager,
                               ARRAYSIZE(RuntimeClass_Windows_Management_Deployment_PackageManager) - 1,
                               class_name);
}

HRESULT trust_level(TrustLevel *level)
{
    if (!level)
        return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *level)
{
    return trust_level(level);
}

static HRESULT WINAPI factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    return package_manager_create(instance);
}

static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    factory_GetIids,
    factory_GetRuntimeClassName,
    factory_GetTrustLevel,
    factory_ActivateInstance,
};

static struct activation_factory package_manager_factory =
{
    {&factory_vtbl},
    1,
};

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **out)
{
    if (out)
        *out = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllGetActivationFactory(HSTRING classid, IActivationFactory **factory)
{
    const WCHAR *name;

    if (!factory)
        return E_POINTER;
    *factory = NULL;
    name = WindowsGetStringRawBuffer(classid, NULL);
    if (!name || wcscmp(name, RuntimeClass_Windows_Management_Deployment_PackageManager))
        return CLASS_E_CLASSNOTAVAILABLE;
    *factory = &package_manager_factory.IActivationFactory_iface;
    IActivationFactory_AddRef(*factory);
    return S_OK;
}
