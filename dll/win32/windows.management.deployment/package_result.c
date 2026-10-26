/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Deployment result runtime object
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <initguid.h>
#include "package_result.h"

struct deployment_result
{
    IDeploymentResult IDeploymentResult_iface;
    LONG ref;
    HSTRING error_text;
    HRESULT extended_error;
    GUID activity_id;
};

static inline struct deployment_result *impl_from_IDeploymentResult(IDeploymentResult *iface)
{
    return CONTAINING_RECORD(iface, struct deployment_result, IDeploymentResult_iface);
}

static HRESULT WINAPI result_QueryInterface(IDeploymentResult *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IDeploymentResult))
        *out = iface;
    else
        return E_NOINTERFACE;
    IDeploymentResult_AddRef((IDeploymentResult *)*out);
    return S_OK;
}

static ULONG WINAPI result_AddRef(IDeploymentResult *iface)
{
    return InterlockedIncrement(&impl_from_IDeploymentResult(iface)->ref);
}

static ULONG WINAPI result_Release(IDeploymentResult *iface)
{
    struct deployment_result *impl = impl_from_IDeploymentResult(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        WindowsDeleteString(impl->error_text);
        HeapFree(GetProcessHeap(), 0, impl);
    }
    return ref;
}

static HRESULT WINAPI result_GetIids(IDeploymentResult *iface, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(sizeof(**iids)))) return E_OUTOFMEMORY;
    (*iids)[0] = IID_IDeploymentResult;
    *count = 1;
    return S_OK;
}

static HRESULT WINAPI result_GetRuntimeClassName(IDeploymentResult *iface, HSTRING *class_name)
{
    if (!class_name) return E_POINTER;
    return WindowsCreateString(RuntimeClass_Windows_Management_Deployment_DeploymentResult,
                               ARRAYSIZE(RuntimeClass_Windows_Management_Deployment_DeploymentResult) - 1,
                               class_name);
}

static HRESULT WINAPI result_GetTrustLevel(IDeploymentResult *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI result_get_ErrorText(IDeploymentResult *iface, HSTRING *value)
{
    if (!value) return E_POINTER;
    return WindowsDuplicateString(impl_from_IDeploymentResult(iface)->error_text, value);
}

static HRESULT WINAPI result_get_ActivityId(IDeploymentResult *iface, GUID *value)
{
    if (!value) return E_POINTER;
    *value = impl_from_IDeploymentResult(iface)->activity_id;
    return S_OK;
}

static HRESULT WINAPI result_get_ExtendedErrorCode(IDeploymentResult *iface, HRESULT *value)
{
    if (!value) return E_POINTER;
    *value = impl_from_IDeploymentResult(iface)->extended_error;
    return S_OK;
}

static const IDeploymentResultVtbl result_vtbl =
{
    result_QueryInterface,
    result_AddRef,
    result_Release,
    result_GetIids,
    result_GetRuntimeClassName,
    result_GetTrustLevel,
    result_get_ErrorText,
    result_get_ActivityId,
    result_get_ExtendedErrorCode,
};

HRESULT deployment_result_create(PCWSTR error_text, HRESULT extended_error, REFGUID activity_id,
                                 IDeploymentResult **result)
{
    struct deployment_result *impl;
    HRESULT hr;

    if (!result || !activity_id) return E_POINTER;
    *result = NULL;
    if (!(impl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->IDeploymentResult_iface.lpVtbl = &result_vtbl;
    impl->ref = 1;
    impl->extended_error = extended_error;
    impl->activity_id = *activity_id;
    hr = WindowsCreateString(error_text ? error_text : L"", error_text ? wcslen(error_text) : 0,
                             &impl->error_text);
    if (FAILED(hr))
    {
        HeapFree(GetProcessHeap(), 0, impl);
        return hr;
    }
    *result = &impl->IDeploymentResult_iface;
    return S_OK;
}
