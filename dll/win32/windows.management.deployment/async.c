/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Package deployment asynchronous operation
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#include <initguid.h>
#include "package_result.h"
#include "package_transaction.h"

static const GUID null_guid = {0};

struct deployment_operation
{
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress operation_iface;
    IAsyncInfo info_iface;
    LONG ref;
    CRITICAL_SECTION lock;
    AsyncStatus status;
    HRESULT error_code;
    UINT32 id;
    BOOL closed;
    BOOL cancellation_requested;
    BOOL progress_assigned;
    BOOL completed_assigned;
    IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress *progress_handler;
    IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress *completed_handler;
    IDeploymentResult *result;
    IStream *uri_stream;
    IStream *dependencies_stream;
    DeploymentOptions options;
};

static LONG next_operation_id;

static inline struct deployment_operation *impl_from_operation(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface)
{
    return CONTAINING_RECORD(iface, struct deployment_operation, operation_iface);
}

static inline struct deployment_operation *impl_from_info(IAsyncInfo *iface)
{
    return CONTAINING_RECORD(iface, struct deployment_operation, info_iface);
}

static HRESULT WINAPI operation_QueryInterface(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface, REFIID iid, void **out)
{
    struct deployment_operation *impl = impl_from_operation(iface);

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) ||
        IsEqualGUID(iid, &IID_IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress))
        *out = &impl->operation_iface;
    else if (IsEqualGUID(iid, &IID_IAsyncInfo))
        *out = &impl->info_iface;
    else
        return E_NOINTERFACE;
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_AddRef(
        &impl->operation_iface);
    return S_OK;
}

static ULONG WINAPI operation_AddRef(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface)
{
    return InterlockedIncrement(&impl_from_operation(iface)->ref);
}

static ULONG WINAPI operation_Release(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface)
{
    struct deployment_operation *impl = impl_from_operation(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        if (impl->progress_handler)
            IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress_Release(impl->progress_handler);
        if (impl->completed_handler)
            IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_Release(impl->completed_handler);
        if (impl->result) IDeploymentResult_Release(impl->result);
        if (impl->uri_stream) IStream_Release(impl->uri_stream);
        if (impl->dependencies_stream) IStream_Release(impl->dependencies_stream);
        DeleteCriticalSection(&impl->lock);
        HeapFree(GetProcessHeap(), 0, impl);
    }
    return ref;
}

static HRESULT WINAPI operation_GetIids(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface, ULONG *count, IID **iids)
{
    if (!count || !iids) return E_POINTER;
    if (!(*iids = CoTaskMemAlloc(2 * sizeof(**iids)))) return E_OUTOFMEMORY;
    (*iids)[0] = IID_IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress;
    (*iids)[1] = IID_IAsyncInfo;
    *count = 2;
    return S_OK;
}

static HRESULT WINAPI operation_GetRuntimeClassName(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface, HSTRING *name)
{
    static const WCHAR class_name[] =
        L"Windows.Foundation.IAsyncOperationWithProgress`2<DeploymentResult,DeploymentProgress>";

    if (!name) return E_POINTER;
    return WindowsCreateString(class_name, ARRAYSIZE(class_name) - 1, name);
}

static HRESULT WINAPI operation_GetTrustLevel(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface, TrustLevel *level)
{
    if (!level) return E_POINTER;
    *level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI operation_put_Progress(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface,
    IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress *handler)
{
    struct deployment_operation *impl = impl_from_operation(iface);
    HRESULT hr = S_OK;

    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else if (impl->progress_assigned) hr = E_ILLEGAL_DELEGATE_ASSIGNMENT;
    else
    {
        impl->progress_assigned = TRUE;
        if (handler)
        {
            IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress_AddRef(handler);
            impl->progress_handler = handler;
        }
    }
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static HRESULT WINAPI operation_get_Progress(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface,
    IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress **handler)
{
    struct deployment_operation *impl = impl_from_operation(iface);
    HRESULT hr = S_OK;

    if (!handler) return E_POINTER;
    *handler = NULL;
    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else if ((*handler = impl->progress_handler))
        IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress_AddRef(*handler);
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static HRESULT WINAPI operation_put_Completed(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface,
    IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress *handler)
{
    struct deployment_operation *impl = impl_from_operation(iface);
    AsyncStatus status = Started;
    HRESULT hr = S_OK;
    BOOL invoke = FALSE;

    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else if (impl->completed_assigned) hr = E_ILLEGAL_DELEGATE_ASSIGNMENT;
    else
    {
        impl->completed_assigned = TRUE;
        if (handler)
        {
            IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_AddRef(handler);
            impl->completed_handler = handler;
            status = impl->status;
            invoke = status != Started;
            if (invoke)
                IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_AddRef(handler);
        }
    }
    LeaveCriticalSection(&impl->lock);
    if (invoke)
    {
        IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_Invoke(
            handler, &impl->operation_iface, status);
        IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_Release(handler);
    }
    return hr;
}

static HRESULT WINAPI operation_get_Completed(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface,
    IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress **handler)
{
    struct deployment_operation *impl = impl_from_operation(iface);
    HRESULT hr = S_OK;

    if (!handler) return E_POINTER;
    *handler = NULL;
    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else if ((*handler = impl->completed_handler))
        IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_AddRef(*handler);
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static HRESULT WINAPI operation_GetResults(
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress *iface, IDeploymentResult **result)
{
    struct deployment_operation *impl = impl_from_operation(iface);
    HRESULT hr = S_OK;

    if (!result) return E_POINTER;
    *result = NULL;
    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else if (impl->status == Started) hr = E_ILLEGAL_METHOD_CALL;
    else if (impl->status == Canceled) hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
    else if (impl->status == Error) hr = impl->error_code;
    else if (impl->result)
    {
        IDeploymentResult_AddRef(impl->result);
        *result = impl->result;
    }
    else hr = E_UNEXPECTED;
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static const IAsyncOperationWithProgress_DeploymentResult_DeploymentProgressVtbl operation_vtbl =
{
    operation_QueryInterface,
    operation_AddRef,
    operation_Release,
    operation_GetIids,
    operation_GetRuntimeClassName,
    operation_GetTrustLevel,
    operation_put_Progress,
    operation_get_Progress,
    operation_put_Completed,
    operation_get_Completed,
    operation_GetResults,
};

static HRESULT WINAPI info_QueryInterface(IAsyncInfo *iface, REFIID iid, void **out)
{
    return operation_QueryInterface(&impl_from_info(iface)->operation_iface, iid, out);
}

static ULONG WINAPI info_AddRef(IAsyncInfo *iface)
{
    return operation_AddRef(&impl_from_info(iface)->operation_iface);
}

static ULONG WINAPI info_Release(IAsyncInfo *iface)
{
    return operation_Release(&impl_from_info(iface)->operation_iface);
}

static HRESULT WINAPI info_GetIids(IAsyncInfo *iface, ULONG *count, IID **iids)
{
    return operation_GetIids(&impl_from_info(iface)->operation_iface, count, iids);
}

static HRESULT WINAPI info_GetRuntimeClassName(IAsyncInfo *iface, HSTRING *name)
{
    return operation_GetRuntimeClassName(&impl_from_info(iface)->operation_iface, name);
}

static HRESULT WINAPI info_GetTrustLevel(IAsyncInfo *iface, TrustLevel *level)
{
    return operation_GetTrustLevel(&impl_from_info(iface)->operation_iface, level);
}

static HRESULT WINAPI info_get_Id(IAsyncInfo *iface, UINT32 *id)
{
    struct deployment_operation *impl = impl_from_info(iface);
    HRESULT hr = S_OK;

    if (!id) return E_POINTER;
    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else *id = impl->id;
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static HRESULT WINAPI info_get_Status(IAsyncInfo *iface, AsyncStatus *status)
{
    struct deployment_operation *impl = impl_from_info(iface);
    HRESULT hr = S_OK;

    if (!status) return E_POINTER;
    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else *status = impl->status;
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static HRESULT WINAPI info_get_ErrorCode(IAsyncInfo *iface, HRESULT *error_code)
{
    struct deployment_operation *impl = impl_from_info(iface);
    HRESULT hr = S_OK;

    if (!error_code) return E_POINTER;
    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else *error_code = impl->error_code;
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static void operation_invoke_completed(struct deployment_operation *impl, AsyncStatus status)
{
    IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress *handler = NULL;

    EnterCriticalSection(&impl->lock);
    if (!impl->closed && impl->completed_handler)
    {
        handler = impl->completed_handler;
        IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_AddRef(handler);
    }
    LeaveCriticalSection(&impl->lock);
    if (handler)
    {
        IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_Invoke(
            handler, &impl->operation_iface, status);
        IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_Release(handler);
    }
}

static HRESULT WINAPI info_Cancel(IAsyncInfo *iface)
{
    struct deployment_operation *impl = impl_from_info(iface);
    HRESULT hr = S_OK;

    EnterCriticalSection(&impl->lock);
    if (impl->closed) hr = E_ILLEGAL_METHOD_CALL;
    else if (impl->status == Started) impl->cancellation_requested = TRUE;
    LeaveCriticalSection(&impl->lock);
    return hr;
}

static HRESULT WINAPI info_Close(IAsyncInfo *iface)
{
    struct deployment_operation *impl = impl_from_info(iface);
    IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress *progress_handler = NULL;
    IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress *completed_handler = NULL;
    IDeploymentResult *result = NULL;
    HRESULT hr = S_OK;

    EnterCriticalSection(&impl->lock);
    if (impl->status == Started) hr = E_ILLEGAL_STATE_CHANGE;
    else if (!impl->closed)
    {
        impl->closed = TRUE;
        progress_handler = impl->progress_handler;
        impl->progress_handler = NULL;
        completed_handler = impl->completed_handler;
        impl->completed_handler = NULL;
        result = impl->result;
        impl->result = NULL;
    }
    LeaveCriticalSection(&impl->lock);
    if (progress_handler)
        IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress_Release(progress_handler);
    if (completed_handler)
        IAsyncOperationWithProgressCompletedHandler_DeploymentResult_DeploymentProgress_Release(completed_handler);
    if (result) IDeploymentResult_Release(result);
    return hr;
}

static const IAsyncInfoVtbl info_vtbl =
{
    info_QueryInterface,
    info_AddRef,
    info_Release,
    info_GetIids,
    info_GetRuntimeClassName,
    info_GetTrustLevel,
    info_get_Id,
    info_get_Status,
    info_get_ErrorCode,
    info_Cancel,
    info_Close,
};

static void operation_report_progress(struct deployment_operation *impl, DeploymentProgress progress)
{
    IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress *handler = NULL;

    EnterCriticalSection(&impl->lock);
    if (!impl->closed && impl->status == Started && impl->progress_handler)
    {
        handler = impl->progress_handler;
        IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress_AddRef(handler);
    }
    LeaveCriticalSection(&impl->lock);
    if (handler)
    {
        IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress_Invoke(
            handler, &impl->operation_iface, progress);
        IAsyncOperationProgressHandler_DeploymentResult_DeploymentProgress_Release(handler);
    }
}

static void operation_complete(struct deployment_operation *impl, AsyncStatus status, HRESULT error_code,
                               IDeploymentResult *result)
{
    BOOL complete = FALSE;

    EnterCriticalSection(&impl->lock);
    if (!impl->closed && impl->status == Started)
    {
        impl->status = status;
        impl->error_code = error_code;
        impl->result = result;
        complete = TRUE;
    }
    LeaveCriticalSection(&impl->lock);
    if (!complete)
    {
        if (result) IDeploymentResult_Release(result);
        return;
    }
    operation_invoke_completed(impl, status);
}

static BOOL WINAPI deployment_is_cancelled(void *context)
{
    struct deployment_operation *impl = context;
    BOOL cancelled;

    EnterCriticalSection(&impl->lock);
    cancelled = impl->cancellation_requested;
    LeaveCriticalSection(&impl->lock);
    return cancelled;
}

static DWORD WINAPI deployment_worker(void *parameter)
{
    struct deployment_operation *impl = parameter;
    IUriRuntimeClass *uri = NULL;
    IIterable_Uri *dependencies = NULL;
    IStream *stream;
    GUID activity_id = {0};
    IDeploymentResult *result = NULL;
    WCHAR error_text[512] = L"";
    DeploymentProgress progress = {DeploymentProgressState_Processing, 0};
    HRESULT hr, operation_error = S_OK;
    DWORD length;
    BOOL canceled;
    HRESULT com_hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    canceled = deployment_is_cancelled(impl);
    if (canceled)
    {
        operation_complete(impl, Canceled, HRESULT_FROM_WIN32(ERROR_CANCELLED), NULL);
        goto done;
    }
    if (FAILED(com_hr))
    {
        operation_error = com_hr;
        goto failed_operation;
    }
    stream = impl->uri_stream;
    impl->uri_stream = NULL;
    hr = CoGetInterfaceAndReleaseStream(stream, &IID_IUriRuntimeClass, (void **)&uri);
    if (FAILED(hr)) goto failed_operation;
    if (impl->dependencies_stream)
    {
        stream = impl->dependencies_stream;
        impl->dependencies_stream = NULL;
        hr = CoGetInterfaceAndReleaseStream(stream, &IID_IIterable_Uri, (void **)&dependencies);
        if (FAILED(hr)) goto failed_operation;
    }
    operation_report_progress(impl, progress);
    hr = package_transaction_add(uri, dependencies, impl->options, deployment_is_cancelled, impl);
    if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
    {
        operation_complete(impl, Canceled, hr, NULL);
        goto done;
    }
    if (FAILED(hr))
    {
        length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                                HRESULT_CODE(hr), 0, error_text, ARRAYSIZE(error_text), NULL);
        if (!length) error_text[0] = UNICODE_NULL;
    }
    if (FAILED(CoCreateGuid(&activity_id))) activity_id = null_guid;
    operation_error = deployment_result_create(error_text, FAILED(hr) ? hr : S_OK,
                                               &activity_id, &result);
    if (FAILED(operation_error)) goto failed_operation;
    progress.percentage = 100;
    operation_report_progress(impl, progress);
    operation_complete(impl, Completed, S_OK, result);
    result = NULL;
    goto done;

failed_operation:
    operation_complete(impl, Error, operation_error, NULL);

done:
    if (result) IDeploymentResult_Release(result);
    if (uri) IUriRuntimeClass_Release(uri);
    if (dependencies) IIterable_Uri_Release(dependencies);
    if (SUCCEEDED(com_hr)) CoUninitialize();
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(&impl->operation_iface);
    return 0;
}

HRESULT deployment_operation_add_package(IUriRuntimeClass *uri, IIterable_Uri *dependencies,
                                         DeploymentOptions options,
                                         IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation)
{
    struct deployment_operation *impl;
    HRESULT hr;

    if (!operation) return E_POINTER;
    *operation = NULL;
    if (!uri) return E_INVALIDARG;
    if (options != DeploymentOptions_None && options != DeploymentOptions_ForceApplicationShutdown)
        return E_INVALIDARG;
    if (!(impl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->operation_iface.lpVtbl = &operation_vtbl;
    impl->info_iface.lpVtbl = &info_vtbl;
    impl->ref = 1;
    impl->status = Started;
    impl->error_code = S_OK;
    impl->id = InterlockedIncrement(&next_operation_id);
    impl->options = options;
    if (!InitializeCriticalSectionEx(&impl->lock, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO))
    {
        HeapFree(GetProcessHeap(), 0, impl);
        return HRESULT_FROM_WIN32(GetLastError());
    }
    hr = CoMarshalInterThreadInterfaceInStream(&IID_IUriRuntimeClass, (IUnknown *)uri, &impl->uri_stream);
    if (SUCCEEDED(hr) && dependencies)
        hr = CoMarshalInterThreadInterfaceInStream(&IID_IIterable_Uri, (IUnknown *)dependencies,
                                                  &impl->dependencies_stream);
    if (FAILED(hr))
    {
        IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(&impl->operation_iface);
        return hr;
    }
    IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_AddRef(&impl->operation_iface);
    if (!QueueUserWorkItem(deployment_worker, impl, WT_EXECUTELONGFUNCTION))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(&impl->operation_iface);
        IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress_Release(&impl->operation_iface);
        return hr;
    }
    *operation = &impl->operation_iface;
    return S_OK;
}
