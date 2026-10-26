/*
 * Copyright 2022-2024 Zhiyi Zhang for CodeWeavers
 * Copyright 2025 Jactry Zeng for CodeWeavers
 * Copyright 2026 Conor McCarthy for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "private.h"
#include "robuffer.h"
#include <limits.h>

WINE_DEFAULT_DEBUG_CHANNEL(wintypes);

/* Synchronous wrapper for async operations returned by IOutputStream async methods.
 * The IAsyncInfo object is queried from the inner operation. */

#define DEFINE_IASYNCOPERATION(iface_type, cs_type_str, impl_type, result_type,                                   \
        handler_iface_type, inner_op_iface_type, outer_handler_iface_type)                                        \
struct impl_type                                                                                                  \
{                                                                                                                 \
    iface_type iface_type##_iface;                                                                                \
    handler_iface_type handler_iface_type##_iface;                                                                \
    IAsyncInfo *async_inner;                                                                                      \
    LONG refcount;                                                                                                \
    struct data_writer *data_writer;                                                                              \
    outer_handler_iface_type *outer_handler;                                                                      \
    AsyncStatus status;                                                                                           \
    result_type result;                                                                                           \
};                                                                                                                \
                                                                                                                  \
static inline struct impl_type *impl_from_##handler_iface_type(handler_iface_type *iface)                         \
{                                                                                                                 \
    return CONTAINING_RECORD(iface, struct impl_type, handler_iface_type##_iface);                                \
}                                                                                                                 \
                                                                                                                  \
static HRESULT WINAPI impl_type##_handler_QueryInterface(handler_iface_type *iface, REFIID iid, void **out)       \
{                                                                                                                 \
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IAgileObject) ||                                 \
        IsEqualGUID(iid, &IID_##handler_iface_type))                                                              \
    {                                                                                                             \
        IUnknown_AddRef(iface);                                                                                   \
        *out = iface;                                                                                             \
        return S_OK;                                                                                              \
    }                                                                                                             \
                                                                                                                  \
    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));                                   \
    *out = NULL;                                                                                                  \
    return E_NOINTERFACE;                                                                                         \
}                                                                                                                 \
                                                                                                                  \
static ULONG WINAPI impl_type##_handler_AddRef(handler_iface_type *iface)                                         \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##handler_iface_type(iface);                                               \
    return iface_type##_AddRef(&impl->iface_type##_iface);                                                        \
}                                                                                                                 \
                                                                                                                  \
static ULONG WINAPI impl_type##_handler_Release(handler_iface_type *iface)                                        \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##handler_iface_type(iface);                                               \
    return iface_type##_Release(&impl->iface_type##_iface);                                                       \
}                                                                                                                 \
                                                                                                                  \
static HRESULT impl_type##_handle_completion(struct impl_type *impl)                                              \
{                                                                                                                 \
    if (impl->status && impl->outer_handler)                                                                      \
        return outer_handler_iface_type##_Invoke(impl->outer_handler, &impl->iface_type##_iface, impl->status);   \
    return S_OK;                                                                                                  \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_handler_Invoke(handler_iface_type *iface,                                       \
        inner_op_iface_type *operation, AsyncStatus status)                                                       \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##handler_iface_type(iface);                                               \
    HRESULT hr;                                                                                                   \
    if (!status) return S_OK;                                                                                     \
    if (status == Completed && FAILED(hr = inner_op_iface_type##_GetResults(operation, &impl->result)))           \
        status = Error;                                                                                           \
    impl->status = status;                                                                                        \
    data_writer_async_complete(impl->data_writer);                                                                \
    return impl_type##_handle_completion(impl);                                                                   \
}                                                                                                                 \
                                                                                                                  \
static handler_iface_type##Vtbl impl_type##_handler_vtbl =                                                        \
{                                                                                                                 \
    impl_type##_handler_QueryInterface,                                                                           \
    impl_type##_handler_AddRef,                                                                                   \
    impl_type##_handler_Release,                                                                                  \
    impl_type##_handler_Invoke,                                                                                   \
};                                                                                                                \
                                                                                                                  \
static inline struct impl_type *impl_from_##iface_type(iface_type *iface)                                         \
{                                                                                                                 \
    return CONTAINING_RECORD(iface, struct impl_type, iface_type##_iface);                                        \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_QueryInterface(iface_type *iface, REFIID iid, void **out)                       \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##iface_type(iface);                                                       \
                                                                                                                  \
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);                                         \
                                                                                                                  \
    if (IsEqualGUID(iid, &IID_IUnknown) ||                                                                        \
        IsEqualGUID(iid, &IID_IInspectable) ||                                                                    \
        IsEqualGUID(iid, &IID_IAgileObject) ||                                                                    \
        IsEqualGUID(iid, &IID_##iface_type))                                                                      \
    {                                                                                                             \
        iface_type##_AddRef((*out = &impl->iface_type##_iface));                                                  \
        return S_OK;                                                                                              \
    }                                                                                                             \
                                                                                                                  \
    if (IsEqualGUID(iid, &IID_IAsyncInfo))                                                                        \
    {                                                                                                             \
        IAsyncInfo_AddRef(*out = impl->async_inner);                                                              \
        return S_OK;                                                                                              \
    }                                                                                                             \
                                                                                                                  \
    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));                                   \
    *out = NULL;                                                                                                  \
    return E_NOINTERFACE;                                                                                         \
}                                                                                                                 \
static ULONG WINAPI impl_type##_AddRef(iface_type *iface)                                                         \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##iface_type(iface);                                                       \
    ULONG ref = InterlockedIncrement(&impl->refcount);                                                            \
    TRACE("iface %p, ref %lu.\n", iface, ref);                                                                    \
    return ref;                                                                                                   \
}                                                                                                                 \
static ULONG WINAPI impl_type##_Release(iface_type *iface)                                                        \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##iface_type(iface);                                                       \
    ULONG ref = InterlockedDecrement(&impl->refcount);                                                            \
    TRACE("iface %p, ref %lu.\n", iface, ref);                                                                    \
                                                                                                                  \
    if (!ref)                                                                                                     \
    {                                                                                                             \
        IDataWriter_Release(&impl->data_writer->IDataWriter_iface);                                               \
        IAsyncInfo_Release(impl->async_inner);                                                                    \
        if (impl->outer_handler)                                                                                  \
            outer_handler_iface_type##_Release(impl->outer_handler);                                              \
        free(impl);                                                                                               \
    }                                                                                                             \
                                                                                                                  \
    return ref;                                                                                                   \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_GetIids(iface_type *iface, ULONG *iid_count, IID **iids)                        \
{                                                                                                                 \
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);                                     \
    return E_NOTIMPL;                                                                                             \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_GetRuntimeClassName(iface_type *iface, HSTRING *class_name)                     \
{                                                                                                                 \
    return WindowsCreateString(L"Windows.Foundation.IAsyncOperation`1<"cs_type_str">",                            \
                                ARRAY_SIZE(L"Windows.Foundation.IAsyncOperation`1<"cs_type_str">"),               \
                                class_name);                                                                      \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_GetTrustLevel(iface_type *iface, TrustLevel *trust_level)                       \
{                                                                                                                 \
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);                                                \
    return E_NOTIMPL;                                                                                             \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_put_Completed(iface_type *iface, outer_handler_iface_type *handler)             \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##iface_type(iface);                                                       \
    TRACE("iface %p, handler %p.\n", iface, handler);                                                             \
    impl->outer_handler = handler;                                                                                \
    outer_handler_iface_type##_AddRef(impl->outer_handler);                                                       \
    return impl_type##_handle_completion(impl);                                                                   \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_get_Completed(iface_type *iface, outer_handler_iface_type **handler)            \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##iface_type(iface);                                                       \
    TRACE("iface %p, handler %p.\n", iface, handler);                                                             \
    if ((*handler = impl->outer_handler))                                                                         \
        outer_handler_iface_type##_AddRef(*handler);                                                              \
    return S_OK;                                                                                                  \
}                                                                                                                 \
static HRESULT WINAPI impl_type##_GetResults(iface_type *iface, result_type *results)                             \
{                                                                                                                 \
    struct impl_type *impl = impl_from_##iface_type(iface);                                                       \
                                                                                                                  \
    TRACE("iface %p, results %p.\n", iface, results);                                                             \
                                                                                                                  \
    if (impl->status != Completed)                                                                                \
        return E_ILLEGAL_METHOD_CALL;                                                                             \
                                                                                                                  \
    *results = impl->result;                                                                                      \
    return S_OK;                                                                                                  \
}                                                                                                                 \
static const struct iface_type##Vtbl impl_type##_vtbl =                                                           \
{                                                                                                                 \
    /* IUnknown methods */                                                                                        \
    impl_type##_QueryInterface,                                                                                   \
    impl_type##_AddRef,                                                                                           \
    impl_type##_Release,                                                                                          \
    /* IInspectable methods */                                                                                    \
    impl_type##_GetIids,                                                                                          \
    impl_type##_GetRuntimeClassName,                                                                              \
    impl_type##_GetTrustLevel,                                                                                    \
    /* IAsyncOperation<iface_type> */                                                                             \
    impl_type##_put_Completed,                                                                                    \
    impl_type##_get_Completed,                                                                                    \
    impl_type##_GetResults,                                                                                       \
};                                                                                                                \
HRESULT async_operation_##result_type##_create(struct data_writer *data_writer,                                   \
        inner_op_iface_type *inner_op, iface_type **out)                                                          \
{                                                                                                                 \
    struct impl_type *impl;                                                                                       \
    HRESULT hr;                                                                                                   \
                                                                                                                  \
    *out = NULL;                                                                                                  \
    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;                                                 \
                                                                                                                  \
    impl->iface_type##_iface.lpVtbl = &impl_type##_vtbl;                                                          \
    impl->handler_iface_type##_iface.lpVtbl = &impl_type##_handler_vtbl;                                          \
    impl->data_writer = data_writer;                                                                              \
    impl->refcount = 1;                                                                                           \
                                                                                                                  \
    if (FAILED(hr = inner_op_iface_type##_QueryInterface(inner_op, &IID_IAsyncInfo, (void **)&impl->async_inner)) \
            || FAILED(hr = inner_op_iface_type##_put_Completed(inner_op, &impl->handler_iface_type##_iface)))     \
    {                                                                                                             \
        if (impl->async_inner)                                                                                    \
            IAsyncInfo_Release(impl->async_inner);                                                                \
        free(impl);                                                                                               \
        return hr;                                                                                                \
    }                                                                                                             \
                                                                                                                  \
    IDataWriter_AddRef(&data_writer->IDataWriter_iface);                                                          \
                                                                                                                  \
    *out = &impl->iface_type##_iface;                                                                             \
    TRACE("created IAsyncOperation %p\n", *out);                                                                  \
    return S_OK;                                                                                                  \
}                                                                                                                 \

static HRESULT buffer_create(UINT32 capacity, IBuffer **out)
{
    IBufferFactory *buffer_factory;
    HRESULT hr;

    IActivationFactory_QueryInterface(buffer_activation_factory, &IID_IBufferFactory, (void **)&buffer_factory);
    hr = IBufferFactory_Create(buffer_factory, capacity, out);
    IBufferFactory_Release(buffer_factory);
    return hr;
}

struct data_reader
{
    IDataReader IDataReader_iface;
    IClosable IClosable_iface;
    LONG ref;
    IInputStream *stream;
    IBuffer *buffer;
    IBufferByteAccess *access;
    BYTE *data;
    UINT32 length;
    UINT32 position;
    UnicodeEncoding unicode_encoding;
    ByteOrder byte_order;
    InputStreamOptions input_stream_options;
    BOOL closed;
};

static const struct IDataReaderVtbl data_reader_vtbl;
static const struct IClosableVtbl data_reader_closable_vtbl;

static struct data_reader *impl_from_IDataReader(IDataReader *iface)
{
    return CONTAINING_RECORD(iface, struct data_reader, IDataReader_iface);
}

static struct data_reader *impl_from_IClosable(IClosable *iface)
{
    return CONTAINING_RECORD(iface, struct data_reader, IClosable_iface);
}

static HRESULT data_reader_set_buffer(struct data_reader *impl, IBuffer *buffer)
{
    HRESULT hr;

    if (FAILED(hr = IBuffer_QueryInterface(buffer, &IID_IBufferByteAccess, (void **)&impl->access)))
        return hr;
    if (FAILED(hr = IBufferByteAccess_Buffer(impl->access, &impl->data)))
    {
        IBufferByteAccess_Release(impl->access);
        impl->access = NULL;
        return hr;
    }
    if (FAILED(hr = IBuffer_get_Length(buffer, &impl->length)))
    {
        IBufferByteAccess_Release(impl->access);
        impl->access = NULL;
        impl->data = NULL;
        return hr;
    }
    impl->buffer = buffer;
    IBuffer_AddRef(buffer);
    return S_OK;
}

static HRESULT data_reader_create(IBuffer *buffer, IInputStream *stream, IDataReader **out)
{
    struct data_reader *impl;
    HRESULT hr;

    *out = NULL;
    if (!(impl = calloc(1, sizeof(*impl))))
        return E_OUTOFMEMORY;
    impl->IDataReader_iface.lpVtbl = &data_reader_vtbl;
    impl->IClosable_iface.lpVtbl = &data_reader_closable_vtbl;
    impl->ref = 1;
    impl->unicode_encoding = Utf8;
    impl->byte_order = BigEndian;
    impl->input_stream_options = None;
    if (stream)
    {
        impl->stream = stream;
        IInputStream_AddRef(stream);
    }
    if (buffer && FAILED(hr = data_reader_set_buffer(impl, buffer)))
    {
        if (impl->stream)
            IInputStream_Release(impl->stream);
        free(impl);
        return hr;
    }
    *out = &impl->IDataReader_iface;
    return S_OK;
}

static HRESULT data_reader_read_bytes(struct data_reader *impl, BYTE *value, UINT32 count)
{
    if (impl->closed)
        return E_ILLEGAL_METHOD_CALL;
    if (count > impl->length - impl->position)
        return E_BOUNDS;
    if (count && !value)
        return E_INVALIDARG;
    if (count)
        memcpy(value, impl->data + impl->position, count);
    impl->position += count;
    return S_OK;
}

static HRESULT data_reader_read_value(struct data_reader *impl, void *value, UINT32 size)
{
    BYTE bytes[sizeof(GUID)];
    UINT16 endian_test = 1;
    BOOL host_little_endian = *(BYTE *)&endian_test;
    UINT32 i;
    HRESULT hr;

    if (size > sizeof(bytes))
        return E_INVALIDARG;
    if (FAILED(hr = data_reader_read_bytes(impl, bytes, size)))
        return hr;
    if ((impl->byte_order == BigEndian) == host_little_endian && size > 1)
        for (i = 0; i < size; ++i)
            ((BYTE *)value)[i] = bytes[size - i - 1];
    else
        memcpy(value, bytes, size);
    return S_OK;
}

static HRESULT data_reader_QueryInterface(IDataReader *iface, REFIID iid, void **out)
{
    struct data_reader *impl = impl_from_IDataReader(iface);

    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IDataReader))
        *out = &impl->IDataReader_iface;
    else if (IsEqualGUID(iid, &IID_IClosable))
        *out = &impl->IClosable_iface;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }
    IInspectable_AddRef(*out);
    return S_OK;
}

static ULONG data_reader_addref(struct data_reader *impl)
{
    return InterlockedIncrement(&impl->ref);
}

static ULONG data_reader_release(struct data_reader *impl)
{
    ULONG ref = InterlockedDecrement(&impl->ref);

    if (!ref)
    {
        if (impl->stream)
        {
            IClosable *closable;
            if (SUCCEEDED(IInputStream_QueryInterface(impl->stream, &IID_IClosable, (void **)&closable)))
            {
                IClosable_Close(closable);
                IClosable_Release(closable);
            }
            IInputStream_Release(impl->stream);
        }
        if (impl->access)
            IBufferByteAccess_Release(impl->access);
        if (impl->buffer)
            IBuffer_Release(impl->buffer);
        free(impl);
    }
    return ref;
}

static ULONG WINAPI data_reader_AddRef(IDataReader *iface)
{
    return data_reader_addref(impl_from_IDataReader(iface));
}

static ULONG WINAPI data_reader_Release(IDataReader *iface)
{
    return data_reader_release(impl_from_IDataReader(iface));
}

static HRESULT WINAPI data_reader_GetIids(IDataReader *iface, ULONG *iid_count, IID **iids)
{
    *iids = CoTaskMemAlloc(2 * sizeof(**iids));
    if (!*iids)
        return E_OUTOFMEMORY;
    (*iids)[0] = IID_IDataReader;
    (*iids)[1] = IID_IClosable;
    *iid_count = 2;
    return S_OK;
}

static HRESULT WINAPI data_reader_GetRuntimeClassName(IDataReader *iface, HSTRING *class_name)
{
    static const WCHAR name[] = L"Windows.Storage.Streams.DataReader";
    return WindowsCreateString(name, ARRAY_SIZE(name) - 1, class_name);
}

static HRESULT WINAPI data_reader_GetTrustLevel(IDataReader *iface, TrustLevel *trust_level)
{
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI data_reader_get_UnconsumedBufferLength(IDataReader *iface, UINT32 *value)
{
    struct data_reader *impl = impl_from_IDataReader(iface);
    if (impl->closed)
        return E_ILLEGAL_METHOD_CALL;
    *value = impl->length - impl->position;
    return S_OK;
}

static HRESULT WINAPI data_reader_get_UnicodeEncoding(IDataReader *iface, UnicodeEncoding *value)
{
    *value = impl_from_IDataReader(iface)->unicode_encoding;
    return S_OK;
}

static HRESULT WINAPI data_reader_put_UnicodeEncoding(IDataReader *iface, UnicodeEncoding value)
{
    impl_from_IDataReader(iface)->unicode_encoding = value;
    return S_OK;
}

static HRESULT WINAPI data_reader_get_ByteOrder(IDataReader *iface, ByteOrder *value)
{
    *value = impl_from_IDataReader(iface)->byte_order;
    return S_OK;
}

static HRESULT WINAPI data_reader_put_ByteOrder(IDataReader *iface, ByteOrder value)
{
    impl_from_IDataReader(iface)->byte_order = value;
    return S_OK;
}

static HRESULT WINAPI data_reader_get_InputStreamOptions(IDataReader *iface, InputStreamOptions *value)
{
    *value = impl_from_IDataReader(iface)->input_stream_options;
    return S_OK;
}

static HRESULT WINAPI data_reader_put_InputStreamOptions(IDataReader *iface, InputStreamOptions value)
{
    impl_from_IDataReader(iface)->input_stream_options = value;
    return S_OK;
}

static HRESULT WINAPI data_reader_ReadByte(IDataReader *iface, BYTE *value)
{
    return data_reader_read_value(impl_from_IDataReader(iface), value, sizeof(*value));
}

static HRESULT WINAPI data_reader_ReadBytes(IDataReader *iface, UINT32 value_size, BYTE *value)
{
    return data_reader_read_bytes(impl_from_IDataReader(iface), value, value_size);
}

static HRESULT WINAPI data_reader_ReadBuffer(IDataReader *iface, UINT32 length, IBuffer **buffer)
{
    struct data_reader *impl = impl_from_IDataReader(iface);
    IBufferByteAccess *access;
    BYTE *data;
    HRESULT hr;

    *buffer = NULL;
    if (impl->closed)
        return E_ILLEGAL_METHOD_CALL;
    if (length > impl->length - impl->position)
        return E_BOUNDS;
    if (FAILED(hr = buffer_create(length, buffer)))
        return hr;
    if (FAILED(hr = IBuffer_QueryInterface(*buffer, &IID_IBufferByteAccess, (void **)&access)))
    {
        IBuffer_Release(*buffer);
        *buffer = NULL;
        return hr;
    }
    if (FAILED(hr = IBufferByteAccess_Buffer(access, &data)))
    {
        IBufferByteAccess_Release(access);
        IBuffer_Release(*buffer);
        *buffer = NULL;
        return hr;
    }
    if (length)
        memcpy(data, impl->data + impl->position, length);
    IBuffer_put_Length(*buffer, length);
    IBufferByteAccess_Release(access);
    impl->position += length;
    return S_OK;
}

static HRESULT WINAPI data_reader_ReadBoolean(IDataReader *iface, boolean *value)
{
    return data_reader_read_value(impl_from_IDataReader(iface), value, sizeof(*value));
}

#define DEFINE_DATA_READER_READ(name, type) \
static HRESULT WINAPI data_reader_##name(IDataReader *iface, type *value) \
{ \
    return data_reader_read_value(impl_from_IDataReader(iface), value, sizeof(*value)); \
}

DEFINE_DATA_READER_READ(ReadInt16, INT16)
DEFINE_DATA_READER_READ(ReadInt32, INT32)
DEFINE_DATA_READER_READ(ReadInt64, INT64)
DEFINE_DATA_READER_READ(ReadUInt16, UINT16)
DEFINE_DATA_READER_READ(ReadUInt32, UINT32)
DEFINE_DATA_READER_READ(ReadUInt64, UINT64)
DEFINE_DATA_READER_READ(ReadSingle, FLOAT)
DEFINE_DATA_READER_READ(ReadDouble, DOUBLE)

static HRESULT WINAPI data_reader_ReadGuid(IDataReader *iface, GUID *value)
{
    return data_reader_read_value(impl_from_IDataReader(iface), value, sizeof(*value));
}

static HRESULT WINAPI data_reader_ReadDateTime(IDataReader *iface, DateTime *value)
{
    return data_reader_read_value(impl_from_IDataReader(iface), &value->UniversalTime, sizeof(value->UniversalTime));
}

static HRESULT WINAPI data_reader_ReadTimeSpan(IDataReader *iface, TimeSpan *value)
{
    return data_reader_read_value(impl_from_IDataReader(iface), &value->Duration, sizeof(value->Duration));
}

static HRESULT WINAPI data_reader_ReadString(IDataReader *iface, UINT32 code_unit_count, HSTRING *value)
{
    struct data_reader *impl = impl_from_IDataReader(iface);
    const BYTE *data;
    WCHAR *text = NULL;
    UINT32 byte_count, wide_count, i;
    int converted;
    HRESULT hr;

    *value = NULL;
    if (impl->closed)
        return E_ILLEGAL_METHOD_CALL;
    if (impl->unicode_encoding == Utf8)
    {
        byte_count = code_unit_count;
        if (byte_count > impl->length - impl->position)
            return E_BOUNDS;
        if (!byte_count)
            return WindowsCreateString(L"", 0, value);
        data = impl->data + impl->position;
        converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)data, byte_count, NULL, 0);
        if (!converted)
            return HRESULT_FROM_WIN32(GetLastError());
        wide_count = converted;
        if (!(text = malloc(wide_count * sizeof(*text))))
            return E_OUTOFMEMORY;
        converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)data, byte_count,
                text, wide_count);
        if (!converted)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            free(text);
            return hr;
        }
    }
    else if (impl->unicode_encoding == Utf16LE || impl->unicode_encoding == Utf16BE)
    {
        if (code_unit_count > ~(UINT32)0 / sizeof(WCHAR))
            return E_BOUNDS;
        byte_count = code_unit_count * sizeof(WCHAR);
        if (byte_count > impl->length - impl->position)
            return E_BOUNDS;
        if (!code_unit_count)
            return WindowsCreateString(L"", 0, value);
        if (!(text = malloc(byte_count)))
            return E_OUTOFMEMORY;
        data = impl->data + impl->position;
        for (i = 0; i < code_unit_count; ++i)
        {
            if (impl->unicode_encoding == Utf16LE)
                text[i] = data[i * 2] | ((WCHAR)data[i * 2 + 1] << 8);
            else
                text[i] = ((WCHAR)data[i * 2] << 8) | data[i * 2 + 1];
        }
        wide_count = code_unit_count;
    }
    else
        return E_INVALIDARG;

    hr = WindowsCreateString(text, wide_count, value);
    free(text);
    if (SUCCEEDED(hr))
        impl->position += byte_count;
    return hr;
}

static HRESULT WINAPI data_reader_LoadAsync(IDataReader *iface, UINT32 count, IAsyncOperation_UINT32 **operation)
{
    struct data_reader *impl = impl_from_IDataReader(iface);
    TRACE("iface %p, count %u, operation %p stub.\n", iface, count, operation);
    *operation = NULL;
    if (!impl->stream)
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);
    return E_NOTIMPL;
}

static HRESULT WINAPI data_reader_DetachBuffer(IDataReader *iface, IBuffer **buffer)
{
    struct data_reader *impl = impl_from_IDataReader(iface);
    TRACE("iface %p, buffer %p.\n", iface, buffer);
    *buffer = impl->buffer;
    impl->buffer = NULL;
    if (impl->access)
    {
        IBufferByteAccess_Release(impl->access);
        impl->access = NULL;
    }
    impl->data = NULL;
    impl->length = 0;
    impl->position = 0;
    return S_OK;
}

static HRESULT WINAPI data_reader_DetachStream(IDataReader *iface, IInputStream **stream)
{
    struct data_reader *impl = impl_from_IDataReader(iface);
    TRACE("iface %p, stream %p.\n", iface, stream);
    *stream = impl->stream;
    impl->stream = NULL;
    return S_OK;
}

static const struct IDataReaderVtbl data_reader_vtbl =
{
    data_reader_QueryInterface,
    data_reader_AddRef,
    data_reader_Release,
    data_reader_GetIids,
    data_reader_GetRuntimeClassName,
    data_reader_GetTrustLevel,
    data_reader_get_UnconsumedBufferLength,
    data_reader_get_UnicodeEncoding,
    data_reader_put_UnicodeEncoding,
    data_reader_get_ByteOrder,
    data_reader_put_ByteOrder,
    data_reader_get_InputStreamOptions,
    data_reader_put_InputStreamOptions,
    data_reader_ReadByte,
    data_reader_ReadBytes,
    data_reader_ReadBuffer,
    data_reader_ReadBoolean,
    data_reader_ReadGuid,
    data_reader_ReadInt16,
    data_reader_ReadInt32,
    data_reader_ReadInt64,
    data_reader_ReadUInt16,
    data_reader_ReadUInt32,
    data_reader_ReadUInt64,
    data_reader_ReadSingle,
    data_reader_ReadDouble,
    data_reader_ReadString,
    data_reader_ReadDateTime,
    data_reader_ReadTimeSpan,
    data_reader_LoadAsync,
    data_reader_DetachBuffer,
    data_reader_DetachStream,
};

static HRESULT WINAPI data_reader_closable_QueryInterface(IClosable *iface, REFIID iid, void **out)
{
    return IDataReader_QueryInterface(&impl_from_IClosable(iface)->IDataReader_iface, iid, out);
}

static ULONG WINAPI data_reader_closable_AddRef(IClosable *iface)
{
    return data_reader_addref(impl_from_IClosable(iface));
}

static ULONG WINAPI data_reader_closable_Release(IClosable *iface)
{
    return data_reader_release(impl_from_IClosable(iface));
}

static HRESULT WINAPI data_reader_Close(IClosable *iface)
{
    struct data_reader *impl = impl_from_IClosable(iface);
    if (impl->closed)
        return S_OK;
    impl->closed = TRUE;
    if (impl->stream)
    {
        IClosable *closable;
        if (SUCCEEDED(IInputStream_QueryInterface(impl->stream, &IID_IClosable, (void **)&closable)))
        {
            IClosable_Close(closable);
            IClosable_Release(closable);
        }
        IInputStream_Release(impl->stream);
        impl->stream = NULL;
    }
    if (impl->access)
    {
        IBufferByteAccess_Release(impl->access);
        impl->access = NULL;
    }
    if (impl->buffer)
    {
        IBuffer_Release(impl->buffer);
        impl->buffer = NULL;
    }
    impl->data = NULL;
    impl->length = 0;
    impl->position = 0;
    return S_OK;
}

static HRESULT WINAPI data_reader_closable_GetIids(IClosable *iface, ULONG *iid_count, IID **iids)
{
    return IDataReader_GetIids(&impl_from_IClosable(iface)->IDataReader_iface, iid_count, iids);
}

static HRESULT WINAPI data_reader_closable_GetRuntimeClassName(IClosable *iface, HSTRING *class_name)
{
    return IDataReader_GetRuntimeClassName(&impl_from_IClosable(iface)->IDataReader_iface, class_name);
}

static HRESULT WINAPI data_reader_closable_GetTrustLevel(IClosable *iface, TrustLevel *trust_level)
{
    return IDataReader_GetTrustLevel(&impl_from_IClosable(iface)->IDataReader_iface, trust_level);
}

static const struct IClosableVtbl data_reader_closable_vtbl =
{
    data_reader_closable_QueryInterface,
    data_reader_closable_AddRef,
    data_reader_closable_Release,
    data_reader_closable_GetIids,
    data_reader_closable_GetRuntimeClassName,
    data_reader_closable_GetTrustLevel,
    data_reader_Close,
};

struct data_reader_factory
{
    IActivationFactory IActivationFactory_iface;
    IDataReaderFactory IDataReaderFactory_iface;
    IDataReaderStatics IDataReaderStatics_iface;
    LONG ref;
};

static struct data_reader_factory *impl_from_data_reader_activation_factory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct data_reader_factory, IActivationFactory_iface);
}

static HRESULT WINAPI data_reader_activation_factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    struct data_reader_factory *impl = impl_from_data_reader_activation_factory(iface);

    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IActivationFactory))
        *out = &impl->IActivationFactory_iface;
    else if (IsEqualGUID(iid, &IID_IDataReaderFactory))
        *out = &impl->IDataReaderFactory_iface;
    else if (IsEqualGUID(iid, &IID_IDataReaderStatics))
        *out = &impl->IDataReaderStatics_iface;
    else
    {
        *out = NULL;
        return E_NOINTERFACE;
    }
    IActivationFactory_AddRef(iface);
    return S_OK;
}

static ULONG WINAPI data_reader_activation_factory_AddRef(IActivationFactory *iface)
{
    return InterlockedIncrement(&impl_from_data_reader_activation_factory(iface)->ref);
}

static ULONG WINAPI data_reader_activation_factory_Release(IActivationFactory *iface)
{
    return InterlockedDecrement(&impl_from_data_reader_activation_factory(iface)->ref);
}

static HRESULT WINAPI data_reader_activation_factory_GetIids(IActivationFactory *iface, ULONG *iid_count, IID **iids)
{
    *iid_count = 0;
    *iids = NULL;
    return S_OK;
}

static HRESULT WINAPI data_reader_activation_factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *class_name)
{
    static const WCHAR name[] = L"Windows.Storage.Streams.DataReader";
    return WindowsCreateString(name, ARRAY_SIZE(name) - 1, class_name);
}

static HRESULT WINAPI data_reader_activation_factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *trust_level)
{
    *trust_level = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI data_reader_activation_factory_ActivateInstance(IActivationFactory *iface, IInspectable **instance)
{
    *instance = NULL;
    return E_NOTIMPL;
}

static const struct IActivationFactoryVtbl data_reader_activation_factory_vtbl =
{
    data_reader_activation_factory_QueryInterface,
    data_reader_activation_factory_AddRef,
    data_reader_activation_factory_Release,
    data_reader_activation_factory_GetIids,
    data_reader_activation_factory_GetRuntimeClassName,
    data_reader_activation_factory_GetTrustLevel,
    data_reader_activation_factory_ActivateInstance,
};

DEFINE_IINSPECTABLE(reader_factory, IDataReaderFactory, struct data_reader_factory, IActivationFactory_iface)
DEFINE_IINSPECTABLE(reader_statics, IDataReaderStatics, struct data_reader_factory, IActivationFactory_iface)

static HRESULT WINAPI data_reader_factory_CreateDataReader(IDataReaderFactory *iface, IInputStream *input_stream,
        IDataReader **data_reader)
{
    if (!input_stream)
        return E_INVALIDARG;
    return data_reader_create(NULL, input_stream, data_reader);
}

static HRESULT WINAPI data_reader_statics_FromBuffer(IDataReaderStatics *iface, IBuffer *buffer,
        IDataReader **data_reader)
{
    if (!buffer)
        return E_INVALIDARG;
    return data_reader_create(buffer, NULL, data_reader);
}

static const struct IDataReaderFactoryVtbl data_reader_factory_vtbl =
{
    reader_factory_QueryInterface,
    reader_factory_AddRef,
    reader_factory_Release,
    reader_factory_GetIids,
    reader_factory_GetRuntimeClassName,
    reader_factory_GetTrustLevel,
    data_reader_factory_CreateDataReader,
};

static const struct IDataReaderStaticsVtbl data_reader_statics_vtbl =
{
    reader_statics_QueryInterface,
    reader_statics_AddRef,
    reader_statics_Release,
    reader_statics_GetIids,
    reader_statics_GetRuntimeClassName,
    reader_statics_GetTrustLevel,
    data_reader_statics_FromBuffer,
};

static struct data_reader_factory data_reader_factory =
{
    {&data_reader_activation_factory_vtbl},
    {&data_reader_factory_vtbl},
    {&data_reader_statics_vtbl},
    1
};

IActivationFactory *data_reader_activation_factory = &data_reader_factory.IActivationFactory_iface;

struct data_writer
{
    IDataWriter IDataWriter_iface;
    LONG ref;

    IOutputStream *stream;
    IBuffer *buffer;
    byte *data;
    BOOL storing;
    UnicodeEncoding unicode_encoding;
    ByteOrder byte_order;
};

static HRESULT data_writer_async_complete(struct data_writer *impl);

DEFINE_IASYNCOPERATION(IAsyncOperation_UINT32, "IAsyncOperation<UInt32>", async_uint32, UINT32, \
        IAsyncOperationWithProgressCompletedHandler_UINT32_UINT32, \
        IAsyncOperationWithProgress_UINT32_UINT32, \
        IAsyncOperationCompletedHandler_UINT32)

static HRESULT data_writer_init_buffer(struct data_writer *impl, UINT32 extra_capacity)
{
    /* Native capacity starts at 0x88 */
    UINT32 new_capacity, capacity = max(extra_capacity, 0x88), pos = 0;
    IBufferByteAccess *access;
    IBuffer *buffer;
    HRESULT hr;
    byte *data;

    if (impl->buffer)
    {
        IBuffer_get_Capacity(impl->buffer, &capacity);
        IBuffer_get_Length(impl->buffer, &pos);

        new_capacity = pos + extra_capacity;
        if (new_capacity < pos || new_capacity < extra_capacity)
            return E_OUTOFMEMORY;
        if (new_capacity <= capacity)
            return S_OK;

        /* If allocation size grows by 50%, the sixth allocation can fit in freed
         * memory of the first four if they were contiguous. This matches native. */
        capacity = max(new_capacity, capacity + capacity / 2u);
    }

    if (FAILED(hr = buffer_create(capacity, &buffer)))
        return hr;

    IBuffer_QueryInterface(buffer, &IID_IBufferByteAccess, (void **)&access);
    IBufferByteAccess_Buffer(access, &data);
    IBufferByteAccess_Release(access);

    if (impl->buffer)
    {
        memcpy(data, impl->data, pos);
        IBuffer_Release(impl->buffer);
    }

    impl->buffer = buffer;
    impl->data = data;

    return S_OK;
}

static HRESULT data_writer_write_value(struct data_writer *impl, const void *value, UINT32 size)
{
    UINT32 pos, i;
    UINT16 endian_test = 1;
    BOOL host_little_endian = *(BYTE *)&endian_test;
    HRESULT hr;

    if (FAILED(hr = data_writer_init_buffer(impl, size)))
        return hr;

    IBuffer_get_Length(impl->buffer, &pos);
    if ((impl->byte_order == BigEndian) == host_little_endian && size > 1)
    {
        const BYTE *bytes = value;
        for (i = 0; i < size; ++i)
            impl->data[pos + i] = bytes[size - i - 1];
    }
    else
        memcpy(&impl->data[pos], value, size);

    return IBuffer_put_Length(impl->buffer, pos + size);
}

static HRESULT data_writer_write_bytes(struct data_writer *impl, const BYTE *data, UINT32 size)
{
    UINT32 pos;
    HRESULT hr;

    if (!size)
        return S_OK;
    if (!data)
        return E_INVALIDARG;
    if (FAILED(hr = data_writer_init_buffer(impl, size)))
        return hr;

    IBuffer_get_Length(impl->buffer, &pos);
    memcpy(&impl->data[pos], data, size);
    return IBuffer_put_Length(impl->buffer, pos + size);
}

static HRESULT data_writer_measure_string(struct data_writer *impl, HSTRING value, UINT32 *size)
{
    const WCHAR *string;
    UINT32 length;
    int result;

    string = WindowsGetStringRawBuffer(value, &length);
    switch (impl->unicode_encoding)
    {
    case Utf8:
        if (!length)
        {
            *size = 0;
            return S_OK;
        }
        if (length > (UINT32)INT_MAX)
            return E_OUTOFMEMORY;
        result = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, string, length, NULL, 0, NULL, NULL);
        if (!result)
            return HRESULT_FROM_WIN32(GetLastError());
        *size = (UINT32)result;
        return S_OK;
    case Utf16LE:
    case Utf16BE:
        *size = length;
        return S_OK;
    default:
        return E_INVALIDARG;
    }
}

static struct data_writer *impl_from_IDataWriter(IDataWriter *iface)
{
    return CONTAINING_RECORD(iface, struct data_writer, IDataWriter_iface);
}

static HRESULT WINAPI data_writer_QueryInterface(IDataWriter *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown)
            || IsEqualGUID(iid, &IID_IInspectable)
            || IsEqualGUID(iid, &IID_IAgileObject)
            || IsEqualGUID(iid, &IID_IDataWriter))
    {
        *out = iface;
        IDataWriter_AddRef(iface);
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI data_writer_AddRef(IDataWriter *iface)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    ULONG ref = InterlockedIncrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static ULONG WINAPI data_writer_Release(IDataWriter *iface)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);

    TRACE("iface %p, ref %lu.\n", iface, ref);

    if (!ref)
    {
        if (impl->stream)
        {
            IClosable *closable;
            HRESULT hr;

            if (SUCCEEDED(hr = IOutputStream_QueryInterface(impl->stream, &IID_IClosable, (void **)&closable)))
            {
                hr = IClosable_Close(closable);
                IClosable_Release(closable);
            }

            if (FAILED(hr))
                WARN("Failed to close stream, hr %#lx.\n", hr);

            IOutputStream_Release(impl->stream);
        }
        if (impl->buffer)
            IBuffer_Release(impl->buffer);
        free(impl);
    }

    return ref;
}

static HRESULT WINAPI data_writer_GetIids(IDataWriter *iface, ULONG *iid_count, IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT WINAPI data_writer_GetRuntimeClassName(IDataWriter *iface, HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);
    return E_NOTIMPL;
}

static HRESULT WINAPI data_writer_GetTrustLevel(IDataWriter *iface, TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT WINAPI data_writer_get_UnstoredBufferLength(IDataWriter *iface, UINT32 *value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %p.\n", iface, value);
    return IBuffer_get_Length(impl->buffer, value);
}

static HRESULT WINAPI data_writer_get_UnicodeEncoding(IDataWriter *iface, UnicodeEncoding *value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %p.\n", iface, value);
    *value = impl->unicode_encoding;
    return S_OK;
}

static HRESULT WINAPI data_writer_put_UnicodeEncoding(IDataWriter *iface, UnicodeEncoding value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %u.\n", iface, value);
    impl->unicode_encoding = value;
    return S_OK;
}

static HRESULT WINAPI data_writer_get_ByteOrder(IDataWriter *iface, ByteOrder *value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %p.\n", iface, value);
    *value = impl->byte_order;
    return S_OK;
}

static HRESULT WINAPI data_writer_put_ByteOrder(IDataWriter *iface, ByteOrder value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %u.\n", iface, value);
    impl->byte_order = value;
    return S_OK;
}

static HRESULT WINAPI data_writer_WriteByte(IDataWriter *iface, BYTE value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %u.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteBytes(IDataWriter *iface, UINT32 value_size, BYTE *value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);

    TRACE("iface %p, value_size %u, value %p.\n", iface, value_size, value);
    return data_writer_write_bytes(impl, value, value_size);
}

static HRESULT WINAPI data_writer_WriteBufferRange(IDataWriter *iface, IBuffer *buffer, UINT32 start, UINT32 count);

static HRESULT WINAPI data_writer_WriteBuffer(IDataWriter *iface, IBuffer *buffer)
{
    UINT32 length;
    HRESULT hr;

    TRACE("iface %p, buffer %p.\n", iface, buffer);

    if (!buffer)
        return E_INVALIDARG;
    if (FAILED(hr = IBuffer_get_Length(buffer, &length)))
        return hr;

    return data_writer_WriteBufferRange(iface, buffer, 0, length);
}

static HRESULT WINAPI data_writer_WriteBufferRange(IDataWriter *iface, IBuffer *buffer, UINT32 start, UINT32 count)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    IBufferByteAccess *access;
    UINT32 length, pos;
    BYTE *source, *copy;
    HRESULT hr;

    TRACE("iface %p, buffer %p, start %u, count %u.\n", iface, buffer, start, count);

    if (!buffer)
        return E_INVALIDARG;
    if (FAILED(hr = IBuffer_get_Length(buffer, &length)))
        return hr;
    if (start > length || count > length - start)
        return E_INVALIDARG;
    if (!count)
        return S_OK;
    if (FAILED(hr = IBuffer_QueryInterface(buffer, &IID_IBufferByteAccess, (void **)&access)))
        return hr;
    if (FAILED(hr = IBufferByteAccess_Buffer(access, &source)))
    {
        IBufferByteAccess_Release(access);
        return hr;
    }
    if (!(copy = malloc(count)))
    {
        IBufferByteAccess_Release(access);
        return E_OUTOFMEMORY;
    }
    memcpy(copy, source + start, count);
    IBufferByteAccess_Release(access);

    if (FAILED(hr = data_writer_init_buffer(impl, count)))
    {
        free(copy);
        return hr;
    }
    IBuffer_get_Length(impl->buffer, &pos);
    memcpy(&impl->data[pos], copy, count);
    free(copy);
    return IBuffer_put_Length(impl->buffer, pos + count);
}

static HRESULT WINAPI data_writer_WriteBoolean(IDataWriter *iface, boolean value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %u.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteGuid(IDataWriter *iface, GUID value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %s.\n", iface, debugstr_guid(&value));
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteInt16(IDataWriter *iface, INT16 value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %d.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteInt32(IDataWriter *iface, INT32 value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %d.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteInt64(IDataWriter *iface, INT64 value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %I64d.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteUInt16(IDataWriter *iface, UINT16 value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %u.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteUInt32(IDataWriter *iface, UINT32 value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %u.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteUInt64(IDataWriter *iface, UINT64 value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %I64u.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteSingle(IDataWriter *iface, FLOAT value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %.7f.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteDouble(IDataWriter *iface, DOUBLE value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %.15f.\n", iface, value);
    return data_writer_write_value(impl, &value, sizeof(value));
}

static HRESULT WINAPI data_writer_WriteDateTime(IDataWriter *iface, DateTime value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %I64u.\n", iface, value.UniversalTime);
    return data_writer_write_value(impl, &value.UniversalTime, sizeof(value.UniversalTime));
}

static HRESULT WINAPI data_writer_WriteTimeSpan(IDataWriter *iface, TimeSpan value)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %I64u.\n", iface, value.Duration);
    return data_writer_write_value(impl, &value.Duration, sizeof(value.Duration));
}

static HRESULT WINAPI data_writer_WriteString(IDataWriter *iface, HSTRING value, UINT32 *code_unit_count)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    const WCHAR *string;
    BYTE *encoded;
    UINT32 length, size, byte_size, i;
    HRESULT hr;

    TRACE("iface %p, value %s, code_unit_count %p.\n", iface, debugstr_hstring(value), code_unit_count);

    if (FAILED(hr = data_writer_measure_string(impl, value, &size)))
        return hr;
    string = WindowsGetStringRawBuffer(value, &length);
    byte_size = size;
    if (impl->unicode_encoding != Utf8)
    {
        if (size > ~(UINT32)0 / sizeof(WCHAR))
            return E_OUTOFMEMORY;
        byte_size *= sizeof(WCHAR);
    }
    if (byte_size && !(encoded = malloc(byte_size)))
        return E_OUTOFMEMORY;
    if (!byte_size)
        encoded = NULL;

    if (impl->unicode_encoding == Utf8)
    {
        if (size && !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, string, length,
                (char *)encoded, byte_size, NULL, NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            free(encoded);
            return hr;
        }
    }
    else
    {
        for (i = 0; i < length; ++i)
        {
            encoded[i * 2] = (BYTE)(string[i] & 0xff);
            encoded[i * 2 + 1] = (BYTE)(string[i] >> 8);
            if (impl->unicode_encoding == Utf16BE)
            {
                BYTE temp = encoded[i * 2];
                encoded[i * 2] = encoded[i * 2 + 1];
                encoded[i * 2 + 1] = temp;
            }
        }
    }

    hr = data_writer_write_bytes(impl, encoded, byte_size);
    free(encoded);
    if (SUCCEEDED(hr))
        *code_unit_count = size;
    return hr;
}

static HRESULT WINAPI data_writer_MeasureString(IDataWriter *iface, HSTRING value, UINT32 *code_unit_count)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);
    TRACE("iface %p, value %s, code_unit_count %p.\n", iface, debugstr_hstring(value), code_unit_count);
    return data_writer_measure_string(impl, value, code_unit_count);
}

static HRESULT data_writer_async_complete(struct data_writer *impl)
{
    impl->storing = FALSE;
    return S_OK;
}

static HRESULT WINAPI data_writer_StoreAsync(IDataWriter *iface, IAsyncOperation_UINT32 **operation)
{
    IAsyncOperationWithProgress_UINT32_UINT32 *inner_operation;
    struct data_writer *impl = impl_from_IDataWriter(iface);
    HRESULT hr;

    TRACE("iface %p, operation %p.\n", iface, operation);

    *operation = NULL;

    if (!impl->stream)
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);

    if (FAILED(hr = IOutputStream_WriteAsync(impl->stream, impl->buffer, &inner_operation)))
        return hr;
    IBuffer_Release(impl->buffer);
    impl->buffer = NULL;
    impl->storing = TRUE;

    hr = async_operation_UINT32_create(impl, inner_operation, operation);
    IAsyncOperationWithProgress_UINT32_UINT32_Release(inner_operation);

    if (SUCCEEDED(hr))
        hr = data_writer_init_buffer(impl, 0);

    return hr;
}

static HRESULT WINAPI data_writer_FlushAsync(IDataWriter *iface, IAsyncOperation_boolean **operation)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);

    FIXME("iface %p, operation %p stub!\n", iface, operation);

    *operation = NULL;

    if (!impl->stream)
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);

    return E_NOTIMPL;
}

static HRESULT WINAPI data_writer_DetachBuffer(IDataWriter *iface, IBuffer **buffer)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);

    TRACE("iface %p, buffer %p.\n", iface, buffer);

    *buffer = impl->buffer;
    impl->buffer = NULL;
    return data_writer_init_buffer(impl, 0);
}

static HRESULT WINAPI data_writer_DetachStream(IDataWriter *iface, IOutputStream **output_stream)
{
    struct data_writer *impl = impl_from_IDataWriter(iface);

    TRACE("iface %p, output_stream %p.\n", iface, output_stream);

    *output_stream = NULL;

    if (impl->storing)
        return HRESULT_FROM_WIN32(ERROR_INVALID_OPERATION);

    *output_stream = impl->stream;
    impl->stream = NULL;
    return S_OK;
}

static const struct IDataWriterVtbl data_writer_vtbl =
{
    /* IUnknown methods */
    data_writer_QueryInterface,
    data_writer_AddRef,
    data_writer_Release,
    /* IInspectable methods */
    data_writer_GetIids,
    data_writer_GetRuntimeClassName,
    data_writer_GetTrustLevel,
    /* IDataWriter */
    data_writer_get_UnstoredBufferLength,
    data_writer_get_UnicodeEncoding,
    data_writer_put_UnicodeEncoding,
    data_writer_get_ByteOrder,
    data_writer_put_ByteOrder,
    data_writer_WriteByte,
    data_writer_WriteBytes,
    data_writer_WriteBuffer,
    data_writer_WriteBufferRange,
    data_writer_WriteBoolean,
    data_writer_WriteGuid,
    data_writer_WriteInt16,
    data_writer_WriteInt32,
    data_writer_WriteInt64,
    data_writer_WriteUInt16,
    data_writer_WriteUInt32,
    data_writer_WriteUInt64,
    data_writer_WriteSingle,
    data_writer_WriteDouble,
    data_writer_WriteDateTime,
    data_writer_WriteTimeSpan,
    data_writer_WriteString,
    data_writer_MeasureString,
    data_writer_StoreAsync,
    data_writer_FlushAsync,
    data_writer_DetachBuffer,
    data_writer_DetachStream,
};

static HRESULT data_writer_create(IOutputStream *output_stream, IDataWriter **out)
{
    struct data_writer *impl;
    HRESULT hr;

    *out = NULL;
    if (!(impl = calloc(1, sizeof(*impl))))
        return E_OUTOFMEMORY;

    impl->IDataWriter_iface.lpVtbl = &data_writer_vtbl;
    impl->stream = output_stream;
    impl->ref = 1;
    impl->unicode_encoding = Utf8;
    impl->byte_order = BigEndian;

    if (FAILED(hr = data_writer_init_buffer(impl, 0)))
    {
        free(impl);
        return hr;
    }

    if (output_stream)
        IOutputStream_AddRef(output_stream);

    *out = &impl->IDataWriter_iface;
    return S_OK;
}

struct data_writer_factory
{
    IActivationFactory IActivationFactory_iface;
    IDataWriterFactory IDataWriterFactory_iface;
    LONG ref;
};

static inline struct data_writer_factory *impl_data_writer_factory_from_IActivationFactory(IActivationFactory *iface)
{
    return CONTAINING_RECORD(iface, struct data_writer_factory, IActivationFactory_iface);
}

static inline struct data_writer_factory *impl_data_writer_factory_from_IDataWriterFactory(IDataWriterFactory *iface)
{
    return CONTAINING_RECORD(iface, struct data_writer_factory, IDataWriterFactory_iface);
}

static HRESULT STDMETHODCALLTYPE data_writer_activation_factory_QueryInterface(IActivationFactory *iface, REFIID iid,
        void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown)
            || IsEqualGUID(iid, &IID_IInspectable)
            || IsEqualGUID(iid, &IID_IAgileObject)
            || IsEqualGUID(iid, &IID_IActivationFactory))
    {
        IUnknown_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    if (IsEqualGUID(iid, &IID_IDataWriterFactory))
    {
        struct data_writer_factory *impl = impl_data_writer_factory_from_IActivationFactory(iface);
        IDataWriterFactory_AddRef(&impl->IDataWriterFactory_iface);
        *out = &impl->IDataWriterFactory_iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE data_writer_activation_factory_AddRef(IActivationFactory *iface)
{
    struct data_writer_factory *impl = impl_data_writer_factory_from_IActivationFactory(iface);
    ULONG ref = InterlockedIncrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE data_writer_activation_factory_Release(IActivationFactory *iface)
{
    struct data_writer_factory *impl = impl_data_writer_factory_from_IActivationFactory(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static HRESULT STDMETHODCALLTYPE data_writer_activation_factory_GetIids(IActivationFactory *iface, ULONG *iid_count,
        IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE data_writer_activation_factory_GetRuntimeClassName(IActivationFactory *iface,
        HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE data_writer_activation_factory_GetTrustLevel(IActivationFactory *iface,
        TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE data_writer_activation_factory_ActivateInstance(IActivationFactory *iface,
        IInspectable **instance)
{
    IDataWriter *data_writer;
    HRESULT hr;

    TRACE("iface %p, instance %p.\n", iface, instance);

    if (FAILED(hr = data_writer_create(NULL, &data_writer)))
        return hr;

    hr = IDataWriter_QueryInterface(data_writer, &IID_IInspectable, (void **)instance);
    IDataWriter_Release(data_writer);

    return hr;
}

static const struct IActivationFactoryVtbl data_writer_activation_factory_vtbl =
{
    data_writer_activation_factory_QueryInterface,
    data_writer_activation_factory_AddRef,
    data_writer_activation_factory_Release,
    /* IInspectable methods */
    data_writer_activation_factory_GetIids,
    data_writer_activation_factory_GetRuntimeClassName,
    data_writer_activation_factory_GetTrustLevel,
    /* IActivationFactory methods */
    data_writer_activation_factory_ActivateInstance,
};

static HRESULT STDMETHODCALLTYPE data_writer_factory_QueryInterface(IDataWriterFactory *iface, REFIID iid, void **out)
{
    TRACE("iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &IID_IUnknown)
            || IsEqualGUID(iid, &IID_IInspectable)
            || IsEqualGUID(iid, &IID_IAgileObject)
            || IsEqualGUID(iid, &IID_IDataWriterFactory))
    {
        IUnknown_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    if (IsEqualGUID(iid, &IID_IActivationFactory))
    {
        struct data_writer_factory *impl = impl_data_writer_factory_from_IDataWriterFactory(iface);
        IActivationFactory_AddRef(&impl->IActivationFactory_iface);
        *out = &impl->IActivationFactory_iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE data_writer_factory_AddRef(IDataWriterFactory *iface)
{
    struct data_writer_factory *impl = impl_data_writer_factory_from_IDataWriterFactory(iface);
    ULONG ref = InterlockedIncrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static ULONG STDMETHODCALLTYPE data_writer_factory_Release(IDataWriterFactory *iface)
{
    struct data_writer_factory *impl = impl_data_writer_factory_from_IDataWriterFactory(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    TRACE("iface %p, ref %lu.\n", iface, ref);
    return ref;
}

static HRESULT STDMETHODCALLTYPE data_writer_factory_GetIids(IDataWriterFactory *iface, ULONG *iid_count,
        IID **iids)
{
    FIXME("iface %p, iid_count %p, iids %p stub!\n", iface, iid_count, iids);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE data_writer_factory_GetRuntimeClassName(IDataWriterFactory *iface,
        HSTRING *class_name)
{
    FIXME("iface %p, class_name %p stub!\n", iface, class_name);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE data_writer_factory_GetTrustLevel(IDataWriterFactory *iface,
        TrustLevel *trust_level)
{
    FIXME("iface %p, trust_level %p stub!\n", iface, trust_level);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE data_writer_factory_CreateDataWriter(IDataWriterFactory *iface,
        IOutputStream *output_stream, IDataWriter **data_writer)
{
    TRACE("iface %p, output_stream %p, data_writer %p.\n", iface, output_stream, data_writer);
    return data_writer_create(output_stream, data_writer);
}

static const struct IDataWriterFactoryVtbl data_writer_factory_vtbl =
{
    data_writer_factory_QueryInterface,
    data_writer_factory_AddRef,
    data_writer_factory_Release,
    /* IInspectable methods */
    data_writer_factory_GetIids,
    data_writer_factory_GetRuntimeClassName,
    data_writer_factory_GetTrustLevel,
    /* IDataWriterFactory methods */
    data_writer_factory_CreateDataWriter,
};

struct data_writer_factory data_writer_factory =
{
    {&data_writer_activation_factory_vtbl},
    {&data_writer_factory_vtbl},
    1
};

IActivationFactory *data_writer_activation_factory = &data_writer_factory.IActivationFactory_iface;
