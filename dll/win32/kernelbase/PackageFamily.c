/*
 * PROJECT:     LiberNT KernelBase
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Package-family enumeration compatibility
 * COPYRIGHT:   Copyright 2026 Ahmed Arif <arif.ing@outlook.com>
 */

#include <windows.h>
#include <appmodel.h>
#include <bcrypt.h>
#include <strsafe.h>
#include <wchar.h>
#include <winternl.h>

static BOOL
IsPackageNameCharacter(
    _In_ WCHAR Character)
{
    return (Character >= L'0' && Character <= L'9') ||
           (Character >= L'A' && Character <= L'Z') ||
           (Character >= L'a' && Character <= L'z') ||
           Character == L'.' || Character == L'-';
}

static BOOL
IsPublisherIdCharacter(
    _In_ WCHAR Character)
{
    static const WCHAR PublisherIdAlphabet[] = L"0123456789abcdefghjkmnpqrstvwxyz";
    const WCHAR *Current;

    for (Current = PublisherIdAlphabet; *Current; Current++)
    {
        if (*Current == Character || towupper(*Current) == Character)
            return TRUE;
    }

    return FALSE;
}

static BOOL
IsPackageString(
    _In_reads_(Length) PCWSTR String,
    _In_ SIZE_T Length,
    _In_ SIZE_T MaximumLength)
{
    SIZE_T Index;

    if (!Length || Length > MaximumLength)
        return FALSE;

    for (Index = 0; Index < Length; Index++)
    {
        if (!IsPackageNameCharacter(String[Index]))
            return FALSE;
    }

    return TRUE;
}

static LONG
BasepGetPublisherId(
    _In_ PCWSTR Publisher,
    _Out_writes_(14) PWSTR PublisherId)
{
    static const WCHAR Alphabet[] = L"0123456789abcdefghjkmnpqrstvwxyz";
    BCRYPT_ALG_HANDLE Algorithm = NULL;
    UCHAR Digest[32];
    SIZE_T PublisherLength;
    ULONG Index, Bit;
    NTSTATUS Status;

    if (!Publisher || (PublisherLength = wcslen(Publisher)) < PACKAGE_PUBLISHER_MIN_LENGTH ||
        PublisherLength > PACKAGE_PUBLISHER_MAX_LENGTH)
        return ERROR_INVALID_PARAMETER;

    Status = BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (Status < 0)
        return RtlNtStatusToDosError(Status);

    Status = BCryptHash(Algorithm, NULL, 0, (PUCHAR)Publisher,
                        (ULONG)(PublisherLength * sizeof(WCHAR)), Digest, sizeof(Digest));
    BCryptCloseAlgorithmProvider(Algorithm, 0);
    if (Status < 0)
        return RtlNtStatusToDosError(Status);

    for (Index = 0; Index < 13; Index++)
    {
        UCHAR Value = 0;

        for (Bit = 0; Bit < 5; Bit++)
        {
            ULONG BitIndex = Index * 5 + Bit;
            Value = (Value << 1) | ((Digest[BitIndex / 8] >> (7 - BitIndex % 8)) & 1);
        }
        PublisherId[Index] = Alphabet[Value];
    }
    PublisherId[13] = UNICODE_NULL;
    SecureZeroMemory(Digest, sizeof(Digest));
    return ERROR_SUCCESS;
}

static LONG
BasepGetPackagePublisherId(
    _In_ const PACKAGE_ID *PackageId,
    _Out_writes_(14) PWSTR PublisherId)
{
    SIZE_T Length;
    SIZE_T Index;

    if (PackageId->publisherId)
    {
        Length = wcslen(PackageId->publisherId);
        if (Length != 13)
            return ERROR_INVALID_PARAMETER;
        for (Index = 0; Index < Length; Index++)
        {
            if (!IsPublisherIdCharacter(PackageId->publisherId[Index]))
                return ERROR_INVALID_PARAMETER;
            PublisherId[Index] = PackageId->publisherId[Index];
        }
        PublisherId[13] = UNICODE_NULL;
        return ERROR_SUCCESS;
    }

    return BasepGetPublisherId(PackageId->publisher, PublisherId);
}

LONG
WINAPI
PackageFamilyNameFromId(
    _In_ const PACKAGE_ID *PackageId,
    _Inout_ UINT32 *PackageFamilyNameLength,
    _Out_writes_opt_(*PackageFamilyNameLength) PWSTR PackageFamilyName)
{
    WCHAR PublisherId[14];
    WCHAR FamilyName[65 + 1 + 13 + 1];
    SIZE_T NameLength;
    UINT32 RequiredLength;
    LONG Error;

    if (!PackageId || !PackageId->name || !PackageFamilyNameLength ||
        (!PackageFamilyName && *PackageFamilyNameLength))
    {
        return ERROR_INVALID_PARAMETER;
    }

    NameLength = wcslen(PackageId->name);
    if (NameLength < PACKAGE_NAME_MIN_LENGTH || !IsPackageString(PackageId->name, NameLength, PACKAGE_NAME_MAX_LENGTH))
        return ERROR_INVALID_PARAMETER;
    if ((Error = BasepGetPackagePublisherId(PackageId, PublisherId)) != ERROR_SUCCESS)
        return Error;

    if (FAILED(StringCchCopyW(FamilyName, ARRAYSIZE(FamilyName), PackageId->name)) ||
        FAILED(StringCchCatW(FamilyName, ARRAYSIZE(FamilyName), L"_")) ||
        FAILED(StringCchCatW(FamilyName, ARRAYSIZE(FamilyName), PublisherId)))
    {
        return ERROR_INVALID_PARAMETER;
    }

    RequiredLength = (UINT32)wcslen(FamilyName) + 1;
    if (!PackageFamilyName || *PackageFamilyNameLength < RequiredLength)
    {
        *PackageFamilyNameLength = RequiredLength;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    CopyMemory(PackageFamilyName, FamilyName, RequiredLength * sizeof(WCHAR));
    *PackageFamilyNameLength = RequiredLength;
    return ERROR_SUCCESS;
}

LONG
WINAPI
PackageFullNameFromId(
    _In_ const PACKAGE_ID *PackageId,
    _Inout_ UINT32 *PackageFullNameLength,
    _Out_writes_opt_(*PackageFullNameLength) PWSTR PackageFullName)
{
    static const struct
    {
        UINT32 Architecture;
        PCWSTR Name;
    } Architectures[] =
    {
        { PROCESSOR_ARCHITECTURE_INTEL, L"x86" },
        { PROCESSOR_ARCHITECTURE_ARM, L"arm" },
        { PROCESSOR_ARCHITECTURE_AMD64, L"x64" },
        { PROCESSOR_ARCHITECTURE_NEUTRAL, L"neutral" },
        { PROCESSOR_ARCHITECTURE_ARM64, L"arm64" },
        { PROCESSOR_ARCHITECTURE_IA32_ON_ARM64, L"x86a64" },
        { PROCESSOR_ARCHITECTURE_UNKNOWN, L"unknown" },
    };
    WCHAR PublisherId[14];
    WCHAR FullName[PACKAGE_FULL_NAME_MAX_LENGTH + 1];
    PCWSTR Architecture = NULL;
    SIZE_T NameLength, ResourceIdLength;
    UINT32 RequiredLength;
    ULONG Index;
    LONG Error;

    if (!PackageId || !PackageId->name || !PackageFullNameLength ||
        (!PackageFullName && *PackageFullNameLength))
    {
        return ERROR_INVALID_PARAMETER;
    }

    NameLength = wcslen(PackageId->name);
    ResourceIdLength = PackageId->resourceId ? wcslen(PackageId->resourceId) : 0;
    if (NameLength < PACKAGE_NAME_MIN_LENGTH ||
        !IsPackageString(PackageId->name, NameLength, PACKAGE_NAME_MAX_LENGTH) ||
        (ResourceIdLength && !IsPackageString(PackageId->resourceId, ResourceIdLength, PACKAGE_RESOURCEID_MAX_LENGTH)))
    {
        return ERROR_INVALID_PARAMETER;
    }

    for (Index = 0; Index < ARRAYSIZE(Architectures); Index++)
    {
        if (PackageId->processorArchitecture == Architectures[Index].Architecture)
        {
            Architecture = Architectures[Index].Name;
            break;
        }
    }
    if (!Architecture)
        return ERROR_INVALID_PARAMETER;

    if ((Error = BasepGetPackagePublisherId(PackageId, PublisherId)) != ERROR_SUCCESS)
        return Error;

    if (FAILED(StringCchPrintfW(FullName, ARRAYSIZE(FullName), L"%ls_%u.%u.%u.%u_%ls_%ls_%ls",
                                PackageId->name,
                                PackageId->version.Major,
                                PackageId->version.Minor,
                                PackageId->version.Build,
                                PackageId->version.Revision,
                                Architecture,
                                PackageId->resourceId ? PackageId->resourceId : L"",
                                PublisherId)))
    {
        return ERROR_INVALID_PARAMETER;
    }

    RequiredLength = (UINT32)wcslen(FullName) + 1;
    if (!PackageFullName || *PackageFullNameLength < RequiredLength)
    {
        *PackageFullNameLength = RequiredLength;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    CopyMemory(PackageFullName, FullName, RequiredLength * sizeof(WCHAR));
    *PackageFullNameLength = RequiredLength;
    return ERROR_SUCCESS;
}

BOOL
BasepIsPackageFamilyName(
    _In_ PCWSTR PackageFamilyName)
{
    const WCHAR *Current;
    const WCHAR *Separator = NULL;
    SIZE_T NameLength;
    SIZE_T PublisherIdLength;

    for (Current = PackageFamilyName; *Current; Current++)
    {
        if (*Current == L'_')
        {
            if (Separator)
                return FALSE;
            Separator = Current;
        }
        else if (!Separator && !IsPackageNameCharacter(*Current))
        {
            return FALSE;
        }
        else if (Separator && !IsPublisherIdCharacter(*Current))
        {
            return FALSE;
        }
    }

    if (!Separator)
        return FALSE;

    NameLength = Separator - PackageFamilyName;
    PublisherIdLength = Current - Separator - 1;
    if (NameLength < 3 || NameLength > 50 || PublisherIdLength != 13)
        return FALSE;

    return Separator[-1] != L'.';
}

LONG
WINAPI
FindPackagesByPackageFamily(
    _In_ PCWSTR PackageFamilyName,
    _In_ UINT32 PackageFilters,
    _Inout_ UINT32 *Count,
    _Out_writes_opt_(*Count) PWSTR *PackageFullNames,
    _Inout_ UINT32 *BufferLength,
    _Out_writes_opt_(*BufferLength) WCHAR *Buffer,
    _Out_writes_opt_(*Count) UINT32 *PackageProperties)
{
    UNREFERENCED_PARAMETER(PackageFilters);
    UNREFERENCED_PARAMETER(PackageProperties);

    if (!PackageFamilyName || !Count || !BufferLength ||
        (!PackageFullNames && *Count) || (!Buffer && *BufferLength) ||
        !BasepIsPackageFamilyName(PackageFamilyName))
    {
        return ERROR_INVALID_PARAMETER;
    }

    *Count = 0;
    *BufferLength = 0;
    return ERROR_SUCCESS;
}

static BOOL
IsValidPackageVersion(
    _In_reads_(Length) PCWSTR Version,
    _In_ SIZE_T Length)
{
    SIZE_T Index, Digits = 0;
    ULONG Parts = 1, Value = 0;

    for (Index = 0; Index < Length; Index++)
    {
        if (Version[Index] == L'.')
        {
            if (!Digits || ++Parts > 4)
                return FALSE;
            Digits = 0;
            Value = 0;
        }
        else if (Version[Index] >= L'0' && Version[Index] <= L'9')
        {
            Value = Value * 10 + (Version[Index] - L'0');
            if (++Digits > 5 || Value > 0xFFFF)
                return FALSE;
        }
        else
        {
            return FALSE;
        }
    }

    return Parts == 4 && Digits;
}

static BOOL
IsValidPackageArchitecture(
    _In_reads_(Length) PCWSTR Architecture,
    _In_ SIZE_T Length)
{
    static const PCWSTR Architectures[] = { L"x86", L"x64", L"arm", L"arm64", L"neutral", L"x86a64", L"unknown" };
    ULONG Index;

    for (Index = 0; Index < ARRAYSIZE(Architectures); Index++)
    {
        if (lstrlenW(Architectures[Index]) == (int)Length &&
            CompareStringOrdinal(Architecture, (int)Length, Architectures[Index], (int)Length, TRUE) == CSTR_EQUAL)
        {
            return TRUE;
        }
    }

    return FALSE;
}

LONG
WINAPI
PackageFamilyNameFromFullName(
    _In_ PCWSTR packageFullName,
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName)
{
    PCWSTR Fields[5], Current;
    WCHAR Family[64 + 1 + 13 + 1];
    SIZE_T Lengths[5], NameLength;
    ULONG Count = 0;

    if (!packageFullName || !packageFamilyNameLength || (!packageFamilyName && *packageFamilyNameLength))
        return ERROR_INVALID_PARAMETER;

    Fields[0] = packageFullName;
    for (Current = packageFullName; ; Current++)
    {
        if (*Current == L'_' || !*Current)
        {
            if (Count >= ARRAYSIZE(Fields))
                return ERROR_INVALID_PARAMETER;
            Lengths[Count] = Current - Fields[Count];
            Count++;
            if (!*Current)
                break;
            if (Count < ARRAYSIZE(Fields))
                Fields[Count] = Current + 1;
        }
    }

    if (Count != ARRAYSIZE(Fields) ||
        !IsValidPackageVersion(Fields[1], Lengths[1]) ||
        !IsValidPackageArchitecture(Fields[2], Lengths[2]))
    {
        return ERROR_INVALID_PARAMETER;
    }

    NameLength = Lengths[0];
    if (NameLength + 1 + Lengths[4] + 1 > ARRAYSIZE(Family))
        return ERROR_INVALID_PARAMETER;

    CopyMemory(Family, Fields[0], NameLength * sizeof(WCHAR));
    Family[NameLength] = L'_';
    CopyMemory(Family + NameLength + 1, Fields[4], Lengths[4] * sizeof(WCHAR));
    Family[NameLength + 1 + Lengths[4]] = UNICODE_NULL;

    if (!BasepIsPackageFamilyName(Family))
        return ERROR_INVALID_PARAMETER;

    if (!packageFamilyName || *packageFamilyNameLength < (UINT32)lstrlenW(Family) + 1)
    {
        *packageFamilyNameLength = lstrlenW(Family) + 1;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    *packageFamilyNameLength = lstrlenW(Family) + 1;
    CopyMemory(packageFamilyName, Family, *packageFamilyNameLength * sizeof(WCHAR));
    return ERROR_SUCCESS;
}

LONG
WINAPI
ParseApplicationUserModelId(
    _In_ PCWSTR applicationUserModelId,
    _Inout_ UINT32 *packageFamilyNameLength,
    _Out_writes_opt_(*packageFamilyNameLength) PWSTR packageFamilyName,
    _Inout_ UINT32 *packageRelativeApplicationIdLength,
    _Out_writes_opt_(*packageRelativeApplicationIdLength) PWSTR packageRelativeApplicationId)
{
    WCHAR Family[64 + 1 + 13 + 1];
    PCWSTR Separator;
    SIZE_T FamilyLength;
    UINT32 FamilyRequired, ApplicationRequired;

    if (!applicationUserModelId || !packageFamilyNameLength || !packageRelativeApplicationIdLength ||
        (!packageFamilyName && *packageFamilyNameLength) ||
        (!packageRelativeApplicationId && *packageRelativeApplicationIdLength))
    {
        return ERROR_INVALID_PARAMETER;
    }

    Separator = wcschr(applicationUserModelId, L'!');
    if (!Separator || !Separator[1])
        return ERROR_INVALID_PARAMETER;

    FamilyLength = Separator - applicationUserModelId;
    if (FamilyLength >= ARRAYSIZE(Family))
        return ERROR_INVALID_PARAMETER;
    CopyMemory(Family, applicationUserModelId, FamilyLength * sizeof(WCHAR));
    Family[FamilyLength] = UNICODE_NULL;
    if (!BasepIsPackageFamilyName(Family))
        return ERROR_INVALID_PARAMETER;

    FamilyRequired = (UINT32)FamilyLength + 1;
    ApplicationRequired = (UINT32)lstrlenW(Separator + 1) + 1;

    if (!packageFamilyName || *packageFamilyNameLength < FamilyRequired ||
        !packageRelativeApplicationId || *packageRelativeApplicationIdLength < ApplicationRequired)
    {
        *packageFamilyNameLength = FamilyRequired;
        *packageRelativeApplicationIdLength = ApplicationRequired;
        return ERROR_INSUFFICIENT_BUFFER;
    }

    CopyMemory(packageFamilyName, Family, FamilyRequired * sizeof(WCHAR));
    CopyMemory(packageRelativeApplicationId, Separator + 1, ApplicationRequired * sizeof(WCHAR));
    *packageFamilyNameLength = FamilyRequired;
    *packageRelativeApplicationIdLength = ApplicationRequired;
    return ERROR_SUCCESS;
}

HRESULT
WINAPI
AddDependencyToProcessPackageGraph(
    _In_ PCWSTR PackageFamilyName,
    _In_opt_ PVOID Reserved1,
    _In_opt_ PVOID Reserved2,
    _In_opt_ PVOID Reserved3)
{
    UNREFERENCED_PARAMETER(PackageFamilyName);
    UNREFERENCED_PARAMETER(Reserved1);
    UNREFERENCED_PARAMETER(Reserved2);
    UNREFERENCED_PARAMETER(Reserved3);

    return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
}

HRESULT
WINAPI
AppXGetPackageSid(
    _In_ PCWSTR PackageFullName,
    _Out_ PSID *PackageSid)
{
    UNREFERENCED_PARAMETER(PackageFullName);
    UNREFERENCED_PARAMETER(PackageSid);

    return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}

VOID
WINAPI
AppXFreeMemory(
    _In_opt_ PVOID Memory)
{
    if (Memory)
        HeapFree(GetProcessHeap(), 0, Memory);
}

HMODULE
WINAPI
LoadPackagedLibrary(
    _In_ LPCWSTR lpwLibFileName,
    _Reserved_ DWORD Reserved)
{
    UNREFERENCED_PARAMETER(lpwLibFileName);
    UNREFERENCED_PARAMETER(Reserved);

    SetLastError(APPMODEL_ERROR_NO_PACKAGE);
    return NULL;
}
