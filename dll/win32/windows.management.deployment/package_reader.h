/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     MSIX package identity reader declarations
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#ifndef __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_READER_H
#define __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_READER_H

#include "private.h"

struct package_identity
{
    WCHAR *full_name;
    WCHAR *family_name;
    WCHAR *name;
    WCHAR *publisher;
    WCHAR *version;
    WCHAR *architecture;
    WCHAR *resource_id;
};

HRESULT package_archive_read_identity(PCWSTR path, struct package_identity *identity);
void package_identity_clear(struct package_identity *identity);

#endif
