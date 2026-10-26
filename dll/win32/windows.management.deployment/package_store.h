/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Per-user package repository operations
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#ifndef __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_STORE_H
#define __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_STORE_H

#include "package_reader.h"

HRESULT package_store_register(PCWSTR full_name, PCWSTR root_path);
HRESULT package_store_get_path(PCWSTR full_name, WCHAR **root_path);
HRESULT package_store_unregister(PCWSTR full_name, PCWSTR expected_path);

#endif
