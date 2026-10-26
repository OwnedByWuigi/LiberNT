/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     MSIX package signature verification declarations
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#ifndef __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_TRUST_H
#define __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_TRUST_H

#include "package_reader.h"

HRESULT package_archive_verify_signature(PCWSTR path, const struct package_identity *identity);

#endif
