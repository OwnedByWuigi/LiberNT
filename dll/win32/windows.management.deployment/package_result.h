/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Deployment result declarations
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#ifndef __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_RESULT_H
#define __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_RESULT_H

#include "private.h"

HRESULT deployment_result_create(PCWSTR error_text, HRESULT extended_error, REFGUID activity_id,
                                 IDeploymentResult **result);

#endif
