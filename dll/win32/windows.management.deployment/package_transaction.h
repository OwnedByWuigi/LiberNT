/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Package staging and registration transaction declarations
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#ifndef __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_TRANSACTION_H
#define __WINDOWS_MANAGEMENT_DEPLOYMENT_PACKAGE_TRANSACTION_H

#include "package_store.h"

HRESULT package_transaction_add(IUriRuntimeClass *uri, IIterable_Uri *dependencies, DeploymentOptions options,
                                package_is_cancelled_callback is_cancelled, void *context);

#endif
