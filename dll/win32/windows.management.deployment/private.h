/*
 * PROJECT:     LiberNT Windows Runtime
 * LICENSE:     GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
 * PURPOSE:     Package deployment runtime declarations
 * COPYRIGHT:   Copyright 2026 LiberNT contributors
 */

#ifndef __WINDOWS_MANAGEMENT_DEPLOYMENT_PRIVATE_H
#define __WINDOWS_MANAGEMENT_DEPLOYMENT_PRIVATE_H

#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>

#define COBJMACROS
#include <windef.h>
#include <winbase.h>
#include <winstring.h>
#include <objbase.h>
#include <roapi.h>

#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Collections
#include <windows.foundation.h>
#define WIDL_using_Windows_ApplicationModel
#include <windows.applicationmodel.h>
#define WIDL_using_Windows_Management_Deployment
#include <windows.management.deployment.h>

HRESULT get_iids(REFIID iid, ULONG *count, IID **iids);
HRESULT trust_level(TrustLevel *level);
HRESULT package_manager_create(IInspectable **instance);
HRESULT deployment_operation_add_package(IUriRuntimeClass *uri, IIterable_Uri *dependencies,
                                         DeploymentOptions options,
                                         IAsyncOperationWithProgress_DeploymentResult_DeploymentProgress **operation);

#endif
