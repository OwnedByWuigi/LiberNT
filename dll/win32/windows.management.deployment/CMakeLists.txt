spec2def(windows.management.deployment.dll windows.management.deployment.spec)

list(APPEND SOURCE
    main.c
    package_reader.c
    package_manager.c
    private.h)

add_library(windows_management_deployment MODULE
    ${SOURCE}
    ${CMAKE_CURRENT_BINARY_DIR}/windows.management.deployment.def
    ${CMAKE_CURRENT_BINARY_DIR}/windows.management.deployment_stubs.c)
set_target_properties(windows_management_deployment PROPERTIES OUTPUT_NAME "windows.management.deployment")
target_include_directories(windows_management_deployment PRIVATE
    ${REACTOS_SOURCE_DIR}/sdk/include/reactos/libs/zlib
    ${REACTOS_SOURCE_DIR}/sdk/lib/3rdparty/zlib/contrib)
add_idl_reg_scripts(windows_management_deployment winrt classes.idl)
set_module_type(windows_management_deployment win32dll)
target_compile_definitions(windows_management_deployment PRIVATE __WINESRC__)
target_link_libraries(windows_management_deployment minizip zlib uuid wine wine_dll_canunload wine_dll_register)
add_importlibs(windows_management_deployment xmllite combase ole32 kernelbase msvcrt kernel32 ntdll)
add_dependencies(windows_management_deployment psdk)
add_cd_file(TARGET windows_management_deployment DESTINATION reactos/system32 FOR all)
set_wine_module_FIXME(windows_management_deployment)
