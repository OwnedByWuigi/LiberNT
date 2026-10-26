#define STANDALONE
#include <wine/test.h>

extern void func_package_manager(void);

const struct test winetest_testlist[] =
{
    { "package_manager", func_package_manager },
    { 0, 0 }
};
