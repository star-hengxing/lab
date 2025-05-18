#include <pedeps.h>

#include <xmi.h>

static int get_exports(lua_State* lua)
{
    const char* input_file = lua_tostring(lua, 1);

    int status = 0;
    pefile_handle pehandle = pefile_create();
    // if (!pehandle)
    // {
    //     lua_pushstring(lua, "Failed to create PE file handle");
    //     return 1;
    // }
    status = pefile_open_file(pehandle, input_file);
    // if (status != 0)
    // {

    // }
    struct lua_table
    {
        lua_State* lua;
        int i;

        void push_string(const char* name, uint16_t ordinal)
        {
            lua_createtable(lua, 0, 2);

            lua_pushstring(lua, "name");
            lua_pushstring(lua, name);
            lua_settable(lua, -3);

            lua_pushstring(lua, "ordinal");
            lua_pushinteger(lua, ordinal);
            lua_settable(lua, -3);

            lua_rawseti(lua, -2, i);
            i += 1;
        }
    } table {lua, 1};

    lua_newtable(lua);
    status = pefile_list_exports(pehandle, [](
            const char* modulename,
            const char* functionname,
            uint16_t ordinal,
            int isdata,
            char* functionforwardername,
            void* callbackdata
        ) -> int {
            reinterpret_cast<lua_table*>(callbackdata)->push_string(functionname, ordinal);
            return 0;
    }, &table);

    pefile_close(pehandle);
    return 1;
}

int luaopen(pe, lua_State* lua)
{
    static const luaL_Reg funcs[]
    {
        {"get_exports", get_exports},
        {nullptr, nullptr},
    };

    lua_newtable(lua);
    luaL_setfuncs(lua, funcs, 0);
    return 1;
}
