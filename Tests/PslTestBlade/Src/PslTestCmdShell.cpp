/** 
 * *****************************************************************************
 * @file HllTestCmdShell.cpp
 * @ingroup psl_test
 * 
 * @brief  Command-shell utilities for our test blade.
 * 
 * *****************************************************************************
 */


#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <string>


#include <PmWsfTestUtils/CommandShell.h>

#include "PslTestCmdShell.h"



namespace psl_test_blade {


/** 
 */
void RegisterCmdHandler(const MyCmdShellHost::CmdRegInfo& rInfo)
{
    PeekHandlerTable().push_back(rInfo);
}

/**
 */
HandlerTableType& PeekHandlerTable()
{
    static HandlerTableType    handlerTable;

    return handlerTable;
}


static std::string g_bladeName;

void SaveBladeName(const char name[])
{
    g_bladeName = name;
}

const char* PeekBladeName()
{
    return g_bladeName.c_str();
}




} // end of namespace psl_test_blade
