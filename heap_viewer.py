#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idaapi
import os
import sys

PLUGIN_DIR = idaapi.idadir(os.path.join("plugins", "heap_viewer"))
sys.path.append(PLUGIN_DIR)
idaapi.require('plugin_gui')

from plugin_gui import HeapPluginForm, PLUGNAME

# -----------------------------------------------------------------------
class StartHandler(idaapi.action_handler_t):
    def __init__(self):
        super(StartHandler, self).__init__()
        
    def activate(self, ctx):
        p = HeapViewPlugin()
        p.run()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------
class HeapViewPlugin(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = PLUGNAME
    wanted_hotkey = "Ctrl-H"

    def init(self):
        self.icon_id = 0
        self.add_menus()
        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        try:
            if "ELF" not in idaapi.get_file_type_name():
                raise Exception("Executable must be ELF fomat")

            if not idaapi.is_debugger_on() or not idaapi.dbg_can_query():
                raise Exception("The debugger must be active and suspended before using this plugin")

            f = HeapPluginForm()
            f.Show()

        except Exception as e:
            idaapi.warning("[%s] %s" % (PLUGNAME, e.message))

    def add_menus(self):
        act_name = '%s:start' % PLUGNAME
        act_desc = idaapi.action_desc_t(
            act_name,       # The action name. Must be unique
            PLUGNAME,       # Action Text
            StartHandler(), # Action handler
            None,           # Optional shortcut
            'Start plugin', # Action tooltip
            122             # Icon
        )
        idaapi.register_action(act_desc)
        idaapi.attach_action_to_menu(
            'Debugger/Debugger windows/',
            act_name,
            idaapi.SETMENU_APP
        )

    def term(self):
        idaapi.msg("[%s] terminated" % (PLUGNAME))

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return HeapViewPlugin()


