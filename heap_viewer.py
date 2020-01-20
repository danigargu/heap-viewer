#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import os
import sys
import idaapi

from heap_viewer import PLUGNAME, plugin_gui
from heap_viewer.misc import is_process_suspended, log

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

            if not idaapi.is_debugger_on() or not is_process_suspended():
                raise Exception("The debugger must be active and suspended before using this plugin")

            f = plugin_gui.HeapPluginForm()
            f.Show()

        except Exception as e:
            idaapi.warning("[%s] %s" % (PLUGNAME, str(e)))

    def add_menus(self):
        # To avoid creating multiple plugin_t instances
        this = self
        class StartHandler(idaapi.action_handler_t):
            def __init__(self):
                idaapi.action_handler_t.__init__(self)
                
            def activate(self, ctx):
                this.run()
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS

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

# -----------------------------------------------------------------------
log("Plugin loaded")
