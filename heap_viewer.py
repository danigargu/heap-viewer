#!/usr/bin/python
# coding: utf-8
#
# HeapViewer - by @danigargu
#

import idaapi

PLUGIN_DIR = idaapi.idadir(os.path.join("plugins", "heap_viewer"))
sys.path.append(PLUGIN_DIR)

# ----- Only for develop / reload modules -------------------------------

idaapi.require('ptmalloc')
idaapi.require('plugin_gui')
idaapi.require('tracer')
idaapi.require('misc')
idaapi.require('bingraph')

#------------------------------------------------------------------------

from plugin_gui import HeapPluginForm

#------------------------------------------------------------------------
__version__  = "0.1"
__plugname__ = "HeapViewer"

# -----------------------------------------------------------------------
class HeapViewPlugin(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = __plugname__
    wanted_hotkey = "Ctrl-H"

    def init(self):
        self.icon_id = 0
        return PLUGIN_KEEP

    def run(self, arg=0):
        try:
            if "ELF" not in get_file_type_name():
                raise Exception("Executable must be ELF format")

            if not is_debugger_on() or not idaapi.dbg_can_query():
                raise Exception("The debugger must be active and suspended before using this plugin")

            f = HeapPluginForm()
            f.Show()

        except Exception as e:
            idaapi.warning("[%s] %s" % (__plugname__, e.message))

    def term(self):
        idaapi.msg("[%s] terminated" % (__plugname__))

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return HeapViewPlugin()


