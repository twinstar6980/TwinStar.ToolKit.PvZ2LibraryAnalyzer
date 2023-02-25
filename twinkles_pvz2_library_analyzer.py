# ------------------------------------------------

import idaapi

# ------------------------------------------------

import sys
sys.path.append('C:/Users/TwinKleS/Documents/Tool/@Reverse/IDA/python/twinkles_pvz2_library_analyzer')

idaapi.require('twinkles_pvz2_library_analyzer')
idaapi.require('twinkles_pvz2_library_analyzer.main')

# ------------------------------------------------

class AnalyzerPlugin(idaapi.plugin_t):

	flags = idaapi.PLUGIN_UNL
	comment = 'analyzer'
	wanted_name = 'TwinKleS PvZ-2 Library Analyzer'
	wanted_hotkey = 'Ctrl-Shift-Z'
	help = 'todo'

	def init(self): 
		idaapi.msg('>>> TwinKleS PvZ-2 Library Analyzer : Loaded\n')
		return idaapi.PLUGIN_OK
	
	def run(self, arg):
		twinkles_pvz2_library_analyzer.main.main()
	
	def term(self):
		idaapi.msg('>>> TwinKleS PvZ-2 Library Analyzer : Finished\n')

def PLUGIN_ENTRY():
	return AnalyzerPlugin()

# ------------------------------------------------
