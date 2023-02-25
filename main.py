
# ------------------------------------------------

import time
import file_system
import rtobject_descriptor
import rtobject_parser

# ------------------------------------------------

def main(
) -> None:
	file_path = 'C:/Users/TwinKleS/Downloads/RtObject.json'
	rtobject_typeinfo_p = rtobject_parser.find_rtobject_typeinfo_address()
	assert rtobject_typeinfo_p != None
	print(f'RtObject : {rtobject_typeinfo_p:x}')
	time_start = time.time()
	result = rtobject_parser.parse_typeinfo(rtobject_typeinfo_p)
	time_end = time.time()
	print(f'耗时 : {time_end - time_start} s')
	file_system.write_file(file_path, '\n'.join(rtobject_descriptor.stringify_class_descriptor(result[1], 0, True)))
	file_system.write_file(file_path, rtobject_descriptor.jsonify_class_descriptor(result))
	print(f'脚本执行完毕，输出 : {file_path}')
	return

# ------------------------------------------------
