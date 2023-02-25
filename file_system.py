''' file system '''

# ------------------------------------------------

def write_file(
	path: str,
	content: str,
) -> None:
	'''
	将字符串写入文件
	* path 文件路径
	* content 文件内容
	* return 无
	'''
	with open(path, mode='w', encoding='utf-8') as file:
		file.write(content)
	return

# ------------------------------------------------
