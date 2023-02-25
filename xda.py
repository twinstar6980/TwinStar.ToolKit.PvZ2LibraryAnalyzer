''' xda '''

# ------------------------------------------------

from typing import Optional

import idc
import idautils
import ida_bytes
import ida_ua

# ------------------------------------------------

o_void   = ida_ua.o_void
o_reg    = ida_ua.o_reg
o_mem    = ida_ua.o_mem
o_phrase = ida_ua.o_phrase
o_displ  = ida_ua.o_displ
o_imm    = ida_ua.o_imm
o_far    = ida_ua.o_far
o_near   = ida_ua.o_near

# ------------------------------------------------

def byte(
	address: int,
) -> int:
	'''
	读取字节值
	* address 地址
	* return 值
	'''
	return ida_bytes.get_byte(address)

def dword(
	address: int,
) -> int:
	'''
	读取双字值
	* address 地址
	* return 值
	'''
	return ida_bytes.get_dword(address)

def string(
	address: int,
) -> str:
	'''
	读取空终止字符串
	* address 地址
	* return 值
	'''
	result = ''
	p = address
	while True:
		value = byte(p)
		if value == 0:
			break
		result += chr(value)
		p += 1
	return result

# ------------------------------------------------

def mnem(
	address: int,
) -> Optional[str]:
	'''
	解析助记符
	* address 地址
	* return 助记符
	'''
	return ida_ua.ua_mnem(address)

def insn(
	address: int,
) -> Optional[ida_ua.insn_t]:
	'''
	解析指令
	* address 地址
	* return 指令
	'''
	result = ida_ua.insn_t()
	result_length = ida_ua.decode_insn(result, address)
	if result_length == 0:
		return None
	return result

# ------------------------------------------------

def name(
	address: int,
) -> str:
	'''
	解析名称
	* address 地址
	* return 名称
	'''
	return idc.get_name(address, idc.GN_DEMANGLED | idc.GN_STRICT | idc.GN_LONG)

def address_of_name(
	name: str,
) -> Optional[int]:
	'''
	获取指定名称的地址
	* name 名称
	* return 地址，如果未找到则为None
	'''
	result = idc.get_name_ea_simple(name)
	return None if result == 0xFFFFFFFF else result

def xref_to(
	address: int,
) -> list:
	'''
	获取对指定地址的引用
	* address 地址
	* return 引用表
	'''
	return idautils.XrefsTo(address)

# ------------------------------------------------
