''' RtObject Parser '''

# ------------------------------------------------

from enum import Enum
from typing import Optional, Union
from dataclasses import dataclass
from rtobject_descriptor import ClassMemberCategory, ClassMemberDescriptor, ClassDescriptor, SimpleClassDescriptor
import xda

# ------------------------------------------------

r_fp = 11
'''FP寄存器'''
r_sp = 13
'''SP寄存器'''
r_pc = 15
'''PC寄存器'''

# ------------------------------------------------

def is_typeinfo_name(
	name: str,
) -> bool:
	'''
	判断一个名称是否为typeinfo名称
	* name 名称
	* return 判断结果
	'''
	return name.startswith("`typeinfo for'")

def get_typeinfo_type(
	name: str,
) -> str:
	'''
	截取typeinfo名称的类名
	* name 名称
	* return 截取结果
	'''
	return name.replace("`typeinfo for'", "")

def is_vtable_name(
	name: str,
) -> bool:
	'''
	判断一个名称是否为vtable名称
	* name 名称
	* return 判断结果
	'''
	return name.startswith("`vtable for'")

def get_vtable_type(
	name: str,
) -> str:
	'''
	截取vtable名称的类名
	* name 名称
	* return 截取结果
	'''
	return name.replace("`vtable for'", "")

# ------------------------------------------------

def parse_simple_type_signature(
	flag_1: int,
	flag_2: int,
) -> str:
	'''
	获取由两个整数标志指定的简单类型名称
	* flag_1 标志1，指定了主类型
	* flag_2 标志2，指定了附类型
	* return 两个标志所指定的类型名称
	'''
	if flag_1 == 1:
		# 未知
		pass
	elif flag_1 == 2:
		# 未知，出现于函数返回类型 TODO
		return '*'
	elif flag_1 == 3:
		# 逻辑值
		if flag_2 == 1:
			return 'bool'
	elif flag_1 == 4:
		# 字符串
		if flag_2 == 1:
			return 'std::string'
	elif flag_1 == 5:
		# 宽字符串
		if flag_2 == 1:
			return 'std::wstring'
	elif flag_1 == 6:
		# 有符号整数
		if flag_2 == 1:
			return 'int8'
		if flag_2 == 2:
			return 'int16'
		if flag_2 == 4:
			return 'int32'
		if flag_2 == 8:
			return 'int64'
	elif flag_1 == 7:
		# 无符号整数
		if flag_2 == 1:
			return 'uint8'
		if flag_2 == 2:
			return 'uint16'
		if flag_2 == 4:
			return 'uint32'
		if flag_2 == 8:
			return 'uint64'
	elif flag_1 == 8:
		# 浮点数
		if flag_2 == 4:
			return 'float'
		if flag_2 == 8:
			return 'double'
	assert False

# ------------------------------------------------

@dataclass
class ImmediateValue:
	'''立即数'''
	value: int
	'''立即数值'''

@dataclass
class VariableValue:
	'''栈内变量'''
	offset: int
	'''偏移量'''
	relative_stack_tail: bool
	'''是否相对于栈底偏移'''

RegisterValue = Union[ImmediateValue, VariableValue]
'''寄存器值变体'''

def analysis_reg_value(
	reg: int,
	used_address: int,
) -> RegisterValue:
	'''
	简单分析指定寄存器的值。
	* reg 寄存器编号
	* used_address 最后使用该寄存器的指令地址
	* return 寄存器的值
	'''
	assert reg not in [ r_pc, r_sp, r_fp ]
	result = None
	for p in range(used_address - 4, 0, -4):
		mnem = xda.mnem(p)
		if mnem in [ 'MOV', 'MOVB', 'MOVW', 'MOVT' ]:
			# MOV Rd, Rm -> Rd = Rm
			# MOV Rd, #m -> Rd = #m -> ImmediateValue
			# MOV Rd, SP/FP -> Rd = SP+0/FP-0 -> VariableValue
			insn = xda.insn(p)
			if insn.ops[0].reg != reg:
				continue
			if insn.ops[1].type == xda.o_imm:
				if mnem == 'MOVT':
					r_low = analysis_reg_value(reg, p)
					assert isinstance(r_low, ImmediateValue)
					result = ImmediateValue(insn.ops[1].value << 16 | r_low.value)
				else:
					result = ImmediateValue(insn.ops[1].value)
			elif insn.ops[1].type == xda.o_reg:
				if insn.ops[1].reg == r_sp:
					result = VariableValue(0x0, False)
				elif insn.ops[1].reg == r_fp:
					result = VariableValue(0x0, True)
				else:
					result = analysis_reg_value(insn.ops[1].reg, p)
			else:
				assert None
			break
		if mnem in [ 'ADD', 'ADDS', 'ADC' ]:
			# ADD Rd, Rn, Rm/#m -> Rd = Rn + Rm/#m -> ImmediateValue
			# ADD Rd, PC, Rm -> Rd = PC + Rm -> ImmediateValue
			# ADD Rd, SP, #m -> Rd = SP + #m -> VariableValue
			# ADDS/ADC 在9.6的lib中只出现了一次，且无进位发生，故暂时不做进位处理 TODO
			insn = xda.insn(p)
			if insn.ops[0].reg != reg:
				continue
			if insn.ops[1].reg == r_pc:
				assert mnem == 'ADD'
				assert insn.ops[2].type == xda.o_reg
				rm = analysis_reg_value(insn.ops[2].reg, p)
				assert isinstance(rm, ImmediateValue)
				result = ImmediateValue(p + 8 + rm.value)
			elif insn.ops[1].reg == r_sp:
				assert mnem == 'ADD'
				assert insn.ops[2].type == xda.o_imm
				result = VariableValue(insn.ops[2].value, False)
			else:
				rn = analysis_reg_value(insn.ops[1].reg, p)
				assert isinstance(rn, ImmediateValue)
				m = None
				if insn.ops[2].type == xda.o_imm:
					m = insn.ops[2].value
				elif insn.ops[2].type == xda.o_reg:
					rm = analysis_reg_value(insn.ops[2].reg, p)
					assert isinstance(rm, ImmediateValue)
					m = rm.value
				else:
					assert None
				result = ImmediateValue(rn.value + m)
			break
		if mnem in [ 'SUB' ]:
			# SUB Rd, FP, #m -> Rd = FP - #m -> VariableValue
			insn = xda.insn(p)
			if insn.ops[0].reg != reg:
				continue
			if insn.ops[1].reg == r_fp:
				assert insn.ops[2].type == xda.o_imm
				result = VariableValue(insn.ops[2].value, True)
			else:
				assert False
			break
		if mnem in [ 'LDR' ]:
			# LDR Rt, [PC, #m] -> Rt = PC[#m] -> ImmediateValue
			insn = xda.insn(p)
			if insn.ops[0].reg != reg:
				continue
			assert insn.ops[1].type == xda.o_mem
			result = ImmediateValue(xda.dword(insn.ops[1].addr))
			break
	return result

# ------------------------------------------------

def analysis_string_variable(
	variable: VariableValue,
	address_range: tuple[int, int],
) -> tuple[str, int]:
	'''
	分析栈内字符串变量的内容
	* variable 变量
	* address_range 分析范围，左闭右开
	* return 元组，[1]为字符串内容，[2]为最后影响字符串变量的指令地址
	'''
	# 字符串变量在内存中是一个12字节结构体，可分为常规态和优化态
	# 常规态会申请堆内存，其+0为定值0x21（TODO：不一定，也有为0x11，但一定是单数），+4为长度，+8为内容指针，需要使用memcpy复制内容
	# 优化态针对短字符串，其+0为长度的两倍，占1字节，+1开始11字节为内容，对于长度为1、2、3、4、5、6、8的字符串，直接通过STR设值，长度为7、9、10、11则使用memcpy复制内容
	# 两种情况中的memcpy复制源都是rodata中的空终止字符串
	struct_size = 0xC
	struct = bytearray(struct_size)
	# 标记处初次与末次STR指令的地址
	first_str_p = None
	last_str_p = None
	# 查找对字符串内存进行修改的指令
	for p in range(address_range[0], address_range[1], +4):
		mnem = xda.mnem(p)
		if mnem in [ 'STRB', 'STRH', 'STR' ]:
			# STR Rt, [Rn, #m] -> Rn[#m] = Rt
			# Rn为SP或FP,Rn+#m指向变量内存区间中的某一地址
			insn = xda.insn(p)
			assert insn.ops[1].type == xda.o_displ
			if (insn.ops[1].reg != r_sp and not variable.relative_stack_tail) or (insn.ops[1].reg != r_fp and variable.relative_stack_tail):
				continue
			offset = insn.ops[1].addr
			# 相对FP偏移时，换算偏移量
			if insn.ops[1].reg == r_fp:
				offset = -(offset - 0x100000000)
				offset = variable.offset + offset + (variable.offset - offset * 2)
			offset -= variable.offset
			if not 0x0 <= offset < struct_size:
				continue
			# 标记STR指令地址
			if first_str_p == None:
				first_str_p = p
			last_str_p = p
			# 解析Rt的值，写入字符串结构
			rt = analysis_reg_value(insn.ops[0].reg, p)
			assert isinstance(rt, ImmediateValue)
			value = rt.value
			for i in range(1 if mnem == 'STRB' else 2 if mnem == 'STRH' else 4):
				struct[offset + i] = value >> (i * 8) & 0b11111111
	# 如果未找到任何一条STR指令，则失败
	assert first_str_p != None
	#print(f'{first_str_p:x} - {address_range[0]:x} {address_range[1]:x} {struct}')
	# 若字符串内容已通过STR指令设置完毕，则解码并返回
	if struct[0] != 0x0 and struct[0] % 2 == 0 and struct[0] <= 0x10 and struct[0] != 0xE:
		length = struct[0] // 2
		return (struct[1:length+1].decode('ascii'), last_str_p)
	# 否则，获取其复制的源字符串
	memcpy_invoke_p = None
	# memcpy的调用只会出现在初次STR后，有可能在末次STR之前
	# 正向遍历 ( 首次STR处, 所给结尾地址 )
	for p in range(first_str_p + 4, address_range[1], +4):
		if xda.mnem(p) == 'BL':
			# BL label
			# 有时可能先调用了 operator new ，这种情况下size参数通过MOV立即数设值，且MOV是BL的前一个指令，即 MOV R0, #m
			if xda.mnem(p - 4) == 'MOV':
				# MOV R0, #m
				mov_insn = xda.insn(p - 4)
				if mov_insn.ops[0].reg == 0 and mov_insn.ops[1].type == xda.o_imm:
					continue
			memcpy_invoke_p = p
			break
	else:
		#print(f'{first_str_p:x} - {address_range[0]:x} {address_range[1]:x}')
		assert False
	# memcpy的a2即源字符串的地址
	r1 = analysis_reg_value(1, memcpy_invoke_p)
	assert isinstance(r1, ImmediateValue)
	return (xda.string(r1.value), memcpy_invoke_p)

# ------------------------------------------------

@dataclass
class FindLDRFunctionInvokeResult:
	offset: int
	'''偏移量'''
	assign: int
	'''LDR取值指令地址'''
	invoke: int
	'''BLX调用指令地址'''

def find_ldr_function_invoke(
	offset_list: list[int],
	address_range: tuple[int, int],
) -> Optional[FindLDRFunctionInvokeResult]:
	'''
	在所给范围内查找对指定偏移的LDR取值与BLX调用
	'''
	result = FindLDRFunctionInvokeResult(
		offset=None,
		assign=None,
		invoke=None,
	)
	# 持有函数地址的寄存器，或其存储至的某个局部变量的偏移
	reg = None
	# 查找LDR
	# 简单起见不对Rn进行判断
	for p in range(address_range[0], address_range[1], +4):
		if xda.mnem(p) == 'LDR':
			# LDR Rt, [Rn, #m] -> Rt = Rn[#m]
			insn = xda.insn(p)
			if insn.ops[1].type != xda.o_displ:
				continue
			if not insn.ops[1].addr in offset_list:
				continue
			reg = [insn.ops[0].reg, None]
			result.offset = insn.ops[1].addr
			result.assign = p
			break
	else:
		return None
	# 查找BLX
	# 可能会先被STR至局部变量中，再LDR至寄存器，最后BLX
	for p in range(result.assign + 4, address_range[1], +4):
		mnem = xda.mnem(p)
		if mnem == 'BLX':
			# BLX Rm -> Rm()
			# 确保持有设值函数的寄存器未被STR
			if reg[1] != None:
				continue
			insn = xda.insn(p)
			# 确保是对持有设值函数的寄存器BLX
			if insn.ops[0].type != xda.o_reg or insn.ops[0].reg != reg[0]:
				continue
			result.invoke = p
			break
		if mnem == 'STR':
			# STR Rt, [SP, #m] -> SP[#m] = Rt
			# 确保持有设值函数的寄存器未被STR
			if reg[1] != None:
				continue
			insn = xda.insn(p)
			if insn.ops[0].reg != reg[0]:
				continue
			assert insn.ops[1].reg == r_sp
			assert insn.ops[1].type == xda.o_displ
			reg = [insn.ops[1].reg, insn.ops[1].addr]
			continue
		if mnem == 'LDR':
			# LDR Rt, [SP, #m] -> Rt = SP[#m]
			# 确保持有设值函数的寄存器已被STR
			if reg[1] == None:
				continue
			insn = xda.insn(p)
			if insn.ops[1].type != xda.o_displ or insn.ops[1].reg != reg[0] or insn.ops[1].addr != reg[1]:
				continue
			reg = [insn.ops[0].reg, None]
			continue
	else:
		print(f'{address_range[0]:x} {address_range[1]:x}')
		assert False
	return result

def find_next_mnem(
	begin_address: int,
	mnem_list: str,
) -> tuple[str, int]:
	p = begin_address
	mnem = None
	while True:
		mnem = xda.mnem(p)
		if mnem in mnem_list:
			break
		p += 4
	return (mnem, p)

# ------------------------------------------------

@dataclass
class ParseDeserializationFunctionResult:
	base: Optional[str]
	member: list[ClassMemberDescriptor]

def parse_deserialization_function(
	address: int,
) -> Optional[ParseDeserializationFunctionResult]:
	'''
	分析对象的反序列化函数
	* address 函数地址
	* return 若分析成功，返回ON基类与成员列表组成的元组
	'''
	# 反序列化函数对从ON中解析值，并设给实例成员
	# 典型的反序列化函数应有PUSH-POP
	if xda.mnem(address) != 'PUSH':
		print(f'atypical deserialization function : {address:x}')
		return None
	result = ParseDeserializationFunctionResult(
		base=None,
		member=[]
	)
	# 根据BEQ进行分段，直至遇到POP
	p = address
	address_range_list = []
	address_range_list.append([p])
	while True:
		mnem = xda.mnem(p)
		insn = xda.insn(p)
		if mnem == 'BEQ':
			# BEQ addr
			if len(address_range_list) != 0:
				address_range_list[-1].append(p)
			p = insn.ops[0].addr
			address_range_list.append([p])
			continue
		if mnem in [ 'POP', 'POPEQ' ]:
			# POP ...
			address_range_list.pop()
			break
		p += 4
	# 遍历所得分段
	for address_range in address_range_list:
		member = ClassMemberDescriptor(
			offset=None,
			category=None,
			name=None,
			type=None,
		)
		# 寻找对设值函数的调用
		# a1[34/38/3C]是设值性的函数，它将变量中指定偏移的值设为从on中解析出的值，34为设置变量的函数，38为设置变量1的函数，3c为设置函数的函数
		# 34型设值函数的逻辑为： func (a1, a2, a3, a4, a5) ，其中a3为表示成员名称的字符串，a4为需要设值的内存相对变量基址的偏移量，a5为需要设置的值
		setter_invoke_detail = find_ldr_function_invoke([0x34, 0x38, 0x3C], address_range)
		if setter_invoke_detail == None:
			continue
		if setter_invoke_detail.offset == 0x34:
			member.category = ClassMemberCategory.variable
		elif setter_invoke_detail.offset == 0x38:
			member.category = ClassMemberCategory.property
		elif setter_invoke_detail.offset == 0x3C:
			member.category = ClassMemberCategory.function
		else:
			assert None
		# 若其紧随LDR后，则是在反序列化基类部分
		if setter_invoke_detail.invoke == setter_invoke_detail.assign + 4:
			assert result.base == None
			# 分析基类名
			# 反向找第一个BLX，该调用的a2既基类名
			prev_blx_p = None
			for p in range(setter_invoke_detail.assign - 4, address_range[0], -4):
				if xda.mnem(p) == 'BLX':
					prev_blx_p = p
					break
			else:
				assert False
			r1 = analysis_reg_value(1, prev_blx_p)
			assert isinstance(r1, VariableValue)
			result.base, _, = analysis_string_variable(r1, [address_range[0], prev_blx_p])
			continue
		# 否则，是在反序列化自身成员
		# 若成员为变量，获取其偏移，即34型设值函数的a4
		if member.category == ClassMemberCategory.variable:
			r3 = analysis_reg_value(3, setter_invoke_detail.invoke)
			assert isinstance(r3, ImmediateValue)
			member.offset = r3.value
		# 分析成员名称
		# 对三种设值函数，a3都是表示成员名称的字符串变量
		# 因为有时操作该字符串结构相关的指令可能在获取设值函数之前，所以应以分段起始作为分析边界，而非以设值函数获取处作为分析边界
		r2 = analysis_reg_value(2, setter_invoke_detail.invoke)
		assert isinstance(r2, VariableValue)
		member.name, member_name_last_insn_p, = analysis_string_variable(r2, [address_range[0] + 4, setter_invoke_detail.invoke])
		# 分析成员类型
		# 正向遍历 ( 与成员名称字符串相关的最后一条指令处, 设值函数调用处 )
		for p in range(member_name_last_insn_p + 4, setter_invoke_detail.invoke, +4):
			# 程序有三种方式从ON中反序列化出成员的值，它们都需要指定成员的具体类型
			# a1[1C](a1, a2, a3) -> r ，a1即为a1，a2、a3为两个类型标志整数，返回反序列化出的值
			# a1[28](a1, a2, a3, a4) -> void ，a1即为a1，a2、a3、a4为3、0、0，表示的类型未知
			# func(a1, a2) -> r ，a1即为a1，a2为成员类型字符串，返回反序列化出的值
			# 第一种是对于基本JSON值类型，程序直接取值，不必再进行额外的反序列化，只传入两个表示类型的标志整数
			# 第二种未知，此时使用的是34设置函数，但不会传入a5， TODO 如e66240(972)
			# 第三种是对于类对象或枚举等类型，需要从解析出的ON中反序列化出对象实例，需要传入成员类型字符串
			mnem = xda.mnem(p)
			if mnem == 'BLX':
				# 如果是BLX，则是第一或二种方式
				# BLX Rm
				insn = xda.insn(p)
				assert insn.ops[0].type == xda.o_reg
				# 查找出 LDR Rt, [Rm, #1C/28] ，Rm是与a1等值的某一寄存器，方便起见不再做判断
				# 需要在 ( 设值函数获取处, BLX调用处 ) 内可找到
				value_getter_type = None
				for p_1 in range(p - 4, setter_invoke_detail.assign, -4):
					if xda.mnem(p_1) == 'LDR':
						ldr_insn = xda.insn(p_1)
						if ldr_insn.ops[0].reg != insn.ops[0].reg:
							continue
						assert ldr_insn.ops[1].type == xda.o_displ
						assert ldr_insn.ops[1].addr in [ 0x1C, 0x28 ]
						value_getter_type = ldr_insn.ops[1].addr
						break
				else:
					# 不是对a1[1C/28]的调用，继续查找
					continue
				if value_getter_type == 0x1C:
					# 如果是在对a1[1C]进行调用，则BLX的前两条指令是 MOV R1, #m 与 MOV R2 #m ，即传给1C函数的两个flag
					r1 = analysis_reg_value(1, p)
					assert isinstance(r1, ImmediateValue)
					r2 = analysis_reg_value(2, p)
					assert isinstance(r2, ImmediateValue)
					# 通过flag得到具体类型
					member.type = parse_simple_type_signature(r1.value, r2.value)
				if value_getter_type == 0x28:
					# TODO
					member.type = '<void *>'
				break
			if mnem == 'BL':
				# 如果是BL，则是第三种方式
				# 这种情况下，要分析传给该函数的a2，即成员类型字符串
				insn = xda.insn(p)
				# 判断BL之前的前1~2条指令是否对R1进行了赋值，否则是其他调用的BL，而非对目标函数的BL
				insn_1 = xda.insn(p - 4)
				insn_2 = xda.insn(p - 8)
				if not (
					(insn_1.ops[0].type == xda.o_reg and insn_1.ops[0].reg == 1) or
					(insn_2.ops[0].type == xda.o_reg and insn_2.ops[0].reg == 1)
				):
					continue
				# 分析a2的值
				# 由于R1可能MOV自另一个寄存器，而该寄存器的值在分段起始之前就被定义，故不可以分段起始起始处作为边界
				r1 = analysis_reg_value(1, p)
				# 经常会先出现memcpy，它以一个绝对地址作为复制源，须跳过
				if isinstance(r1, ImmediateValue):
					continue
				# 因为有时操作该字符串结构相关的指令可能在与成员名称字符串相关的最后一条指令之前，所以应以分段起始作为边界，而非以与成员名称字符串相关的最后一条指令处作为边界
				member.type, _, = analysis_string_variable(r1, [address_range[0] + 4, p])
				break
		else:
			assert False
		result.member.append(member)
	return result

@dataclass
class ParseDeserializationListFunctionResult:
	size: int
	base_and_member: Optional[ParseDeserializationFunctionResult]

def parse_deserialization_list_function(
	address: int,
) -> Optional[dict[str, ParseDeserializationListFunctionResult]]:
	'''
	分析反序列化族函数
	* address 函数地址
	* return 若分析成功，则返回该函数中所有反序列化函数的反序列化结构
	'''
	# 典型的第二层函数应有PUSH-POP
	if xda.mnem(address) != 'PUSH':
		print(f'lv2 not PUSH : {address:x}')
		return None
	detail_map: dict[str, ParseDeserializationListFunctionResult] = {}
	# 寻找反序列化函数
	# 典型的的情况下，存在反序列化函数调用的语句块形如 v = f(); if (v) { ... } ，即 CMP R0, #0 后跟 BEQ
	# 有种非典型情况是，无法获取到这样的范围，如100fd68（971？）-UIImageType，这应该是一个枚举类，只有对枚举字符串的判断，而无下一层调用
	# 先获取第层次函数内所有存在反序列化函数调用的语句块范围
	# 根据CMP+BEQ进行分段，直至遇到POP
	p = address
	address_range_list: list[tuple[int, int]] = []
	while True:
		mnem = xda.mnem(p)
		insn = xda.insn(p)
		if mnem in [ 'CMP' ]:
			# CMP R0, #0
			p += 4
			if insn.ops[0].reg != 0 or insn.ops[1].type != xda.o_imm or insn.ops[1].value != 0:
				continue
			mnem = xda.mnem(p)
			assert mnem == 'BEQ'
			insn = xda.insn(p)
			dest_p = insn.ops[0].addr
			address_range_list.append([p, dest_p])
			p = dest_p
			continue
		if mnem in [ 'POP', 'POPEQ' ]:
			break
		p += 4
	# 遍历所得分段
	# 可能找不到任何一个分段
	if len(address_range_list) == 0:
		pass#print(f'no fun {address:x}')
	for address_range in address_range_list:
		# 找到对a1[14/18]的调用
		setter_invoke_detail = find_ldr_function_invoke([0x14, 0x18], address_range)
		if setter_invoke_detail == None:
			continue
		if setter_invoke_detail.offset == 0x14:
			detail = ParseDeserializationListFunctionResult(
				size=None,
				base_and_member=None,
			)
			r1 = analysis_reg_value(1, setter_invoke_detail.invoke)
			assert isinstance(r1, VariableValue)
			name, _, = analysis_string_variable(r1, [address_range[0] + 4, setter_invoke_detail.invoke])
			r3 = analysis_reg_value(3, setter_invoke_detail.invoke)
			assert isinstance(r3, ImmediateValue)
			detail.size = r3.value
			r2 = analysis_reg_value(2, setter_invoke_detail.invoke)
			assert isinstance(r2, ImmediateValue)
			detail.base_and_member = parse_deserialization_function(r2.value)
			if detail.base_and_member == None:
				print(f'lv3 is none : {name} {r2.value:x} at {address:x}')
			detail_map[name] = detail
		elif setter_invoke_detail.offset == 0x18:
			pass#print(f'0x18 enum here : {setter_invoke_detail.assign_address:x}')
	return detail_map

def parse_deserialization_entry_function(
	address: int,
) -> tuple[Optional[str], Optional[dict[str, ParseDeserializationListFunctionResult]], list[str]]:
	'''
	分析反序列化入口函数
	* address 函数地址
	* return 若分析成功，则返回该类的反序列化结构
	'''
	# 典型的反序列化入口函数中，会向下调用两层函数
	stack_list = []
	stack_list.append(f'!{address:x}')
	# 寻找第一层函数
	# 典型的情况下，反序列化入口函数本身只有一条B指令，以跳转至第一层反序列化函数
	if xda.mnem(address) != 'B':
		print(f'atypical deserialization entry function : {address:x}')
		return (None, None, stack_list)
	lv1_address = xda.insn(address).ops[0].addr
	stack_list.append(f'@{lv1_address:x}')
	# 寻找第二层函数
	# 典型的情况下，第一层函数中，若存在指令为BLX后跟BL，则BL指向第二层函数，否则不确定；该语句之前一般还会调用基类的第一层反序列化函数
	blx_p = None
	lv2_address = None
	name = None
	#find_ldr_function_invoke([0x20], [lv1_address, ])
	# 寻找BLX+BL指令
	p = lv1_address
	while True:
		mnem = xda.mnem(p)
		if mnem == 'BLX':
			blx_p = p
			break
		if mnem == 'POP':
			break
		p += 4
	assert blx_p != None
	r1 = analysis_reg_value(1, blx_p)
	if isinstance(r1, ImmediateValue):
		name = xda.string(r1.value)
	elif isinstance(r1, VariableValue):
		name, _, = analysis_string_variable(r1, [lv1_address, blx_p])
	else:
		assert None
	if xda.mnem(blx_p + 4) != 'BL':
		pass#print(f'lv2 not found {lv1_address:x}')
		return (name, None, stack_list)
	insn = xda.insn(blx_p + 4)
	lv2_address = insn.ops[0].addr
	stack_list.append(f'#{lv2_address:x}')
	detail_map = parse_deserialization_list_function(lv2_address)
	return (name, detail_map, stack_list)

def parse_typeinfo(
	address: int,
) -> tuple[str, ClassDescriptor]:
	'''
	分析指定类的type_info，得出其描述信息
	* address 需分析类的type_info基址
	* return 类名称与类描述
	'''
	descriptor = ClassDescriptor(
		name=None,
		size=None,
		base=None,
		member=None,
		ancillary=None,
		derived={},
		stack='?',
	)
	# 获取类名称
	raw_type_name = xda.name(address)
	assert is_typeinfo_name(raw_type_name)
	type_name = get_typeinfo_type(raw_type_name)
	# 获取对该类type_info的引用，用以求出该类的虚表与派生类
	# 一般情况下，type_info会被二者引用：对应类的虚表，以及派生类的type_info
	# 在对应类的虚表中，-4处指向的是该类的typeinfo，后续部分则指向该类的虚函数
	# 在派生类的type_info中，典型的布局（单继承）是 [ (0)该类型的type_info name, (4)该类型基类的type_info ]
	# 对于 RtObject 类，第一个虚函数即为进行对象反序列化的函数
	vtable_is_found = False
	print(f'class : {type_name}')
	for xref in xda.xref_to(address):
		# 首先判断是否被虚表引用，即-4处是否为 vtable for ...
		xref_name = xda.name(xref.frm - 4)
		if not vtable_is_found and is_vtable_name(xref_name):
			# 若为虚表，则+4处指向对象的反序列化函数
			vtable_is_found = True
			func_detail = parse_deserialization_entry_function(xda.dword(xref.frm + 4))
			if func_detail[0] != None:
				descriptor.name = func_detail[0]
				if func_detail[1] != None:
					descriptor.ancillary = []
					for key, value in func_detail[1].items():
						if key == descriptor.name:
							descriptor.size = value.size
							if value.base_and_member != None:
								descriptor.base = value.base_and_member.base
								descriptor.member = value.base_and_member.member
						else:
							ancillary = SimpleClassDescriptor(
								name=key,
								size=value.size,
								base=None,
								member=None,
							)
							if value.base_and_member != None:
								ancillary.base = value.base_and_member.base
								ancillary.member = value.base_and_member.member
							descriptor.ancillary.append(ancillary)
			descriptor.stack = ' '.join(func_detail[2])
		else:
			# 否则，应该被派生类的 type_info 引用，但也有例外
			# 从引用位置的-8位置开始反向查找出type_info的基址
			for p in range(xref.frm - 8, 0, -4):
				xref_name = xda.name(p)
				if not len(xref_name) == 0:
					if is_typeinfo_name(xref_name):
						# 若找到type_info基址，则递归地对派生类进行分析
						derived = parse_typeinfo(p)
						assert derived[0] not in descriptor.derived
						descriptor.derived.setdefault(derived[0], derived[1])
						break
					elif is_vtable_name(xref_name):
						# 一种例外是被其他类的虚表所引用，如1C16D98
						#print(f'vtable xref at {p:x}')
						break
					else:
						# 否则，简单地认为这是其他例外情况，而非被type_info引用
						print(f'except xref at {p:x}')
						break
	if not vtable_is_found:
		print(f'vtable not found : {type_name} {address:x}')
	return (type_name, descriptor)

def find_rtobject_typeinfo_address(
) -> Optional[int]:
	'''
	查找 RtObject type_info 的所在地址
	* return 如果查找成功，则返回所在地址
	'''
	return xda.address_of_name('_ZTIN4Sexy8RtObjectE')

# ------------------------------------------------

import file_system
import time
import rtobject_descriptor
def main(
) -> None:
	text_file_path = 'C:/Users/TwinKleS/Downloads/RtObject.txt'
	json_file_path = 'C:/Users/TwinKleS/Downloads/RtObject.json'
	rtobject_typeinfo_p = find_rtobject_typeinfo_address()
	assert rtobject_typeinfo_p != None
	print(f'RtObject : {rtobject_typeinfo_p:x}')
	time_start = time.time()
	result = parse_typeinfo(rtobject_typeinfo_p)
	time_end = time.time()
	print(f'耗时 : {time_end - time_start} s')
	file_system.write_file(text_file_path, '\n'.join(rtobject_descriptor.stringify_class_descriptor(result[1], 0, True)))
	file_system.write_file(json_file_path, rtobject_descriptor.jsonify_class_descriptor(result))
	print(f'脚本执行完毕，输出 : {json_file_path}')
	return

main()
# res = parse_deserialization_function(0x2A3240)
# print(res.base)
# print(rtobject_descriptor.jsonify_class_descriptor(res.member))

'''
注意：10.0版本开始，本脚本无法正确解析，需要进一步完善
已知变化：
1. 反序列化函数可能没有第一层跳转（似乎是在内部只有单个序列化函数的情况下没有第一次跳转）
2. 字符串进一步优化，16字节以内的字符串都使用str配合立即数直接赋值（在非SSO（即申请了堆内存）的情况下也是如此）
'''