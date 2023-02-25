''' x '''

# ------------------------------------------------

from dataclasses import dataclass
from typing import Optional
from enum import Enum
import json

# ------------------------------------------------

@dataclass
class EnumItemDescriptor:
	'''枚举项描述'''
	name: str
	'''名称'''
	value: int
	'''数值'''

@dataclass
class EnumDescriptor:
	'''枚举描述'''
	name: str
	'''名称'''
	item: list[EnumItemDescriptor]
	'''选项'''

# ------------------------------------------------

class ClassMemberCategory(Enum):
	'''类成员类别'''
	variable = 1
	'''变量'''
	property = 2
	'''属性'''
	function = 3
	'''函数'''

@dataclass
class ClassMemberDescriptor:
	'''类成员描述'''
	offset: Optional[int]
	'''偏移。即相对类内存基址的偏移量，如果类别不为变量，则为None'''
	category: ClassMemberCategory
	'''类别'''
	name: str
	'''名称'''
	type: str
	'''类型。若为变量，则为变量类型；若为函数，则为返回类型'''

@dataclass
class ClassDescriptor:
	'''类描述'''
	name: str
	'''名称'''
	size: Optional[int]
	'''大小'''
	base: Optional[str]
	'''基类名称（ON意义上的）'''
	member: Optional[list[ClassMemberDescriptor]]
	'''成员'''
	ancillary: Optional[list['SimpleClassDescriptor']]
	'''附属类'''
	derived: dict[str, 'ClassDescriptor']
	'''派生类'''
	stack: str
	'''反序列化函数的地址'''

@dataclass
class SimpleClassDescriptor:
	'''简单类描述'''
	name: str
	'''名称'''
	size: int
	'''大小'''
	base: Optional[str]
	'''基类名称（ON意义上的）'''
	member: Optional[list[ClassMemberDescriptor]]
	'''成员'''

# ------------------------------------------------

class ClassDescriptorJSONEncoder(json.JSONEncoder):
	'''
	为JSON编码器适配类描述类
	'''
	def default(self, o):
		if isinstance(o, (ClassMemberDescriptor, ClassDescriptor, SimpleClassDescriptor)):
			return o.__dict__
		elif isinstance(o, Enum):
			return o.name
		else:
			return super(ClassDescriptorJSONEncoder, self).default(o)

def jsonify_class_descriptor(
	data: ClassDescriptor,
) -> str:
	'''
	转换类描述对象为JSON字符串
	* data 类描述
	* return JSON字符串
	'''
	return json.dumps(data, sort_keys=False, indent='\t', separators=(',', ': '), cls=ClassDescriptorJSONEncoder)

# ------------------------------------------------

# TODO ： remove
def stringify_class_member_descriptor_list(
	member: list[ClassMemberDescriptor],
	depth: int,
	lite: bool,
) -> list[str]:
	result = []
	for e in member:
		if lite:
			result.append(f'{chr(9) * (depth)}{"%" if e.category == ClassMemberCategory.function else "$" if e.category == ClassMemberCategory.variable else "#"} {e.name} : {e.type}')
		else:
			result.append(f'{chr(9) * (depth)}{"%" if e.category == ClassMemberCategory.function else "$" if e.category == ClassMemberCategory.variable else "#"}{"???" if e.offset == None else f"{e.offset:03X}"} {e.name} : {e.type}')
	return result

# TODO ： remove
def stringify_class_descriptor(
	self: ClassDescriptor,
	depth: int,
	lite: bool,
) -> list[str]:
	result = []
	if lite:
		result.append(f'{chr(9) * depth}{self.name} {"?" if self.size == None else f"{self.size:03X}"}')
	else:
		result.append(f'{chr(9) * depth}{self.name} {"?" if self.size == None else f"{self.size:03X}"} {self.stack}')
	if self.member == None:
		#print(f'none member : {self.name}')
		result.append(f'{chr(9) * (depth + 1)}<NONE>')
	else:
		result.extend(stringify_class_member_descriptor_list(self.member, depth + 1, lite))
	for k, v in self.derived.items():
		result.extend(stringify_class_descriptor(v, depth + 1, lite))
	if self.ancillary != None:
		for v in self.ancillary:
			result.append(f'{chr(9) * (depth + 1)}- {v.name}')
			if v.member == None:
				#print(f'none member : {v.name}')
				result.append(f'{chr(9) * (depth + 2)}<NONE>')
			else:
				result.extend(stringify_class_member_descriptor_list(v.member, depth + 2, lite))
	return result

# ------------------------------------------------
