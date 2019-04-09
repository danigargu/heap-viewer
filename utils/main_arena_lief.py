#!/usr/bin/python
#
# Util to find statically the main_arena offset in glibc files 
# by @danigargu
#

import sys
import lief

from struct import unpack

offsets = {
    4: [1088, 1096], # 32 bits
    8: [2152, 2160]  # 64 bits
}

machine_types = {
	lief.ELF.ARCH.i386: ('<I', 4),
	lief.ELF.ARCH.x86_64: ('<Q', 8)
}

def find_main_arena(libc_file):
	binary = lief.parse(libc_file)
	section = binary.get_section(".data")
	data = bytearray(section.content)
	m_type = binary.header.machine_type
	arch_info = machine_types.get(m_type)

	if arch_info is None:
		return None

	u_fmt, ptr_size = arch_info

	ea = 0
	while ea < section.size:
		ptr = unpack(u_fmt, data[ea:ea+ptr_size])[0]
		offset = ptr-section.virtual_address
		if offset < ea:
			if (ea-offset) in offsets[ptr_size]:
				return ptr
		ea += ptr_size
	return None

def main():
	if len(sys.argv) < 2:
		print("usage: python %s <libc-file>" % sys.argv[0])
		return

	libc_file = sys.argv[1]
	main_arena = find_main_arena(libc_file)
	if main_arena is not None:
		print("libc file: %s" % libc_file)
		print("main_arena offset: %#x (%d)" % (main_arena, main_arena))
	else:
		print("ERROR: unable to find the main_arena offset")


if __name__ == '__main__':
	main()

