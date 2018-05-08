/**
*
* main_arena offset extractor
* by @danigargu
* 
* Usage: 
* ./main_arena_offset
* $ LD_PRELOAD=./libc_64.so.6 ./main_arena_offset
*
* Offsets from malloc_state->top (unsortedbin base):
*
* libc <  2.26
* x86: 48
* x64: 88
*
* libc >= 2.26 
* x86: 56
* x64: 96
* 
**/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <gnu/libc-version.h>
#include "pmparser/pmparser.h"

uintptr_t get_main_arena()
{
	size_t arena_offset;
	uint8_t ptr_size = sizeof(size_t);
	const char *libc_version = gnu_get_libc_version();

	if (strcmp(libc_version, "2.26") < 0) // < 2.26
		arena_offset = (ptr_size==8) ? 88 : 48;
	else
		arena_offset = (ptr_size==8) ? 96 : 56;

	uintptr_t *p1 = malloc(2048);
	uintptr_t *p2 = malloc(2048);
	free(p1);

	return p1[0]-arena_offset;
}

int main(int argc, char* argv[])
{
	int pid = -1;
	uintptr_t main_arena_addr = get_main_arena();
	procmaps_struct* maps = pmparser_parse(pid);
	
	if (!maps)
	{
		printf ("[-] Cannot parse the memory map of %d\n", pid);
		return -1;
	}
	procmaps_struct* maps_tmp = NULL;
	while ((maps_tmp=pmparser_next()) != NULL)
	{
		if (strstr (maps_tmp->pathname, "libc"))
		{
			uintptr_t arena_offset = main_arena_addr - (uintptr_t)maps_tmp->addr_start;
			printf("[*] libc version:\t%s\n", gnu_get_libc_version());
			printf("[*] libc file:\t\t%s\n", maps_tmp->pathname);
			printf("[*] libc address:\t%p\n", maps_tmp->addr_start);
			printf("[*] main_arena:\t\t0x%" PRIxPTR "\n", main_arena_addr);
			printf("[*] main_arena offset:\t0x%" PRIxPTR "\n", arena_offset);
			break;
		}
	}
	pmparser_free(maps);
	return 0;
}
