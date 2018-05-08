# proc_maps_parser
a lightweight library to parse Linux's /proc/[pid]/maps file, which contains the memory map of a process

# /proc/[pid]/maps
A file containing the currently mapped memory regions and
their access permissions.  See mmap(2) for some further
information about memory mappings.
#memory map region
proc_maps_parser represents a memory region with this C structure.
```C
struct procmaps_struct{
	void* addr_start; 	//< start address of the region
	void* addr_end; 	//< end address of the region
	unsigned long length; //<  length of the region by bytes

	char perm[5];		//< permissions rwxp 
	short is_r;			//< is readible
	short is_w;			//< is writable	
	short is_x;			//< is executable
	short is_p;			//< is private

	long offset;	//< offset
	
	char dev[12];	//< the device that backs the region, format major:minor
	int inode;	//< inode of the file that backs the area
	char pathname[600];//< the path of the file that backs the area
	
	//The next region in the list
	struct procmaps_struct* next;		//<handler of the chinaed list
}

```
# Usage
from ./examples/map.c
```C
  int pid=-1; //-1 to use the running process id, use pid>0 to list the map of another process
  procmaps_struct* maps=pmparser_parse(pid);
	if(maps==NULL){
		printf ("[map]: cannot parse the memory map of %d\n",pid);
		return -1;
	}

	//iterate over areas
	procmaps_struct* maps_tmp=NULL;
	while( (maps_tmp=pmparser_next())!=NULL){
		pmparser_print(maps_tmp,0);
		printf("\n~~~~~~~~~~~~~~~~~~~~~~~~~\n"); 
	}

	//mandatory: should free the list
	pmparser_free(maps);
```

