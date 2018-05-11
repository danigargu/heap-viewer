# HeapViewer

An IDA Pro plugin (for now) to examine the heap, focused on exploit development.

Currently only supports glibc malloc (ptmalloc2).

## Requirements

* IDA Pro >= 6.9

## Tested on

* glibc <= 2.27 (x86, x64)

## Features

* Heap tracer (malloc/free/calloc/realloc)
* Malloc chunk info
* Multi-arena info (chunks, top, last-remainder)
* Bins info (fastbins, unsortedbin, smallbins y largebins)
* Tcache info (glibc >= 2.26)
* GraphView for linked lists (bins/tcache)
* Magic utils:
  * Unlink merge info
  * Fake fastbin finder
  * House of force helper
  * Useful libc offsets

## Install

Just drop the `heap_viewer.py` file and the `heap_viewer` folder into IDA's plugin directory.

Because IDA not load libc-dbg symbols in the debug session, is necesary generate a config file before using the plugin. To make this, simply install the `libc6-dbg` package in the remote linux machine and execute the script `utils\get_config.py`. Then, paste the content in the `heap_viewer\config.json` file.


### get_config.py
```
$ python get_config.py
[*] config.json:

{
  "libc_offsets": {
    "32": {
      "mp_": 1921312,
      "main_arena": 1922976,
    },
    "64": {
      "mp_": 3883648,
      "main_arena": 3886144,
    }
  },
  "libc_version": "2.27"
}
```

If you not have the dbg symbols for given libc (ex: CTFs ;D), you can use the `get_main_arena` tool, and get the main_arena offset for that libc. This is enough so the plugin works correctly. Simply put the main_arena offset in the config.json file.

Examples:

```
$ ./main_arena_offset
[*] libc version:       2.27
[*] libc file:          /lib/i386-linux-gnu/libc-2.27.so
[*] libc address:       0xf7ceb000
[*] main_arena:         0xf7ec07a0
[*] main_arena offset:  0x1d57a0

$ LD_PRELOAD=./libc_64.so.6 ./main_arena_offset
...
```

## Screenshots

**Tracer**

![Tracer](https://user-images.githubusercontent.com/1675387/39698165-fe882786-51f3-11e8-847a-18a5b40a6be2.png)

**Arena & chunk info**

![Arena-Chunk](https://user-images.githubusercontent.com/1675387/39698203-2ba59370-51f4-11e8-9b66-c3dfaafadba3.png)

**Tcache entries**

![Tcache entries](https://user-images.githubusercontent.com/1675387/39698220-4c3d3e94-51f4-11e8-8aea-ef9182c8910f.png)

**Bins**

![Bins](https://user-images.githubusercontent.com/1675387/39698914-19bf9db0-51f7-11e8-97f4-82ddf84b7e0e.png)

**Bin graph**

![BinGraph](https://user-images.githubusercontent.com/1675387/39698795-97abbd90-51f6-11e8-8cbc-475b5e623894.png)


**Fastbin graph**

![fastbin graph](https://user-images.githubusercontent.com/1675387/39918437-b5e49562-5510-11e8-8437-86da11eb466f.png)


**Find fake fastbin**

![Find fake fastbin](https://user-images.githubusercontent.com/1675387/39698662-f661b11a-51f5-11e8-8796-c852252bd75a.png)


**Unlink merge info**

![Unlink merge info](https://user-images.githubusercontent.com/1675387/39699039-b2740870-51f7-11e8-9e61-ca9407af1793.png)


**Useful libc offsets**

![Useful libc offsets](https://user-images.githubusercontent.com/1675387/39698577-b1d40b56-51f5-11e8-8ef8-7711bc2efd32.png)


## AUTHOR

* Daniel García Gutiérrez - @danigargu

## CONTRIBUITORS :beer:

Special mention to my colleagues @soez, @wagiro and @DiaLluvioso for give me some ideas during the development of the plugin. And of course, the @pwndbg project, from which I picked up some things about heap parsing.

## BUGS / FEEDBACK / PRs

Any comment, issue or pull request will be highly appreciated :-)

