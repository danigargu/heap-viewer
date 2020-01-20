# HeapViewer
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

An IDA Pro plugin to examine the heap, focused on exploit development.

Currently supports the glibc malloc implementation (ptmalloc2).

[3rd place winner of the 2018 Hex-Rays Plugin Contest](https://www.hex-rays.com/contests/2018/index.shtml)


## Requirements

* IDA Pro >= 7.0

## Tested on

* glibc 2.23 <= 2.29 (x86, x64)

## Features

* Heap tracer (malloc/free/calloc/realloc)
  * Detection of overlaps and double-frees
  * Visualization using [villoc](https://github.com/wapiflapi/villoc)
* Malloc chunk info
* Chunk editor
* Multi-arena info (chunks, top, last-remainder)
* Bins info (fastbins, unsortedbin, smallbins y largebins)
* Tcache info (glibc >= 2.26)
* GraphView for linked lists (bins/tcache)
* Structs view (malloc_state / malloc_par / tcache_perthread)
* Magic utils:
  * Unlink merge info
  * Freeable/merge info
  * Fake fastbin finder
  * House of force helper
  * Useful libc offsets
  * Calc chunk size (request2size)
  * IO_FILE structs


## Install

Just drop the `heap_viewer.py` file and the `heap_viewer` folder into IDA's plugin directory.

To install just for the current user, copy the files into one of these directories:

| OS          | Plugin path                          |
| ----------- | ------------------------------------ |
| Linux/macOS | `~/.idapro/plugins`                  |
| Windows     | `%AppData%\Hex-Rays\IDA Pro\plugins` |

## Configuration

Currently the plugin does not require to be configured, since it tries to obtain automatically the necessary offsets to analyze the heap. 

However, in case the plugin fails, it is possible to set the different offsets in the configuration tab. To obtain these offsets, you can use any of the tools located in the `utils` folder.

If you find any inconsistency, let me know :)

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


**Tcache graph**

![tcache graph](https://user-images.githubusercontent.com/1675387/39926350-3dbbc7e4-552f-11e8-99f9-72e5dd99d421.png)


**Find fake fastbin**

![Find fake fastbin](https://user-images.githubusercontent.com/1675387/39698662-f661b11a-51f5-11e8-8796-c852252bd75a.png)


**Unlink merge info**

![Unlink merge info](https://user-images.githubusercontent.com/1675387/39699039-b2740870-51f7-11e8-9e61-ca9407af1793.png)


**Useful libc offsets**

![Useful libc offsets](https://user-images.githubusercontent.com/1675387/39698577-b1d40b56-51f5-11e8-8ef8-7711bc2efd32.png)


## Learning Resources

I'd recommend the following resources alongside this tool for learning heap exploiting.

* [shellphish's how2heap](https://github.com/shellphish/how2heap)


## Author

* Daniel García Gutiérrez - @danigargu

## Contributors :beer:

Special mention to my colleagues [soez][soez], [wagiro][wagiro] and [DiaLluvioso][DiaLluvioso] for give me some ideas during the development of the plugin. And of course, the [@pwndbg](https://github.com/pwndbg/pwndbg/) project, from which I picked up some things about heap parsing.

[Contributors](https://github.com/danigargu/heap-viewer/graphs/contributors)

[soez]: https://twitter.com/javierprtd
[wagiro]: https://twitter.com/egarme
[DiaLluvioso]: https://twitter.com/Manuelbp01

## Bugs / Feedback / PRs

Any comment, issue or pull request will be highly appreciated :-)

