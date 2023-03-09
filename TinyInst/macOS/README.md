# TinyInst on macOS

```
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Limitations on macOS

* TinyInst may not always detect the exact time of target process exit. As a consequence the `OnProcessExit()` callback might have a maximum delay of 100ms. In the future, additional APIs (e.g. kqueue) could be used to detect process exit accurately.
* TinyInst on macOS is affected by the same custom exceptions-handling issues as the Windows version. For the description of the issue and workarounds, see [this section in the readme](https://github.com/googleprojectzero/TinyInst#return-address-patching)
* TinyInst leverages read-only pages to redirect the instruction pointer to the
instrumented code if the original, uninstrumented, code is invoked. On macOS running on ARM chips, the code
section of the modules inside the Dyld cache is aligned to 4k pages, however, ARM uses 16k pages. This makes it more difficult to instrument
individual modules inside the Dyld cache. TinyInst currently solves ths by instrumenting adjacent modules automatically until their code section
aligns to 16k to ensure that not only parts of a module is instrumented. This
behavior is controlled by the `-page_extend_modules` flag which is set to
`true` by default on M1. In some cases it might be possible to turn off this flag resulting in better performance.

## TinyInst and Guard Malloc

On macOS, [Guard Malloc](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/Articles/MallocDebug.html) is a special version of the malloc library that makes it easier to catch certain types of memory safety issues. To enable Guard Malloc for a target process running under TinyInst, use the following flag:

```
-target_env DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib
```

However, on some targets, additional workarounds might be needed.

An issue was observed with some targets, where the combination of TinyInst and Guard Malloc put a process in a state where calls to (mach_)vm_allocate would fail, even though there was still sufficient free memory in the system and the target process address space (possibly due to an issue in macOS itself). This caused libgmalloc to be stuck in an infinite loop the first time it tried to allocate memory after a module was instrumented. The workaround for this is to have the modules loaded and instrumented before libgmalloc is loaded. This can be accomplished by the following flags:

```
-target_env DYLD_INSERT_LIBRARIES=/path/to/instrumented/module.dylib:/usr/lib/libgmalloc.dylib -instrument_modules_on_load
```

The first part ensures that the instrumented module will be loaded before libgmalloc (the order of libraries in `DYLD_INSERT_LIBRARIES` is important). The `-instrument_modules_on_load` flag ensures that modules will be instrumented as soon as they are loaded (and not when the process entypoint or the target method is reached, as is normally the case in TinyInst.

Additionally, especially if you enconter errors related to stack unwinding, the `-patch_return_addresses` flag might be needed.
