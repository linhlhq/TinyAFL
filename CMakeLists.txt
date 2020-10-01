# Copyright 2020 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION "3.1")
set (CMAKE_CXX_STANDARD 11)

add_subdirectory(TinyInst)

project("afl-showmap")

add_executable(afl-showmap
  types.h
  hash.h
  debug.h
  config.h
  alloc-inl.h
  afl-showmap.cpp
  )

target_link_libraries(afl-showmap tinyinst)

project("afl-tmin")

add_executable(afl-tmin
  types.h
  hash.h
  debug.h
  config.h
  alloc-inl.h
  afl-tmin.cpp
  )

target_link_libraries(afl-tmin tinyinst)


project("AFL")

add_executable(AFL
  types.h
  hash.h
  debug.h
  config.h
  alloc-inl.h
  afl-fuzz.cpp
  )

target_link_libraries(AFL tinyinst)