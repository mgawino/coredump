cmake_minimum_required(VERSION 3.0)

project(raise)

set(CMAKE_C_COMPILER gcc)

add_executable(raise raise.c)
set_target_properties(raise PROPERTIES LINK_FLAGS "-static \
                      -Wl,--section-start=.init=00048158 \
                      -Wl,--section-start=.note.ABI-tag=00068134 \
                      -Wl,--section-start=.note.gnu.build-id=00088154 \
                      -Ttext=00100000")