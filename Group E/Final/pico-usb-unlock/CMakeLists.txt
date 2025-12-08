cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_usb_unlock C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_usb_unlock
    src/main.c
    src/ed25519.c
    src/monocypher.c
    src/monocypher-ed25519.c
)

target_include_directories(pico_usb_unlock PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
)

pico_enable_stdio_usb(pico_usb_unlock 1)
pico_enable_stdio_uart(pico_usb_unlock 0)

pico_add_extra_outputs(pico_usb_unlock)

target_link_libraries(pico_usb_unlock
    pico_stdlib
)
