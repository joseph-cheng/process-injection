cmake_minimum_required(VERSION 3.10)

project(ProcessInjection)

add_definitions(-DDEBUG)
include_directories("src")
file(GLOB_RECURSE SOURCES "src/*.cpp")

add_executable(dll_inject ${SOURCES})
