# this file is used by some software that help the developers.
# you can just ignore this file if you feel that's better.

# manual DEVELOPMENT compilation is done with "gcc -Wall -pedantic -O0 main.c -o qs"
# manual PRODUCTION compilation is done with "gcc -Wall -pedantic -O3 main.c -o qs"

cmake_minimum_required(VERSION 3.20)
project(qs C)
set(CMAKE_C_STANDARD 99)

# SOURCE FILES
set(QS_SRC  "main.c")

if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
set (CMAKE_C_FLAGS "/W3 /Zi /O2 -D_CRT_SECURE_NO_WARNINGS")
else()
set (CMAKE_C_FLAGS "-Wall -Wextra -pedantic -g -O3 -std=c99")
endif()

# add as a static library
add_library(${PROJECT_NAME} ${QS_SRC})

# INCLUDE DIRECTORIES
target_include_directories(${PROJECT_NAME}
        PUBLIC . )

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto)