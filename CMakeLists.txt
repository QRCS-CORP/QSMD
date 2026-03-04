cmake_minimum_required(VERSION 3.15)

project(QSMD_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# QSMD Static Library
file(GLOB_RECURSE QSMD_SOURCES "Source/QSMD/*.c")
file(GLOB_RECURSE QSMD_HEADERS "Source/QSMD/*.h")

add_library(qsmd STATIC ${QSMD_SOURCES} ${QSMD_HEADERS})
target_include_directories(qsmd PUBLIC "Source/QSMD")
target_link_libraries(qsmd PUBLIC qsc)

# QSMD DUPLEX Sender
file(GLOB_RECURSE QSMD_SENDER_SOURCES "Source/Sender/*.c")

add_executable(qsmd_sender ${QSMD_SENDER_SOURCES})
target_include_directories(qsmd_sender PRIVATE "Source/Sender")
target_link_libraries(qsmd_sender PRIVATE qsmd)

# QSMP DUPLEX Listener
file(GLOB_RECURSE QSMD_LISTENER_SOURCES "Source/Listener/*.c")

add_executable(qsmd_listener ${QSMD_LISTENER_SOURCES})
target_include_directories(qsmd_listener PRIVATE "Source/Listener")
target_link_libraries(qsmd_listener PRIVATE qsmd)

# Warnings
foreach(target qsmd qsmd_sender qsmd_listener)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
