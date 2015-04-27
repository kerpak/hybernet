cmake_minimum_required(VERSION 3.0.0)
project(hybernet)

include_directories(src include)
add_definitions(-std=c++1y)

include_directories(~/Code/github/libtorrent/include)
link_directories(~/Code/github/libtorrent/bin/gcc-4.9.2/release/deprecated-functions-off/fpic-on/link-static/threading-multi)
set(TORRENT_STATIC_CFLAGS
  -DBOOST_ASIO_ENABLE_CANCELIO 
  -DBOOST_ASIO_HASH_MAP_BUCKETS=1021 
  -DBOOST_ASIO_SEPARATE_COMPILATION 
  -DBOOST_EXCEPTION_DISABLE 
  -DBOOST_NO_DEPRECATED 
  -DTORRENT_NO_DEPRECATE 
  -DTORRENT_USE_I2P=1 
  -DUNICODE 
  -D_FILE_OFFSET_BITS=64 
  -D_UNICODE 
)

find_package(PkgConfig REQUIRED)

set(SWIG_EXECUTABLE swig3.0)
find_package(SWIG 3.0 REQUIRED)
include(${SWIG_USE_FILE})

set_source_files_properties(src/module.i PROPERTIES CPLUSPLUS ON)
set_source_files_properties(src/module.i PROPERTIES SWIG_FLAGS "-includeall;-namespace;HyberNet.CDN")
file(GLOB_RECURSE SOURCES src/*.cpp)

swig_add_module(libhybernet csharp src/module.i ${SOURCES})
target_compile_options(libhybernet PRIVATE ${TORRENT_STATIC_CFLAGS})
target_link_libraries(libhybernet -Wl,--as-needed torrent boost_system pthread sodium zmq)
set_target_properties(libhybernet PROPERTIES OUTPUT_NAME hybernet)


add_executable(test-session test/test_session.cpp src/session.cpp)
target_compile_options(test-session PRIVATE ${TORRENT_STATIC_CFLAGS})
target_link_libraries(test-session -Wl,--as-needed torrent boost_system pthread sodium zmq)
