add_library(tmcommon STATIC
  src/common.c
  src/log.c
  src/frame.c
  src/crypto.c
  src/tls.c
  src/io.c
  src/config.c
  src/net.c
  src/cJSON.c
)

target_include_directories(tmcommon PUBLIC include include/tunnelmate)
target_link_libraries(tmcommon PUBLIC OpenSSL::SSL OpenSSL::Crypto PkgConfig::LIBUV)
target_compile_definitions(tmcommon PUBLIC _GNU_SOURCE)