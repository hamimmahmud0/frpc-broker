add_executable(tunnelmate-peer
    src/main.c
    src/tcp.c
    src/udp.c
)
target_link_libraries(tunnelmate-peer PRIVATE tmcommon)
target_include_directories(tunnelmate-peer PRIVATE src ${CMAKE_SOURCE_DIR}/common/include)

install(TARGETS tunnelmate-peer RUNTIME DESTINATION sbin)