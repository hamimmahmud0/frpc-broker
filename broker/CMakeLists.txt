add_executable(tunnelmated
    src/main.c
    src/control.c
    src/registry.c
    src/relay.c
    src/tcp.c
    src/udp.c
    src/metrics.c
    src/ipc.c
)
target_include_directories(tunnelmated PRIVATE
    ${CMAKE_SOURCE_DIR}/common/include
    ${CMAKE_SOURCE_DIR}/broker/src
)
target_link_libraries(tunnelmated PRIVATE tmcommon)
install(TARGETS tunnelmated RUNTIME DESTINATION sbin)