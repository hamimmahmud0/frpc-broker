add_executable(tunnelmate-agent
    src/main.c
    src/control.c
    src/tcp.c
    src/udp.c
)
target_link_libraries(tunnelmate-agent PRIVATE tmcommon)
target_include_directories(tunnelmate-agent PRIVATE src ${CMAKE_SOURCE_DIR}/common/include)

install(TARGETS tunnelmate-agent RUNTIME DESTINATION sbin)