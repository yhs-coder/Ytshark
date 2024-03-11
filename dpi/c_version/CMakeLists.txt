
project(dpi)
# add source
add_executable(dpi ./main.c ./dpi.c ./dpi_pkt_main.c)

target_link_libraries(dpi pcap)

