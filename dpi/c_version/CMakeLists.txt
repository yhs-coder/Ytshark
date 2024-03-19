
cmake_minimum_required(VERSION 2.8)
project(dpi)
# add source

include_directories(./)
file(GLOB srcs ./*.c ./protocol/*.c)
#add_executable(dpi ./main.c ./dpi.c ./dpi_pkt_main.c ./dpi_ssh.c ./dpi_list.c)
add_executable(dpi ${srcs})
target_link_libraries(dpi pcap)

