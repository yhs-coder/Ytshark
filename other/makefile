# object = main.o packet_capture.o

# main:$(object)
# 	g++ $(object) -o main -g -Wall -lpcap -std=c++17

# %.o: %.cpp
# 	g++ -c $<
wireshark:main.cpp packet_capture.cpp mail.cpp
	g++ main.cpp packet_capture.cpp mail.cpp -o $@ -g -Wall -lpcap -lssl -lcrypto -std=c++17 
.PHONY:clean
clean:
	rm wireshark 
# rm *.o
# rm  main




