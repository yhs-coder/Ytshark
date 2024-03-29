src = $(wildcard *.cpp)
object = $(patsubst %.cpp, %.o, $(src))

ALL:mini_wireshark
args = -Wall -g -std=c++14

mini_wireshark:$(object)
	g++ $(object) -o $@ $(args)

%.o:%.cpp
	g++ -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(object)
	rm mini_wireshark
