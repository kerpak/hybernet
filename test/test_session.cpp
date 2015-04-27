#include "session.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <csignal>

static volatile bool terminated = false;

void terminate(int s) {
  terminated = true;
}

int main(int argc, char** argv) {
  std::signal(SIGINT, terminate);

  hybernet::session s;

  while (!terminated) {
  	std::cerr << "------------------------------------------------------------------------------" << std::endl;
	  for(auto v : s.get_peers())
	  	std::cerr << "FOUND: " << s.get_name(v) << std::endl;
    s.publish("COUCOU");
	  std::this_thread::sleep_for(std::chrono::seconds(1));
	}
}
