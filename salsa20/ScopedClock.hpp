#pragma once

#include <iostream>
#include <chrono>
#include <string>

struct ScopedClock {
	std::string label;
	std::chrono::high_resolution_clock::time_point startTime;

	ScopedClock (const std::string& label) : label (label), startTime (std::chrono::high_resolution_clock::now ()) {}
	~ScopedClock () {
		std::cout << " ### "
			<< label
			<< " ### - time: "
			<< std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::high_resolution_clock::now () - startTime).count ()
			<< " msec"
			<< std::endl;
	}
};
