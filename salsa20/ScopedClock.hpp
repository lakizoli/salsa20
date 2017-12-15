#pragma once

#include <iostream>
#include <chrono>
#include <string>

struct ScopedClock {
	std::string label;
	std::string item;
	size_t itemCount;
	std::chrono::high_resolution_clock::time_point startTime;

	ScopedClock (const std::string& label, const std::string& item, size_t itemCount) :
		label (label), item (item), itemCount (itemCount), startTime (std::chrono::high_resolution_clock::now ())
	{
	}

	~ScopedClock () {
		size_t duration = std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::high_resolution_clock::now () - startTime).count ();
		double velocity = duration > 0 ? (double) itemCount / (double) duration: 0; //multiply with 1e3 to convert: millisec -> sec, and divide with 1e3 to convert: item -> kiloitem, so everything remains the same!

		std::cout << " ### "
			<< label
			<< " ### - time: "
			<< duration
			<< " msec ("
			<< itemCount << " pcs of " << item << " calculated with vecolcity: "
			<< velocity << " k" << item << "/sec)"
			<< std::endl;
	}
};
