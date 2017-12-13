//salsa20 speedup project

#include <experimental/filesystem>
#include <cassert>
#include <iostream>

namespace fs = std::experimental::filesystem;
using namespace std;

#define SUCCESS 0
#define ERROR 1

static int PrintUsage (char* exePath) {
	cout << "Usage:" << endl << endl << fs::absolute (exePath).filename ().string () << " <source file path> <target file path>" << endl << endl;
	return ERROR;
}

int main (int argc, char* argv[]) {
	//Read parameters
	if (argc < 3) {
		assert (argc >= 1);
		return PrintUsage (argv[0]);
	}

	//Do reference cipher

    return SUCCESS;
}

