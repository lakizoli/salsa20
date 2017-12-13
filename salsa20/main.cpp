//salsa20 speedup project

#include "defs.h"
#include <experimental/filesystem>
#include <cassert>
#include <iostream>
#include <functional>

namespace fs = std::experimental::filesystem;
using namespace std;

extern "C" void referenceSalsa8 (uint32_t B[16], const uint32_t Bx[16]);
extern void speedupSalsa8 (const uint32_t input[16], uint32_t output[16]);
extern int RunCipher (const string& tag, const string& source, const string& target, function<void (const uint32_t input[16], uint32_t output[16])> cipher);
extern int HasSameContent (const string& file1, const string& file2, bool& same);

static int PrintUsage (char* exePath) {
	cout << "Usage:" << endl << endl << fs::absolute (exePath).filename ().string () << " <source file path> <reference target file path> <speedup target file path>" << endl << endl;
	return ERROR;
}

int main (int argc, char* argv[]) {
	//Read parameters
	if (argc < 4) {
		assert (argc >= 1);
		return PrintUsage (argv[0]);
	}

	//Do reference cipher
	cout << "Executing reference cipher..." << endl;

	int resCode = RunCipher ("reference", argv[1], argv[2], [] (const uint32_t input[16], uint32_t output[16]) -> void {
		referenceSalsa8 (output, input);
	});
	if (resCode != SUCCESS) {
		cout << "Error occured!" << endl;
		return resCode;
	}

	//Do speedup cipher
	cout << "Executing speedup cipher..." << endl;

	resCode = RunCipher ("speedup", argv[1], argv[3], [] (const uint32_t input[16], uint32_t output[16]) -> void {
		speedupSalsa8 (input, output);
	});
	if (resCode != SUCCESS) {
		cout << "Error occured!" << endl;
		return resCode;
	}

	//Check validity
	cout << "Checking cipher results..." << endl;

	bool isSame = false;
	resCode = HasSameContent (argv[2], argv[3], isSame);
	if (resCode != SUCCESS) {
		cout << "Error occured!" << endl;
		return resCode;
	}

	cout << "Algorithm was: " << (isSame ? "good" : "failed") << endl;
    return SUCCESS;
}

