//salsa20 speedup project

#include "defs.h"
#include <experimental/filesystem>
#include <cassert>
#include <iostream>
#include <functional>

namespace fs = std::experimental::filesystem;
using namespace std;

extern "C" {
	uint32_t initReferenceCypher ();
	void releaseReferenceCypher ();
	void referenceCypher (const uint32_t* input, uint32_t* output);
}

extern uint32_t initSpeedupCypher ();
extern void releaseSpeedupCypher ();
extern void speedupCypher (const uint32_t* input, uint32_t* output);

extern int RunCipher (const string& tag, const string& source, const string& target, size_t sourceIntegerCount, size_t targetIntegerCount,
	function<uint32_t ()> initCypher, function<void ()> releaseCypher,
	function<void (const uint32_t* input, uint32_t* output)> cipher);

extern int HasSameContent (const string& file1, const string& file2, bool& same);

extern void speedUpAssessment ();

static int PrintUsage (char* exePath) {
	cout << "Usage:" << endl << endl << fs::absolute (exePath).filename ().string () << " <source file path> <reference target file path> <speedup target file path>" << endl << endl;
	return ERROR;
}

int main (int argc, char* argv[]) {
	////ASSESSMENT
	//speedUpAssessment ();
	//return SUCCESS;
	////END ASSESSMENT

	//Read parameters
	if (argc < 4) {
		assert (argc >= 1);
		return PrintUsage (argv[0]);
	}

	const size_t sourceIntegerCount = 20; //count of uint32_t in source chunk
	const size_t targetIntegerCount = 8; //count of uint32_t in target chunk

	//Do reference cipher
	cout << "Executing reference cipher..." << endl;

	int resCode = RunCipher ("reference", argv[1], argv[2], sourceIntegerCount, targetIntegerCount,
		[] () -> uint32_t {
			return initReferenceCypher ();
		},
		[] () -> void {
			releaseReferenceCypher ();
		},
		[] (const uint32_t* input, uint32_t* output) -> void {
			referenceCypher (input, output);
		});
	if (resCode != SUCCESS) {
		cout << "Error occured!" << endl;
		return resCode;
	}

	//Do speedup cipher
	cout << "Executing speedup cipher..." << endl;

	resCode = RunCipher ("speedup", argv[1], argv[3], sourceIntegerCount, targetIntegerCount,
		[] () -> uint32_t {
			return initSpeedupCypher ();
		},
		[] () -> void {
			releaseSpeedupCypher ();
		},
		[] (const uint32_t* input, uint32_t* output) -> void {
			speedupCypher (input, output);
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

