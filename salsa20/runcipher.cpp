#include "defs.h"
#include "ScopedClock.hpp"
#include <functional>
#include <fstream>
#include <vector>

using namespace std;

int RunCipher (const string& tag, const string& source, const string& target, function<void (const uint32_t input[16], uint32_t output[16])> cipher) {
	//Read whole input to the memory
	ifstream inFile (source, ios::in | ios::binary);
	if (!inFile) {
		return ERROR;
	}

	inFile.seekg (0, ios::end);
	if (!inFile) {
		return ERROR;
	}

	size_t len = inFile.tellg ();
	inFile.seekg (0, ios::beg);
	if (!inFile) {
		return ERROR;
	}

	const size_t chunkLen = 16 * sizeof (uint32_t);
	size_t chunkCount = len / chunkLen;
	if (len % chunkLen > 0) {
		++chunkCount;
	}

	vector<uint8_t> buffer (chunkCount * chunkLen);
	inFile.read ((char*) &buffer[0], len);
	if (!inFile) {
		return ERROR;
	}

	inFile.close ();

	size_t residual = chunkCount * chunkLen - len;
	if (residual > 0) {
		memset (&buffer[len], 0, residual);
	}

	//Run cipher
	vector<uint8_t> outputBuffer (chunkCount * chunkLen);

	{
		ScopedClock clk ("cipher: " + tag + "");

		for (size_t i = 0; i < chunkCount; ++i) {
			cipher ((const uint32_t*) &buffer[i * chunkLen], (uint32_t*) &outputBuffer[i * chunkLen]);
		}
	}

	//Write output file
	ofstream outFile (target, ios::out | ios::binary | ios::trunc);
	if (!outFile) {
		return ERROR;
	}

	outFile.write ((const char*) &outputBuffer[0], outputBuffer.size ());
	return outFile ? SUCCESS : ERROR;
}