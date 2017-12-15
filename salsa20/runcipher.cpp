#include "defs.h"
#include "ScopedClock.hpp"
#include <functional>
#include <fstream>
#include <vector>

using namespace std;

int RunCipher (const string& tag, const string& source, const string& target, size_t sourceIntegerCount, size_t targetIntegerCount,
	function<void ()> initCypher, function<void ()> releaseCypher,
	function<void (const uint32_t* input, uint32_t* output, size_t sourceIntegerCount, size_t targetIntegerCount)> cipher)
{
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

	const size_t inputChunkLen = sourceIntegerCount * sizeof (uint32_t);
	size_t chunkCount = len / inputChunkLen;
	if (len % inputChunkLen > 0) {
		++chunkCount;
	}

	vector<uint8_t> buffer (chunkCount * inputChunkLen);
	inFile.read ((char*) &buffer[0], len);
	if (!inFile) {
		return ERROR;
	}

	inFile.close ();

	size_t residual = chunkCount * inputChunkLen - len;
	if (residual > 0) {
		memset (&buffer[len], 0, residual);
	}

	//Run cipher
	const size_t outputChunkLen = targetIntegerCount * sizeof (uint32_t);
	vector<uint8_t> outputBuffer (chunkCount * outputChunkLen);

	{
		ScopedClock clk ("cipher: " + tag, "hash", chunkCount);

		initCypher ();
		for (size_t i = 0; i < chunkCount; ++i) {
			cipher ((const uint32_t*) &buffer[i * inputChunkLen], (uint32_t*) &outputBuffer[i * outputChunkLen], sourceIntegerCount, targetIntegerCount);
		}
		releaseCypher ();
	}

	//Write output file
	ofstream outFile (target, ios::out | ios::binary | ios::trunc);
	if (!outFile) {
		return ERROR;
	}

	outFile.write ((const char*) &outputBuffer[0], outputBuffer.size ());
	return outFile ? SUCCESS : ERROR;
}