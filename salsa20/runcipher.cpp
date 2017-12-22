#include "defs.h"
#include "ScopedClock.hpp"
#include "alignedallocator.h"
#include <functional>
#include <fstream>
#include <vector>

using namespace std;

int RunCipher (const string& tag, const string& source, const string& target, size_t sourceIntegerCount, size_t targetIntegerCount,
	function<uint32_t ()> initCypher, function<void ()> releaseCypher, function<void (const uint32_t* input, uint32_t* output)> cipher)
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

	vector<uint8_t, AlignedAllocator<uint8_t, Alignment::AVX>> buffer (chunkCount * inputChunkLen);
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
	vector<uint8_t, AlignedAllocator<uint8_t, Alignment::AVX>> outputBuffer (chunkCount * outputChunkLen);

	{
		uint32_t stepCount = initCypher ();
		vector<uint8_t, AlignedAllocator<uint8_t, Alignment::AVX>> lastInputBuffer (stepCount * inputChunkLen);
		vector<uint8_t, AlignedAllocator<uint8_t, Alignment::AVX>> lastOutputBuffer (stepCount * outputChunkLen);

		{
			ScopedClock clk ("cipher: " + tag, "hash", chunkCount);

			for (size_t i = 0; i < chunkCount; i += stepCount) {
				if (i + stepCount > chunkCount) { //last step
					size_t residualStepCount = chunkCount - i;
					memcpy (&lastInputBuffer[0], &buffer[i * inputChunkLen], residualStepCount * inputChunkLen);

					cipher ((const uint32_t*) &lastInputBuffer[0], (uint32_t*) &lastOutputBuffer[0]);

					memcpy (&outputBuffer[i * outputChunkLen], &lastOutputBuffer[0], residualStepCount * outputChunkLen);
				} else { //All subsequent steps
					cipher ((const uint32_t*) &buffer[i * inputChunkLen], (uint32_t*) &outputBuffer[i * outputChunkLen]);
				}
			}
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