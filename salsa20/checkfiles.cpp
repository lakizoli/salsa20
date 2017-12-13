#include "defs.h"
#include <fstream>
#include <vector>

using namespace std;

int HasSameContent (const string& file1, const string& file2, bool& same) {
	same = false;

	ifstream inFile1 (file1, ios::in | ios::binary);
	ifstream inFile2 (file2, ios::in | ios::binary);
	if (!inFile1 || !inFile2) {
		return ERROR;
	}

	inFile1.seekg (0, ios::end);
	inFile2.seekg (0, ios::end);
	if (!inFile1 || !inFile2) {
		return ERROR;
	}

	size_t len1 = inFile1.tellg ();
	size_t len2 = inFile2.tellg ();

	inFile1.seekg (0, ios::beg);
	inFile2.seekg (0, ios::beg);
	if (!inFile1 || !inFile2) {
		return ERROR;
	}

	if (len1 != len2) {
		same = false;
		return SUCCESS;
	}

	const size_t chunkLen = 1024 * 1024;
	size_t chunkCount = len1 / chunkLen;
	if (len1 % chunkLen > 0) {
		++chunkCount;
	}

	vector<uint8_t> buffer1 (chunkLen);
	vector<uint8_t> buffer2 (chunkLen);
	for (size_t i = 0; i < chunkCount; ++i) {
		size_t readLen = i == chunkCount - 1 ? chunkLen : len1 % chunkLen;

		inFile1.read ((char*) &buffer1[0], readLen);
		if (!inFile1) {
			return ERROR;
		}

		inFile2.read ((char*) &buffer2[0], readLen);
		if (!inFile2) {
			return ERROR;
		}

		if (memcmp (&buffer1[0], &buffer2[0], readLen) != 0) {
			same = false;
			return SUCCESS;
		}
	}

	same = true;
	return SUCCESS;
}
