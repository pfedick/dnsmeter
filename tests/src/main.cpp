
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <ppl7.h>
#include <gtest/gtest.h>


unsigned short getQueryTimestamp()
{
	struct timeval tp;
	if (gettimeofday(&tp,NULL)==0) {
		return (unsigned short)((tp.tv_sec%60)*1000+(tp.tv_usec/1000));
	}
	return 0;
}

double getQueryRTT(unsigned short start)
{
	unsigned short now=getQueryTimestamp();
	unsigned short diff=now-start;
	if (now<start) diff=60000-start+now;
	return (double)(diff)/1000.0f;
}


int main (int argc, char**argv)
{
	unsigned short start=getQueryTimestamp();
	for (int i=0;i<1200;i++) {
		unsigned short now=getQueryTimestamp();
		double diff=getQueryRTT(start);
		printf ("now=%d, diff=%0.3f\n",now,diff);

		ppl7::MSleep(100);
	}
	return 0;
	::testing::InitGoogleTest(&argc, argv);
	try {
		return RUN_ALL_TESTS();
	} catch (const ppl7::Exception &e) {
		printf ("ppl7::Exception: %s\n",e.what());
	} catch (...) {
		printf ("Unbekannte Exception\n");
	}

	return 1;
}
