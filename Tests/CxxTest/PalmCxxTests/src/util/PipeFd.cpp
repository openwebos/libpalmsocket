

//#define VERBOSE


#include <unistd.h>
#include <assert.h>


#include "PipeFd.h"
#include "CommonUtils.h"


PipeFd::PipeFd() {
	int fd[2];

	int err = pipe(fd);

	assert(!err);

	fdIn_ = fd[0];
	fdOut_ = fd[1];
}


void PipeFd::SendShutdownSignal() const {
	char data=0;

    int res = write(GetFdOut(), &data, 1);
    assert(res!=-1); //write should not fail
    assert(res==1);  //must write one and only one byte
}
