/*
 * PeerBaseParams.cpp
 *
 */

#include "PeerBaseParams.h"


PeerBaseParams::PeerBaseParams(GMain *pGMain, PmSockIOChannel *pChannel, const Config *pConfig,
		const PipeFd *pPipeFd)
	:pGMain_(pGMain), pChannel_(pChannel), pConfig_(pConfig), pPipeFd_(pPipeFd)
{
	pSSLMethod_ = NULL;
}
