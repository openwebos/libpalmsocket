

#include <glib/gmain.h>
#include <palmsocket.h>


#include "palmsockerror.h"
#include "IObserver.h"
#include "Callback.h"


void Attach(IThreadShutdownObserver *pObserver, GSource *pSource) {
	GIOFunc Func = GIOFuncCallback<IThreadShutdownObserver>;
	g_source_set_callback(pSource, (GSourceFunc)Func, /*data*/pObserver, /*notify*/NULL);
}
