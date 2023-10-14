#include <ogc/lwp_watchdog.h>

time_t timeout = 0;

inline void reset_timeout() {
	timeout = 0;
}

inline void set_timeout(time_t seconds) {
	timeout = gettime() + secs_to_ticks(seconds);
}

inline bool timedout() {
	bool o = gettime() > timeout;
	if (o) reset_timeout();
	return o;
}

