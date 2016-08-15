/* vi: set sw=4 ts=4: */
/*
 * phddns implementation for busybox
 *
 *
 * Copyright (C) 2000,2001  Matt Kraai
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

//usage:#define phddns_trivial_usage
//usage:       "Peanuthull Linux, Copyright (c) 2006-2014\n"
//usage:       "\n"
//usage:       "\n	-f, run for the first time\n"
//usage:       "\n	-i, run as interactive mode\n"
//usage:       "\n	-d, run as a daemon\n"
//usage:       "\n	-c, run with configuration file\n"
//usage:       "\n	-u, run as the user \n"
//usage:       "\n	-h, print this screen.\n"
//usage:#define phddns_full_usage "\n\n"
//usage:       "Peanuthull Linux, Copyright (c) 2006-2014\n"
//usage:       "\n"
//usage:       "--first-run\n"
//usage:       "\n	-f, run for the first time\n"
//usage:       "--interact\n"
//usage:       "\n	-i, run as interactive mode\n"
//usage:       "\n	program will request for necessary parameters.\n"
//usage:       "\n	this mode will automatically enabled at first running,\n"
//usage:       "\n	or your configuration file has been lost.\n"
//usage:       "--daemon\n"
//usage:       "\n	-d, run as a daemon\n"
//usage:       "\n	program will quit after put itself to background,\n"
//usage:       "\n	and continue running even you logout,\n"
//usage:       "\n	you can use kill -9 <PID> to terminate.\n"
//usage:       "--config\n"
//usage:       "\n	-c, run with configuration file\n"
//usage:       "\n	program will run with the file\n"
//usage:       "--user\n"
//usage:       "\n	-u, run as the user \n"
//usage:       "\n	program will run as the user\n"
//usage:       "--help\n"
//usage:       "\n	-h, print this screen.\n"
//usage:       "Please visit http://www.oray.com for detail.\n"
//usage:#define phddns_example_usage
//usage:       "$ phddns -d -c /etc/phlinux.conf\n"

#include "libbb.h"
#include <stdio.h>
#include <signal.h>     /* for singal handle */
#include "phkey.h"
#include "phruncall.h"
#include "phupdate.h"
#ifndef WIN32
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <netdb.h>
#include <unistd.h>     /* for close() */
#include "log.h"

static void create_pidfile()
{
    FILE *pidfile;
    char pidfilename[128];
    sprintf(pidfilename, "%s", "/var/run/phddns.pid");

    if ((pidfile = fopen(pidfilename, "w")) != NULL) {
		fprintf(pidfile, "%d\n", getpid());
		(void) fclose(pidfile);
    } else {
		printf("Failed to create pid file %s: %m", pidfilename);
		pidfilename[0] = 0;
    }
}
#endif

PHGlobal global;
PH_parameter parameter;
static void my_handleSIG (int sig)
{
	if (sig == SIGINT)
	{
		printf ("signal = SIGINT\n");
		phddns_stop(&global);
		exit(0);
	}
	if (sig == SIGTERM)
	{
		printf ("signal = SIGTERM\n");
		phddns_stop(&global);
	}
	signal (sig, my_handleSIG);
}

//状态更新回调
static void myOnStatusChanged(PHGlobal* global, int status, long data)
{
	printf("myOnStatusChanged %s", convert_status_code(status));
	if (status == okKeepAliveRecved)
	{
		printf(", IP: %d", data);
	}
	if (status == okDomainsRegistered)
	{
		printf(", UserType: %d", data);
	}
	printf("\n");
}

//域名注册回调
static void myOnDomainRegistered(PHGlobal* global, char *domain)
{
	printf("myOnDomainRegistered %s\n", domain);
}

//用户信息XML数据回调
static void myOnUserInfo(PHGlobal* global, char *userInfo, int len)
{
	printf("myOnUserInfo %s\n", userInfo);
}

//域名信息XML数据回调
static void myOnAccountDomainInfo(PHGlobal* global, char *domainInfo, int len)
{
	printf("myOnAccountDomainInfo %s\n", domainInfo);
}


int phddns_main(int argc, char **argv[]) MAIN_EXTERNALLY_VISIBLE;

int phddns_main(int argc, char **argv[])
{
	void (*ohandler) (int);

#ifdef WIN32
	WORD VersionRequested;		// passed to WSAStartup
	WSADATA  WsaData;			// receives data from WSAStartup
	int error;

	VersionRequested = MAKEWORD(2, 0);

	//start Winsock 2
	error = WSAStartup(VersionRequested, &WsaData);
#endif

	ohandler = signal (SIGINT, my_handleSIG);
	if (ohandler != SIG_DFL) {
		printf ("previous signal handler for SIGINT is not a default handler\n");
		signal (SIGINT, ohandler);
	}

	init_global(&global);
	init_parameter(&parameter);
	if( checkparameter(argc,argv,&global,&parameter) != 0 ) {
//		printf ("Parameter has an unexpected error,please read the help above.Thank you for your patient!\n");
		return 0;
	}

	if( parameter.bDaemon == 1 ) {
#ifndef WIN32
		printf("phddns started as daemon!\n");
		if(0 != daemon(0,0))
		{
			printf("daemon(0,0) failed\n");
			return -1;
		}
#else
		printf("phddns started daemon failed\n");
#endif
	}

	log_open( parameter.logfile, 1);	//empty file will cause we printf to stdout
	//create_pidfile();

	global.cbOnStatusChanged = myOnStatusChanged;
	global.cbOnDomainRegistered = myOnDomainRegistered;
	global.cbOnUserInfo = myOnUserInfo;
	global.cbOnAccountDomainInfo = myOnAccountDomainInfo;

	set_default_callback(&global);
	#ifdef OFFICIAL_CLIENT
	#include "official/official_key.c"
	#else

	global.clientinfo = PH_EMBED_CLIENT_INFO;
	global.challengekey = PH_EMBED_CLIENT_KEY;
	#endif

	for (;;)
	{
		int next = phddns_step(&global);
		sleep(next);
	}
	phddns_stop(&global);
	return 0;
}
