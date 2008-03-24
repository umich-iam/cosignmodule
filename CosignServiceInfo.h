/*
 * Copyright (c) 2008 Regents of The University of Michigan.
 * All Rights Reserved.  See COPYRIGHT.
 */

enum COSIGNSTATUS { COSIGNERROR, COSIGNOK, COSIGNLOGGEDIN, COSIGNLOGGEDOUT, COSIGNRETRY, COSIGNBADSUFFIX };

struct CosignServiceInfo {

	std::string	ipAddr;
	std::string	user;
	std::string	realm;
	std::string	krb5TicketPath;
	std::vector<std::string>	factors;
	std::string strFactors;
	ULARGE_INTEGER	timeStamp;

};
