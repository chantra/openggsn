/*
 *  OpenGGSN - Gateway GPRS Support Node
 *  Copyright (C) 2002, 2003, 2004 Mondru AB.
 *  Copyright (C) 2010 Emmanuel Bretelle <chantra@debuntu.org>
 *
 *  The contents of this file may be used under the terms of the GNU
 *  General Public License Version 2, provided that the above copyright
 *  notice and this permission notice is included in all copies or
 *  substantial portions of the software.
 *
 *  gtpdump_options.h
 *
 *  Options for gtpdump
 */

#ifndef _GTPDUMP_OPTIONS_H
#define _GTPDUMP_OPTIONS_H

#define DFT_SNAPLEN 65535
#define DFT_PROMISC 1

struct gtpdump_options {
  char      *read;
  char      *write;
  char      *interface;
  char      *msisdn;
  char      *imsi;
  int       snaplen;
};

#endif /* _GTPDUMP_OPTIONS_H */
