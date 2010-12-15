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
 *  gtpie_utils.h
 *
 *  Useful function to decode/encode GTPIE from/to human/machine readable
 */


#ifndef _GTPIE_UTILS_H
#define _GTPIE_UTILS_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../gtp/pdp.h"

/**
 * gtpie_utils_apn_decode
 *
 * Decode a GTPIE APN format
 *
 * Spec Ref:
 * 3GPP TS 29.060 (7.7.30)
 * TODO: for now, decoding is wonky, needs to be properly done
 *
 * Returns a pointer to a statically allocated string
 */
extern char *gtpie_utils_apn_decode (struct ul255_t apnie);

/**
 * gtpie_utils_imsi_decode
 *
 * Decode a GTPIE IMSI encoding as TBCD
 * like IMSI for instance
 *
 * Spec Ref:
 * 3GPP TS 29.060 (7.7.2)
 * http://en.wikipedia.org/wiki/TBCD
 *
 * Returns a pointer to a statically allocated string
 */
extern char *gtpie_utils_tbcd_decode (u_char *encoded, uint32_t len);
extern int gtpie_utils_tbcd_encode (char *str, void *dst, unsigned int *len, unsigned int size);

extern char *gtpie_utils_imsi_decode (uint64_t imsi);
extern int gtpie_utils_imsi_encode (char *imsi, uint64_t *dst);

extern char *gtpie_utils_msisdn_decode (u_char *encoded, uint32_t len);
extern int gtpie_utils_msisdn_encode (char *msisdn, void *dst, unsigned int *len, unsigned int size);

#endif /* _GTPIE_UTILS_H */
