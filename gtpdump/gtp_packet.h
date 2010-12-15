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
 *  gtp_packet.h
 */

#ifndef _GTP_PACKET_H
#define _GTP_PACKET_H

#include "../gtp/gtp.h"

#define GTP_V(gtp_packet) gtp_packet->flags >> 5
#define GTP_PT(gtp_packet) (gtp_packet->flags >> 4) & 1
#define GTP_E(gtp_packet) gtp_packet->flags & 0x04
#define GTP_S(gtp_packet) gtp_packet->flags & 0x02
#define GTP_PN(gtp_packet) gtp_packet->flags & 0x01
#define GTP_TYPE(gtp_packet) gtp_packet->gtp0.h.type
#define GTP_LENGTH(gtp_packet) ntohs(gtp_packet->gtp0.h.length)

#define GTP_HLEN(gtp_packet) (GTP_V(gtp_packet) == 0 ? GTP0_HEADER_SIZE : (gtp_packet->flags & 0x07 ? GTP1_HEADER_SIZE_LONG : GTP1_HEADER_SIZE_SHORT) )


#endif /* _GTP_PACKET_H */
