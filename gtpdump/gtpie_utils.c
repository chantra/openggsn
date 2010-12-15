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
 */

/*
 * gtpie_utils.c: Contains iutilities to decode/encode from GTPIE stack format to
 * human readable format
*/

#include <stdio.h>
#include <string.h>
#include "gtpie_utils.h"

#define TBCD_VALUES "0123456789*#abc"

char *
gtpie_utils_apn_decode (struct ul255_t apnie){

	static char buf[BUFSIZ];
	int i = 0;
	buf[0] = 0;

	if( apnie.l >= BUFSIZ)
		return buf;

	while( i < apnie.l && i < BUFSIZ-1){
		memcpy(buf+i, apnie.v+i+1, apnie.v[i]);
		i+= apnie.v[i]+1;
		if(i!=apnie.l) buf[i-1] = '.';
	}
	buf[i-1] = 0;
	return buf;
}


char *
gtpie_utils_imsi_decode (uint64_t imsi){
	return gtpie_utils_tbcd_decode ((u_char *)&imsi, sizeof(imsi));
}

int
gtpie_utils_imsi_encode (char *imsi, uint64_t *dst){
	int rc;
	unsigned int len;
	rc = gtpie_utils_tbcd_encode( imsi, dst, &len, sizeof( *dst ) );
	if (rc == 0 && len != sizeof( *dst )){
		return -1;
	}
	return rc;
}


/**
 * MSISDN formatting
 * see: TS 23.040 section 9.1.2.5 Address fields
 */
char *
gtpie_utils_msisdn_decode (u_char *encoded, uint32_t len){
	static char buf[BUFSIZ];
	buf[0] = 0;

	if (len && encoded[0] == 0x91){
		buf[0] = '+';
		strncpy( buf+1, gtpie_utils_tbcd_decode (encoded+1, len-1), BUFSIZ-2);
	}else
		strncpy( buf, gtpie_utils_tbcd_decode (encoded, len), BUFSIZ-1);
	return buf;
}

int
gtpie_utils_msisdn_encode (char *msisdn, void *dst, unsigned int *len, unsigned int size){
	u_char *bytearray = dst;
	int rc;

	if (msisdn[0] == '+'){
		*bytearray = 0x91;
		rc = gtpie_utils_tbcd_encode( msisdn+1, bytearray+1, len, size - 1);
		*len += 1;
	}else{
		rc = gtpie_utils_tbcd_encode( msisdn, bytearray, len, size);
	}
	return rc;
}
/*
 * TBCD-string: Technical Binary Coded Digits.
 * The octetstring contains the digits 0 to F, two digits per octet.
 * Bit 4 to 1 of octet n encoding digit 2(n-1)+1, Bit 5 to 8 of octet n encoding digit 2n,
 * bit 8 being most significant bit.
 * e.g. number = 12345 stored in following order : 2143F5FFFF... ( FF... only for fixed length)
 * represent several digits from 0 through 9, *, #, a, b, c, two
 * digits per octet, each digit encoded 0000 to 1001 (0 to 9),
 * 1010 (*), 1011 (#), 1100 (a), 1101 (b) or 1110 (c); 1111 used
 * as filler when there is an odd number of digits.

 * bits 8765 of octet n encoding digit 2n
 * bits 4321 of octet n encoding digit 2(n-1) +1 which require diffrernt type of encoding .
 */


char *
gtpie_utils_tbcd_decode (u_char *encoded, uint32_t len){
	static char buf[BUFSIZ];
	int i,j,offset;
	u_char c;

	i = j = offset = 0;
	buf[0] = 0;
	while( i < len && offset < BUFSIZ-1){
		if(j%2){
			c = (*encoded & 0xF0) >> 4;
			encoded++;
			i+=1;
		}else{
			c = *encoded & 0x0F;
		}
		j = (j+1)%2;
		switch (c){
			case 0xF:
				break;
			default:
				buf[offset] = TBCD_VALUES[c];
				offset++;
		}
	}
	buf[offset] = 0;
	return buf;
}

int
gtpie_utils_tbcd_encode (char *str, void *dst, unsigned int *len, unsigned int size){
	uint8_t upper = 0;
	u_char *bytearray = dst;
	u_char val;

	*len = 0;
	/* TODO handle all proper case */
	while (*str && (*len < size || (*len == size && upper))){
		/* check for invalid characters */
		if ( !((*str >= '0' && *str <= '9') || (*str >= 'a' && *str <= 'c') || *str == '#' || *str == '*')){
			/* TODO log error */
			return -1;
		}
		/* size increase eachtime we change byte */
		if (!upper)
			*len += 1;

		switch (*str){
			case '*':
				val = 0x0A;
				break;
			case '#':
				val = 0x0B;
				break;
			case 'a':
				val = 0x0C;
				break;
			case 'b':
				val = 0x0D;
				break;
			case 'c':
				val = 0x0E;
				break;
			default:
				val = *str - '0';
		}
		if (upper){
			val = val << 4;
			*bytearray |= val;
			/* upper part of byte done, let move our pointer one step forward */
			bytearray++;
		}else{
			//memcpy(bytearray, &val, 1);
			*bytearray = val;
		}
		upper = (upper + 1) % 2;
		str++;
	}
	if (*len && upper){
		/* we need to fill that missing bit */
		*bytearray |= 0xF0;
	}
	if (*str){
		/* String to encode is longer than max size */
		return -1;
	}
	return 0;
}
