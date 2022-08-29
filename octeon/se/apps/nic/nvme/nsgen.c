/*
 * Author: Cavium, Inc.
 *
 * Copyright (c) 2015 Cavium, Inc. All rights reserved.
 *
 * Contact: support@cavium.com
 *          Please include "LiquidIO" in the subject.
 *
 * This file, which is part of the LiquidIO SDK from Cavium Inc.,
 * contains proprietary and confidential information of Cavium Inc.
 * and in some cases its suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Inc. Unless you and Cavium Inc. have agreed otherwise in writing, the
 * applicable license terms "OCTEON SDK License Type 5" can be found under
 * the directory: $LIQUIDIO_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
 * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS
 * OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
 * RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY
 * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT
 * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY)
 * WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A
 * PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET
 * ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE
 * RISK ARISING OUT OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.
 */

/***************************************************************************//**
*
*  \file
*
*  \brief Program to turn namespace descriptions into a namespace definition
*  file in c.
*
* See the document "NVMe namespace data generator". The general plan is like a
* lex/yacc, but sucks way less. See also the NVMe spec. This program follows the
* 1.2 NVMe spec.
*
* The general plan is to load up the values from the source file, and output the
* C code file into the destination file. We use the same data structures as
* the NVMe FW uses for its internal structure (which in turn matches the NVMe
* spec, since the namespace id structure is returned to host).
*
* Since the same structures as are inside the FW serve as the intermediate,
* the loader code, or the storeout code, or both, could be embedded in FW.
* The loader code would be creating a namespace description from file or memory.
* The storer code makes less sense, but could be reworked to form a state
* storage mechanism.
*
*******************************************************************************/

#include "nvme_cvm.h"

/**
 * Maximum number of characters in string
 */
#define MAXSTR 250 // maximum number of characters in string

/*
 * Turn on tolken printing
 */
#define DEBUG_TOLKENS 0

/**
 * Tolken types
 */
enum {
	tk_end,       /* 0: end of file */
	tk_num,       /* 1: a number */
	tk_str,       /* 2: a string */
	tk_star,      /* 3: the "*" character */
	// below are keywords
	tk_namespace, /* 4: namespace */
	tk_nameend,   /* 5: nameend */
	tk_nsze,      /* 6: nsze */
	tk_ncap,      /* 7: ncap */
	tk_nuse,      /* 8: nuse */
	tk_nsfeat,    /* 9: nsfeat */
	tk_dealloc,   /* 10: dealloc */
	tk_altflag,   /* 11: altflag */
	tk_thin,      /* 12: thin */
	tk_mc,        /* 13: mc */
	tk_extdata,   /* 14: extdata */
	tk_extlba,    /* 15: extlba */
	tk_dpc,       /* 16: dpc */
	tk_last8,     /* 17: last8 */
	tk_first8,    /* 18: first8 */
	tk_prot3,     /* 19: prot3 */
	tk_prot2,     /* 20: prot2 */
	tk_prot1,     /* 21: prot1 */
	tk_dps,       /* 22: dps */
	tk_nmic,      /* 23: nmic */
	tk_share,     /* 24: share */
	tk_rescap,    /* 25: rescap */
	tk_allexc,    /* 26: allexc */
	tk_wrtexc,    /* 27: wrtexc */
	tk_excreg,    /* 28: excreg */
	tk_wrtexcreg, /* 29: wrtexcreg */
	tk_excres,    /* 30: excres */
	tk_wrtexcres, /* 31: wrtexcres */
	tk_pwrl,      /* 32: pwrl */
	tk_fpi,       /* 33: fpi */
	tk_nawun,     /* 34: nawun */
	tk_nawupf,    /* 35: nawupf */
	tk_nacwu,     /* 36: nacwu */
	tk_eui64,     /* 37: eui64 */
	tk_euioff,    /* 38: euioff */
	tk_euiman,    /* 39: euiman */
	tk_lbaf,      /* 40: lbaf */
	tk_best,      /* 41: best */
	tk_better,    /* 42: better */
	tk_good,      /* 43: good */
	tk_degraded,  /* 44: degraded */
	tk_metaend,   /* 45: metaend */
	tk_vs,        /* 46: vs */
	tk_assign,    /* 47: assign */
	tk_policy,    /* 48: policy */
	tk_onetoall,  /* 49: onetoall */
	tk_onetoone,  /* 50: onetoone */
	tk_pertable,  /* 51: pertable */
	// this is also the end marker
	tk_alias,     /* 52: alias */
};

/**
 * Tolken table
 *
 * A series of tolken strings followed by zero.
 */
char *idtab[tk_alias+2] = {
	"",          /* end of file */
	"",          /* a number */
	"",          /* a string */
	"*",         /* the "*" character */
	"namespace", /* namespace */
	"nameend",   /* nameend */
	"nsze",      /* nsze */
	"ncap",      /* ncap */
	"nuse",      /* nuse */
	"nsfeat",    /* nsfeat */
	"dealloc",   /* dealloc */
	"altflag",   /* altflag */
	"thin",      /* thin */
	"mc",        /* mc */
	"extdata",   /* extdata */
	"extlba",    /* extlba */
	"dpc",       /* dpc */
	"last8",     /* last8 */
	"first8",    /* first8 */
	"prot3",     /* prot3 */
	"prot2",     /* prot2 */
	"prot1",     /* prot1 */
	"dps",       /* dps */
	"nmic",      /* nmic */
	"share",     /* share */
	"rescap",    /* rescap */
	"allexc",    /* allexc */
	"wrtexc",    /* wrtexc */
	"excreg",    /* excreg */
	"wrtexcreg", /* wrtexcreg */
	"excres",    /* excres */
	"wrtexcres", /* wrtexcres */
	"pwrl",      /* pwrl */
	"fpi",       /* fpi */
	"nawun",     /* nawun */
	"nawupf",    /* nawupf */
	"nacwu",     /* nacwu */
	"eui64",     /* eui64 */
	"euioff",    /* euioff */
	"euiman",    /* euiman */
	"lbaf",      /* lbaf */
	"best",      /* best */
	"better",    /* better */
	"good",      /* good */
	"degraded",  /* degraded */
	"metaend",   /* metaend */
	"vs",        /* vs */
	"assign",    /* assign */
	"policy",    /* policy */
	"onetoall",  /* onetoall */
	"onetoone",  /* onetoone */
	"pertable",  /* pertable */
	"alias",     /* alias */
	0
};

/**
 * bit table
 *
 * For values that are bits, this table gives the values, shifted into place,
 * of the bit or value field it represents. Also gives a mask for multibit
 * values.
 */
#define VALUE 0  /* value */
#define MASK 1   /* mask */
#define BITMASK(b) (1 << b) /* form bitmask */
#define VAL(v, b) (v << b) /* value mask */
int valtab[tk_alias+1][2] = {
	{ 0, 0 },                     /* end of file */
	{ 0, 0 },                     /* a number */
	{ 0, 0 },                     /* a string */
	{ 0, 0 },                     /* the "*" character */
	{ 0, 0 },                     /* namespace */
	{ 0, 0 },                     /* nameend */
	{ 0, 0 },                     /* nsze */
	{ 0, 0 },                     /* ncap */
	{ 0, 0 },                     /* nuse */
	{ 0, 0 },                     /* nsfeat */
	{ BITMASK(2), BITMASK(2) },   /* dealloc */
	{ BITMASK(1), BITMASK(1) },   /* altflag */
	{ BITMASK(0), BITMASK(0) },   /* thin */
	{ 0, 0 },                     /* mc */
	{ BITMASK(1), BITMASK(1) },   /* extdata */
	{ BITMASK(0), BITMASK(0) },   /* extlba */
	{ 0, 0 },                     /* dpc */
	{ BITMASK(4), BITMASK(4) },   /* last8 */
	{ BITMASK(3), BITMASK(3) },   /* first8 */
	{ BITMASK(2), BITMASK(2) },   /* prot3 */
	{ BITMASK(1), BITMASK(1) },   /* prot2 */
	{ BITMASK(0), BITMASK(0) },   /* prot1 */
	{ 0, 0 },                     /* dps */
	{ 0, 0 },                     /* nmic */
	{ BITMASK(0), BITMASK(0) },   /* share */
	{ 0, 0 },                     /* rescap */
	{ BITMASK(6), BITMASK(6) },   /* allexc */
	{ BITMASK(5), BITMASK(5) },   /* wrtexc */
	{ BITMASK(4), BITMASK(4) },   /* excreg */
	{ BITMASK(3), BITMASK(3) },   /* wrtexcreg */
	{ BITMASK(2), BITMASK(2) },   /* excres */
	{ BITMASK(1), BITMASK(1) },   /* wrtexcres */
	{ BITMASK(0), BITMASK(0) },   /* pwrl */
	{ 0, 0 },                     /* fpi */
	{ 0, 0 },                     /* nawun */
	{ 0, 0 },                     /* nawupf */
	{ 0, 0 },                     /* nacwu */
	{ 0, 0 },                     /* eui64 */
	{ 0, 0 },                     /* euioff */
	{ 0, 0 },                     /* euiman */
	{ 0, 0 },                     /* lbaf */
	{ VAL(0x0, 0), VAL(0x3, 0) }, /* best */
	{ VAL(0x1, 0), VAL(0x3, 0) }, /* better */
	{ VAL(0x2, 0), VAL(0x3, 0) }, /* good */
	{ VAL(0x3, 0), VAL(0x3, 0) }, /* degraded */
	{ BITMASK(4), BITMASK(4) },   /* metaend */
	{ 0, 0 },                     /* vs */
	{ 0, 0 },                     /* assign */
	{ 0, 0 },                     /* policy */
	{ 0, 0 },                     /* onetoall */
	{ 0, 0 },                     /* onetoone */
	{ 0, 0 },                     /* pertable */
	{ 0, 0 }                      /* alias */
};

/**
 * Source file
 */
FILE* inpfil; // input file

/**
 * Destination file
 */
FILE* outfil; // output file

/**
 * Line number in input file
 */
int lineno;

/**
 * Lexer data block
 */
int nxt_tlk;                // next tolken
char nxt_str[MAXSTR];       // next string
unsigned long long nxt_num; // next number

/**
 * namespaces directory
 *
 * This table has entries for each namespace used in the drive.
 */
struct ns_ctrl * sal_namespaces[MAX_NUMBER_NS] = { 0, };

/**
 * Number of namespaces in directory
 */
int namecnt = 0;

/**
 * Controller Associativity table (CAT)
 *
 * Gives possible namespace associations for each of 1028 controllers
 * (pf and vf). Zero namespaces mark empty entries. For each controller
 * slot, give a list of the logical namespace numbers that are to be
 * linked to that controller.
 *
 * Terminate this table with zero.
 */
uint32_t ns_cat[NVME_NUM_PFVF][MAX_NUMBER_NS_CTLR] = {
	{ 0, },
};

/**
 * Base of eui serial values
 *
 * This sets the starting point for serially assigned values per namespace in
 * euis.
 */
unsigned long long euibase = 0;

/**
 * Manufacturer number
 *
 * Carries the IEEE EUI64 manufacturer value. The default is for Cavium
 * networks, 0x000FB7
 */
unsigned long long euiman = 0x000fb7;

/**
 * Namespace ram sharing table
 *
 * Each namespace can be set to share its ram block with another namespace.
 * This is an array of namespace numbers, one per "live" namespace control
 * structures. If the namespace is 0, the ram block is not shared, but created
 * from scratch. If a logical namespace number appears, then the RAM block for
 * the namespace will be obtained from that namespace.
 */
uint32_t ns_share[MAX_NUMBER_NS] = {
	0,
};

/**
 * Next input character
 */
int nxtchr;

/*
 * Namespace mapping policy
 */
uint8_t ns_map_policy = MAP_ONE_TO_ALL;

/**
 * Get next character
 *
 * Gets the next character in the input. Counts the lines.
 */
void getchr(void)

{

	nxtchr = fgetc(inpfil); // get next character
	if (nxtchr == '\n') lineno++; // count off lines

}

/**
 * Get next tolken
 *
 * Retrives the next tolken from the input. The resulting tolken is placed into
 * the lexer data block.
 *
 */
void next(void)

{

	int i;
	int t;
	char* p;
	int v;

	// move forward, skipping spaces and control characters
	do {

		getchr(); // get next character
		if (nxtchr == '!') { // skip line comments

			do {

				getchr(); // get next character

			} while (nxtchr != '\n' && nxtchr != EOF);

		}

	} while ((nxtchr <= ' ' || nxtchr == '!') && nxtchr != EOF);
	if (nxtchr == EOF) nxt_tlk = tk_end; // set end of file
	else if (isdigit(nxtchr)) {

		// sequence is number
		nxt_tlk = tk_num; // set tolken type
		i = 0; // start index
		while (isdigit(nxtchr) || (tolower(nxtchr) >= 'a' && tolower(nxtchr) <= 'f')) {

			if (i >= MAXSTR) {

				fprintf(stderr, "*** Number too large: line: %d\n", lineno);
				exit(1);

			}
			nxt_str[i++] = nxtchr; // place
			getchr(); // next character

		}
		nxt_str[i] = 0; // terminate buffer
		// convert the number in decimal or hex
		nxt_num = strtoul(nxt_str, &p, 0); // convert the number
		if (*p) {

			fprintf(stderr, "*** Invalid number format: line: %d\n", lineno);
			exit(1);

		}
		// process mega
		if (nxtchr == 'm' || nxtchr == 'M') { nxt_num *= 1048576; getchr(); }
		// process giga
		if (nxtchr == 'g' || nxtchr == 'G') { nxt_num *= 1073741824; getchr(); }

	} else if (nxtchr == '"' || nxtchr == '\'') {

		// sequence is string
		nxt_tlk = tk_str; // set tolken type
		i = 0; // start index
		while (nxtchr != '"' && nxtchr != '\'' && nxtchr != '\n' &&
		       nxtchr != EOF) {

			if (nxtchr == '\\') {

				getchr(); // get next character
				switch (nxtchr) {

					case 'n': nxtchr = '\n'; break;
					case 't': nxtchr = '\t'; break;
					case 'v': nxtchr = '\v'; break;
					case 'b': nxtchr = '\b'; break;
					case 'r': nxtchr = '\r'; break;
					case 'f': nxtchr = '\f'; break;
					case 'a': nxtchr = '\a'; break;
					case '0': case '1': case '2': case '3':
					case '4': case '5': case '6': case '7':
					case '8': case '9':
						// collect forced number
						v = 0;
						while (isdigit(nxtchr)) {

							v = v*10+nxtchr-'0';
							getchr(); // next character

						}
						nxtchr = (char) v;
						// octal is it for now. Submit a req if you need hex
				}

			}
			if (i >= MAXSTR) {

				fprintf(stderr, "*** String too large: line: %d\n", lineno);
				exit(1);

			}
			nxt_str[i++] = nxtchr; // place
			getchr(); // next character

		}
		if (nxtchr != '"' && nxtchr != '\'') {

			fprintf(stderr, "*** Unterminated string: line: %d\n", lineno);
			exit(1);

		}

	} else if (nxtchr == '*') nxt_tlk = tk_star; // set '*' character
	else {

		// grind it into a keyword
		i = 0; // start index
		while (isalnum(nxtchr)) {

			// collect alphanumeric characters to buffer}
			if (i >= MAXSTR) {

				fprintf(stderr, "*** Tolken too large: line: %d\n", lineno);
				exit(1);

			}
			nxt_str[i++] = nxtchr; // place character
			getchr(); // next character

		}
		nxt_str[i] = 0; // terminate
		if (!nxt_str[0]) {

			fprintf(stderr, "*** Unidentified character in source: line %d\n", lineno);
			exit(1);

		}
		// search id table
		for (t = 0; t < tk_alias; t++) {

			if (!strcmp(nxt_str, idtab[t])) {

				// found matching id
				nxt_tlk = t; // place code
				break; // exit

			}

		}
		if (!idtab[t]) {

			fprintf(stderr, "*** Unidentified tolken in source: line %d\n", lineno);
			exit(1);

		}
		nxt_tlk = t; // place found keyword

	}
	if (DEBUG_TOLKENS) {

		printf("Line: %d Tolken: ", lineno);
		switch (nxt_tlk) {

			case tk_end: printf("End of file"); break;
			case tk_num: printf("Number: %llu:0x%llx", nxt_num, nxt_num); break;
			case tk_str: printf("String: %s\n", nxt_str); break;
			default: printf("%s", idtab[nxt_tlk]); break;

		}
		printf("\n");

	}

}

/**
 * Validate controller number
 *
 */

int ctlrvalid(void)

{

	int ctlr;

	if (nxt_tlk != tk_num) {

		fprintf(stderr, "*** Expected controller number: line: %d\n", lineno);
		exit(1);

	}
	ctlr = nxt_num; // get controller number
	if (ctlr >= NVME_NUM_PFVF) {

		fprintf(stderr, "*** Invalid controller number: %d line: %d\n", ctlr, lineno);
		exit(1);

	}
	next(); // skip controller number

	return ctlr; // exit with controller number

}

/**
 * Validate namespace number
 *
 */

int nsvalid(void)

{

	int ns;

	if (nxt_tlk != tk_num) {

		fprintf(stderr, "*** Expected namespace number: line: %d\n", lineno);
		exit(1);

	}
	ns = nxt_num; // get namespace number
	if (!ns || ns > MAX_NUMBER_NS) {

		fprintf(stderr, "*** Invalid namespace number: line: %d\n", lineno);
		exit(1);

	}
	next(); // skip namespace number

	return ns; // exit with namespace number

}

/**
 * Validate number
 *
 */

int numvalid(void)

{

	int num;

	if (nxt_tlk != tk_num) {

		fprintf(stderr, "*** Expected number: line: %d\n", lineno);
		exit(1);

	}
	num = nxt_num; // get number
	next(); // skip number

	return num; // exit with number

}

/**
 * Flag/field insert
 *
 * Each keyword can have a flag/field and mask associated with it. This only
 * applies to definitions that set values in namespace fields. Each such value
 * has a value and a mask. The mask is used to remove the previous set value,
 * then the value is or'ed in. This techique covers both individual bits as well
 * as multibit fields.
 */

void flag(uint8_t* val)

{

	*val &= ~valtab[nxt_tlk][MASK]; // mask off field
	*val |= valtab[nxt_tlk][VALUE]; // insert field

}
/**
 * Process namespace definition
 */

void parsenamespace(void)

{

	int nsi;
	struct ns_ctrl* ncp;
	struct nvme_ns_id* nsp;
	unsigned long long eui;
	int i, b, p;
	int ff;
	int lbano = 0;
	unsigned long long v;
	unsigned long long t;
	int vsi = 0;
	int ttlk;

	next(); // skip "namespace"

	if (namecnt >= MAX_NUMBER_NS) {

		fprintf(stderr, "*** Too many namespaces defined: line: %d\n", lineno);
		exit(1);

	}
	// get a new namespace control structure
	ncp = (struct ns_ctrl*) malloc(sizeof(struct ns_ctrl));
	// clear it
	memset(ncp, 0, sizeof(struct ns_ctrl));
	if (namecnt >= MAX_NUMBER_NS) {

		fprintf(stderr, "*** Too many namespaces defined: line: %d\n", lineno);
		exit(1);

	}
	sal_namespaces[namecnt++] = ncp; // place new namespace in directory
	nsp = &ncp->id_ns; // index namespace control struct
	// Set default lba sector. This gets overwritten if an LBA is defined.
	nsp->lbaf[0].lbads = (uint8_t) 9; // sector size 512
	while (nxt_tlk != tk_nameend) {

		// process namespace block
		ttlk = nxt_tlk; // save and skip
		next();
		switch (ttlk) {

			// process namespace commands

			case tk_nsze:   // namespace size
				// get size and copy to capacity
				nsp->ncap = nsp->nsze = numvalid();
				break;
			case tk_ncap:   // namespace capacity
				nsp->ncap = numvalid();
				break;
			case tk_nuse:   // namespace utilization
				nsp->nuse = numvalid();
				break;
			case tk_nsfeat: // namespace features
				while (nxt_tlk == tk_dealloc ||
				       nxt_tlk == tk_altflag ||
				       nxt_tlk == tk_thin)
					flag(&nsp->nsfeat);
				break;
			case tk_mc:     // metadata capabilities
				while (nxt_tlk == tk_extdata ||
				       nxt_tlk == tk_extlba)
					flag(&nsp->mc);
				break;
			case tk_dpc:    // End to end data protection capabilities
				while (nxt_tlk == tk_last8 ||
				       nxt_tlk == tk_first8 ||
				       nxt_tlk == tk_prot3 ||
				       nxt_tlk == tk_prot2 ||
				       nxt_tlk == tk_prot1)
					flag(&nsp->dpc);
				break;
			case tk_dps:    // end to end data protection settings
				// yes, the bit meanings line up with dpc. Read
				// it carefully.
				while (nxt_tlk == tk_first8 ||
				       nxt_tlk == tk_prot3 ||
				       nxt_tlk == tk_prot2 ||
				       nxt_tlk == tk_prot1)
					flag(&nsp->dps);
				break;
			case tk_nmic:   // Namespace multi-path I/O and namespace sharing capabilities
				while (nxt_tlk == tk_share) flag(&nsp->nmic);
				break;
			case tk_rescap: // reservation capabilities
				while (nxt_tlk == tk_allexc ||
				       nxt_tlk == tk_wrtexc ||
				       nxt_tlk == tk_excreg ||
				       nxt_tlk == tk_wrtexcreg ||
				       nxt_tlk == tk_excres ||
				       nxt_tlk == tk_wrtexcres ||
				       nxt_tlk == tk_pwrl)
					flag(&nsp->rescap);
				break;
			case tk_fpi: //format progress indicator
				v = numvalid(); // get percentage
				if (v > 100) {

					fprintf(stderr, "*** Percentage must be 0 to 100: line: %d\n", lineno);
					exit(1);

				}
				// place value and indicator bit
				nsp->fpi = (uint8_t) v+0x80;
				break;
			case tk_nawun: // namespace atomic write unit normal
				nsp->nawun = (uint8_t) numvalid();
				break;
			case tk_nawupf: // namespace atomic write unit power fail
				nsp->nawupf = (uint8_t) numvalid();
				break;
			case tk_nacwu: // namespace atomic compare & write unit
				nsp->nacwu = (uint8_t) numvalid();
				break;
			case tk_eui64:  // Extended unique identifier
				eui = numvalid();
				// in the structure, this is bytes
				for (i = 7; i > 0; i--) {

					nsp->eui64[i] = eui & 0xff;
					eui >>= 8;

				}
				break;
			case tk_euioff: // Extended unique identifier starting base
				euibase = numvalid();
				break;
			case tk_euiman: // extended unique identifier manufacturer number
				euiman = numvalid();
				break;
			case tk_lbaf:   // LBA format
				if (lbano > 16) {

					fprintf(stderr, "*** Too many LBA formats defined for this namespace: line: %d\n", lineno);
					exit(1);

				}
				// get and skip '*' prime format flag
				if (nxt_tlk == tk_star) {

					next();
					nsp->flbas & ~0x0f; // mask previous value
					nsp->flbas |= lbano; // insert new value

				}
				v = numvalid(); // get lba size
				// validate for power of 2
				t = v;
				i = 0;
				b = 0;
				p = 0;
				while (t) {

					if (t&1) { i++; p = b; } // count bits in word
					t >>= 1;
					b++;

				}
				if (i > 1) {

					fprintf(stderr, "*** LBA size is not a power of 2: line: %d\n", lineno);
					exit(1);

				}
				nsp->lbaf[lbano].lbads = (uint8_t) p; // place lba size in power
				while (nxt_tlk == tk_first8 ||
				       nxt_tlk == tk_best ||
				       nxt_tlk == tk_better ||
				       nxt_tlk == tk_good ||
				       nxt_tlk == tk_degraded ||
				       nxt_tlk == tk_metaend) {

					// the meta end flag is placed in a separate area
					if (nxt_tlk == tk_metaend) flag(&nsp->flbas);
					else flag(&nsp->lbaf[lbano].rp);
					next();

				}
				if (nxt_tlk == tk_num)
					nsp->lbaf[lbano].ms = numvalid(); // place metadata size
				lbano++; // next LBA format
				break;
			case tk_vs:     // vendor specific data
				while (nxt_tlk == tk_num || nxt_tlk == tk_str) {

					// while numbers or strings appear
					if (nxt_tlk == tk_num) { // number

						v = numvalid();
						if (v > 255) {

							fprintf(stderr, "*** Number to large for byte: line: %d\n", lineno);
							exit(1);
						}
						if (vsi >= 3712) {

							fprintf(stderr, "*** Too many values in vendor specific area for namespace: line: %d\n", lineno);
							exit(1);

						}
						nsp->vs[vsi++] = (int8_t) v; // place byte

					} else {

						// place string characters
						for (i = 0; i < MAXSTR; i++) {

							if (vsi >= 3712) {

								fprintf(stderr, "*** Too many values in vendor specific area for namespace: line: %d\n", lineno);
								exit(1);

							}
							nsp->vs[vsi] = nxt_str[vsi];
							vsi++;

						}

					}

				}
				break;
			case tk_policy:
				while (nxt_tlk == tk_onetoall ||
				       nxt_tlk == tk_onetoone ||
				       nxt_tlk == tk_onetoone) {
					switch (nxt_tlk) {
						case tk_onetoall: next(); ns_map_policy = MAP_ONE_TO_ALL; /* onetoall */
						case tk_onetoone: next(); ns_map_policy = MAP_ONE_TO_ONE; /* onetoone */
						case tk_pertable: next(); ns_map_policy = MAP_PER_TABLE; /* pertable */
					}
				}
				break;
			default:
				fprintf(stderr, "*** Valid namespace subcommand not found: line: %d\n", lineno);
				exit(1);

		}

	}
	next(); // skip "namespaceend"
	// copy disk size and sector size to outter fields.
	// this is a gracelabs artifact that is going to be removed.
	ncp->disk_size = nsp->nsze; // copy disk size in LBAs
	// copy sector size from formatted LBA size
	v = 1; // find power
	p = nsp->lbaf[nsp->flbas&0xf].lbads;
	while (p) { v <<= 1; p--; }
	ncp->sector_size = v;

}

/**
 * Get next tolken
 *
 * Retrives the next tolken from the input. The resulting tolken is placed into
 * the lexer data block.
 *
 */

void processinput(void)

{

	int ctlr;
	int ns;
	int i, x, y;
	int found;
	int nsd;
	int nss;

	// Parse input file
	lineno = 1; // set 1st line in file
	next(); // get first tolken
	while (nxt_tlk != tk_end) {

		// parse top level statements
		if (nxt_tlk == tk_namespace) parsenamespace();
		else if (nxt_tlk == tk_assign) {

			// parse controller assignment
			next(); // toss tolken
			ctlr = ctlrvalid(); // get controller number
			ns = nsvalid(); // get 1st namespace
			// find the end of the previous allocation for this controller
			for (i = MAX_NUMBER_NS_CTLR-1; i && !ns_cat[ctlr][i]; i--);
			if (ns_cat[ctlr][i]) i++; // skip last entry
			do {


				if (i >= MAX_NUMBER_NS_CTLR) {

					fprintf(stderr, "*** Too many namespaces defined for this controller (%d): line: %d\n",
					        ctlr, lineno);
					exit(1);

				}
				// place new namespace assignment
				ns_cat[ctlr][i++] = ns;
				if (found = nxt_tlk == tk_num) {

					ns = nsvalid(); // get nth namespace

				}

			} while (found);

		} else if (nxt_tlk == tk_alias) {

			// parse alias statement
			next(); // toss tolken
			if (nxt_tlk != tk_num) {

				fprintf(stderr, "*** Expected number: line: %d\n", lineno);
				exit(1);

			}
			nsd = nsvalid(); // get destination namespace
			nss = nsvalid(); // get source namespace
			// note new alias definitions overwrite old
			ns_share[nsd] = nss; // place alias

		} else if (nxt_tlk == tk_policy) {

			// parse policy statement
			next(); // toss tolken
			while (nxt_tlk == tk_onetoall ||
			       nxt_tlk == tk_onetoone ||
			       nxt_tlk == tk_pertable) {
				switch (nxt_tlk) {
					case tk_onetoall:  /* onetoall */
						next();
						ns_map_policy = MAP_ONE_TO_ALL;
						break;
					case tk_onetoone:  /* onetoone */
						next();
						ns_map_policy = MAP_ONE_TO_ONE;
						break;
					case tk_pertable:  /* pertable */
						next();
						ns_map_policy = MAP_PER_TABLE;
						break;
				}
			}

		} else {

			fprintf(stderr, "*** Internal error: line: %d\n", lineno);
			exit(1);

		}

	}

}

/**
 * Process output file
 *
 */
void processoutput(void)

{

	int i, x, m, n;
	struct ns_ctrl* ncp;
	struct nvme_ns_id* nsp;

// generate preamble
fprintf(outfil, "/*\n");
fprintf(outfil, " * Author: Cavium, Inc.\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * Copyright (c) 2015 Cavium, Inc. All rights reserved.\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * Contact: support@cavium.com\n");
fprintf(outfil, " *          Please include \"LiquidIO\" in the subject.\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * This file, which is part of the LiquidIO SDK from Cavium Inc.,\n");
fprintf(outfil, " * contains proprietary and confidential information of Cavium Inc.\n");
fprintf(outfil, " * and in some cases its suppliers. \n");
fprintf(outfil, " *\n");
fprintf(outfil, " * Any licensed reproduction, distribution, modification, or other use of\n");
fprintf(outfil, " * this file or the confidential information or patented inventions\n");
fprintf(outfil, " * embodied in this file is subject to your license agreement with Cavium\n");
fprintf(outfil, " * Inc. Unless you and Cavium Inc. have agreed otherwise in writing, the\n");
fprintf(outfil, " * applicable license terms \"OCTEON SDK License Type 5\" can be found under\n");
fprintf(outfil, " * the directory: $LIQUIDIO_ROOT/licenses/\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * All other use and disclosure is prohibited.\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED \"AS IS\"\n");
fprintf(outfil, " * AND WITH ALL FAULTS AND CAVIUM INC. MAKES NO PROMISES, REPRESENTATIONS\n");
fprintf(outfil, " * OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH\n");
fprintf(outfil, " * RESPECT TO THE SOFTWARE, INCLUDING ITS CONDITION, ITS CONFORMITY TO ANY\n");
fprintf(outfil, " * REPRESENTATION OR DESCRIPTION, OR THE EXISTENCE OF ANY LATENT OR PATENT\n");
fprintf(outfil, " * DEFECTS, AND CAVIUM SPECIFICALLY DISCLAIMS ALL IMPLIED (IF ANY)\n");
fprintf(outfil, " * WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT, FITNESS FOR A\n");
fprintf(outfil, " * PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR COMPLETENESS, QUIET\n");
fprintf(outfil, " * ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE TO DESCRIPTION. THE ENTIRE\n");
fprintf(outfil, " * RISK ARISING OUT OF USE OR PERFORMANCE OF THE SOFTWARE LIES WITH YOU.\n");
fprintf(outfil, " */\n");
fprintf(outfil, "\n");
fprintf(outfil, "/***************************************************************************//**\n");
fprintf(outfil, "*\n");
fprintf(outfil, "*  \\file\n");
fprintf(outfil, "*\n");
fprintf(outfil, "*  \\brief Defines the namespaces and associated data for NVMe.\n");
fprintf(outfil, "*\n");
fprintf(outfil, "* !!!!!!!!!!!! DO NOT EDIT THIS FILE. IT IS AUTOMATICALLY GENERATED !!!!!!!!!!!!\n");
fprintf(outfil, "* \n");
fprintf(outfil, "*******************************************************************************/\n");
fprintf(outfil, "\n");
fprintf(outfil, "#include \"nvme_cvm.h\"\n");
fprintf(outfil, "\n");

// output the cat table

fprintf(outfil, "/*\n");
fprintf(outfil, " * Controller Associativity table (CAT)\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * Gives possible namespace associations for each of 1028 controllers\n");
fprintf(outfil, " * (pf and vf). Zero namespaces mark empty entries. For each controller\n");
fprintf(outfil, " * slot, give a list of the logical namespace numbers that are to be\n");
fprintf(outfil, " * linked to that controller.\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * Terminate this table with zero.\n");
fprintf(outfil, " */\n");
fprintf(outfil, "uint32_t ns_cat[NVME_NUM_PFVF][MAX_NUMBER_NS_CTLR] = {\n");

// find last non-zero entry in table
n = NVME_NUM_PFVF-1;
while (!ns_cat[n][0] && n) n--;
for (i = 0; i <= n; i++) {

	fprintf(outfil, "\t{ ");
	// find last assignment
	m = MAX_NUMBER_NS_CTLR-1;
	while (!ns_cat[i][m] && m) m--;
	for (x = 0; x <= m; x++) {

		fprintf(outfil, "%d", ns_cat[i][x]);
		if (x < MAX_NUMBER_NS_CTLR-1) fprintf(outfil, ", ");

	}
	fprintf(outfil, "}");
	if (i < NVME_NUM_PFVF-1) fprintf(outfil, ",");
	else fprintf(outfil, " ");
	fprintf(outfil, " // controller %d\n", i);

}

fprintf(outfil, "};\n");

// output the ram share table

fprintf(outfil, "/*\n");
fprintf(outfil, " * Namespace ram sharing table\n");
fprintf(outfil, " *\n");
fprintf(outfil, " * Each namespace can be set to share its ram block with another namespace.\n");
fprintf(outfil, " * This is an array of namespace numbers, one per \"live\" namespace control\n");
fprintf(outfil, " * structures. If the namespace is 0, the ram block is not shared, but created\n");
fprintf(outfil, " * from scratch. If a logical namespace number appears, then the RAM block for\n");
fprintf(outfil, " * the namespace will be obtained from that namespace.\n");
fprintf(outfil, " */\n");
fprintf(outfil, "uint32_t ns_share[MAX_NUMBER_NS] = {\n");

// find last non-zero entry in table
n = MAX_NUMBER_NS-1;
while (!ns_share[n] && n) n--;
for (i = 0; i <= n; i++) {

	fprintf(outfil, "\t%d", ns_share[i]);
	if (i < MAX_NUMBER_NS-1) fprintf(outfil, ",");
	else fprintf(outfil, " ");
	fprintf(outfil, " // namespace %d\n", i);

}

fprintf(outfil, "};\n");
fprintf(outfil, "\n");

// output mapping policy

fprintf(outfil, "/*\n");
fprintf(outfil, " * Namespace mapping policy\n");
fprintf(outfil, " */\n");
fprintf(outfil, "CVMX_SHARED uint8_t ns_map_policy = ");
switch (ns_map_policy) {
	case MAP_ONE_TO_ALL: fprintf(outfil, "MAP_ONE_TO_ALL"); break;
	case MAP_ONE_TO_ONE: fprintf(outfil, "MAP_ONE_TO_ONE"); break;
	case MAP_PER_TABLE:  fprintf(outfil, "MAP_PER_TABLE"); break;
}
fprintf(outfil, ";\n");
fprintf(outfil, "\n");

// output namespace table

fprintf(outfil, "/*\n");
fprintf(outfil, " * Namespace descriptor table\n");
fprintf(outfil, " */\n");
fprintf(outfil, "struct ns_ctrl sal_namespace_tbl[] = {\n");

for (i = 0; i < MAX_NUMBER_NS; i++)
	if (sal_namespaces[i]) {

	ncp = sal_namespaces[i];
	nsp = &ncp->id_ns;
	fprintf(outfil, "\t// namespace %d\n", i+1);
	fprintf(outfil, "\t{\n");
	fprintf(outfil, "\t\t%lu, // disk size in sectors\n", ncp->disk_size);
	fprintf(outfil, "\t\t%u, // sector size\n", ncp->sector_size);
	fprintf(outfil, "\t\t%d, // namespace logical id\n", i+1);
	fprintf(outfil, "\t\t0, // name space  type\n");
	fprintf(outfil, "\t\t{0}, // namespace base pointer (to be filled in later)\n");
	fprintf(outfil, "\t\t{\n");

	fprintf(outfil, "\t\t\tle64_cpu(0x%016lx, ull),  // nsze: name space size\n", nsp->nsze);
	fprintf(outfil, "\t\t\tle64_cpu(0x%016lx, ull),  // ncap: name space capacity\n", nsp->ncap);
	fprintf(outfil, "\t\t\tle64_cpu(0x%016lx, ull),  // nuse: name space utilization\n", nsp->nuse);
	fprintf(outfil, "\t\t\t0x%02x, // nsfeat\n", nsp->nsfeat);
	fprintf(outfil, "\t\t\t0x%02x, // nlbaf\n", nsp->nlbaf);
	fprintf(outfil, "\t\t\t0x%02x, // flbas\n", nsp->flbas);
	fprintf(outfil, "\t\t\t0x%02x, // mc\n", nsp->mc);
	fprintf(outfil, "\t\t\t0x%02x, // dpc\n", nsp->dpc);
	fprintf(outfil, "\t\t\t0x%02x, // dps\n", nsp->dps);
	fprintf(outfil, "\t\t\t0x%02x, // nmic\n", nsp->nmic);
	fprintf(outfil, "\t\t\t0x%02x, // rescap\n", nsp->rescap);
	fprintf(outfil, "\t\t\t0x%02x, // fpi\n", nsp->fpi);
	fprintf(outfil, "\t\t\t0x00, // rsvd33\n");
	fprintf(outfil, "\t\t\tle16_cpu(0x%04x),                   // nawun:\n", nsp->nawun);
	fprintf(outfil, "\t\t\tle16_cpu(0x%04x),                   // nawupf:\n", nsp->nawupf);
	fprintf(outfil, "\t\t\tle16_cpu(0x%04x),                   // nacwu:\n", nsp->nacwu);
	fprintf(outfil, "\t\t\t{ 0, },                             // rsvd40[80]\n");
	fprintf(outfil, "\t\t\t{ ");
	for (x = 0; x < 7; x++) fprintf(outfil, "0x%02x, ", nsp->eui64[x]);
	fprintf(outfil, "0x%02x }, // eui64[8]\n", nsp->eui64[7]);
	fprintf(outfil, "\t\t\t{\n");
	for (x = 0; x < 16; x++) {

		fprintf(outfil, "\t\t\t\t{ le16_cpu(0x%04x), 0x%02x, 0x%02x}, // lba format %d\n",
		        nsp->lbaf[x].ms, nsp->lbaf[x].lbads, nsp->lbaf[x].rp, x);

	}
	fprintf(outfil, "\t\t\t}, // lbaf[16]\n");
	fprintf(outfil, "\t\t\t{ 0, },  // rsvd192[192]\n");
	fprintf(outfil, "\t\t\t{\n");
	fprintf(outfil, "\t\t\t");
	// find the last non-zero byte of vs
	m = 3712-1;
	while (m && !nsp->vs[m]) m--;
	for (x = 0; x <= m; x++) {

		fprintf(outfil, "%02x, ", nsp->vs[x]);
		if (!(x+1%16)) fprintf(outfil, "\n\t\t\t");

	}
	fprintf(outfil, "\n\t\t\t} // vs[3712]\n");
	fprintf(outfil, "\t\t}\n");
	fprintf(outfil, "\t},\n");


}

fprintf(outfil, "\t// end of table */\n");
fprintf(outfil, "\t{\n");
fprintf(outfil, "\t\t0,\n");
fprintf(outfil, "\t\t0,\n");
fprintf(outfil, "\t\t0,\n");
fprintf(outfil, "\t\t0,\n");
fprintf(outfil, "\t\t{0},\n");
fprintf(outfil, "\t\t{\n");
fprintf(outfil, "\t\t\t0,\n");
fprintf(outfil, "\t\t}\n");
fprintf(outfil, "\t}\n");

fprintf(outfil, "};\n");

}

/**
 * Main function
 *
 * Initialize program and accept a series of top level constructs until EOF.
 */
void main(int argc, char *argv[])

{

	printf("Namespace generator vs. 0.1\n");

	if (argc != 3) {

		fprintf(stderr, "*** Usage: nsgen <infile> <outfile>\n");
		exit(1);

	}

	printf("Will generate namespace file %s from input file %s\n", argv[2], argv[1]);

	// process input file
	inpfil = fopen(argv[1], "r");
	if (!inpfil) {

		fprintf(stderr, "*** Unable to open input file\n");

	}

	// process input
	printf("Reading specification file %s\n", argv[1]);
	processinput();

	// close input file
	fclose(inpfil);

	// process output file
	outfil = fopen(argv[2], "w");
	if (!outfil) {

		fprintf(stderr, "*** Unable to open output file\n");

	}

	// process output
	printf("Writing result to file %s\n", argv[2]);
	processoutput();

	fclose(outfil);

}
