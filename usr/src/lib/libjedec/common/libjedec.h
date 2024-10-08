/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _LIBJEDEC_H
#define	_LIBJEDEC_H

/*
 * Library routines that support various JEDEC standards:
 *
 *  o JEDEC JEP-106 vendor data
 *  o Temperature range and Measurement Standards for Components and Modules
 *    (JESD402-1)
 *  o DDR3 Serial Presence Detect (SPD) decoding
 *  o DDR4 Serial Presence Detect (SPD) decoding
 *  o LPDDR3/4/4x Serial Presence Detect (SPD) decoding
 *  o DDR5 Serial Presence Detect (SPD) decoding
 *  o LPDDR5/x Serial Presence Detect (SPD) decoding
 */

#include <sys/types.h>
#include <stdint.h>
#include <libnvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode a JEDEC continuation ID (without parity) and a group ID.
 */
extern const char *libjedec_vendor_string(uint_t, uint_t);

/*
 * JEDEC operating temperature ranges. These are defined in JESD402-1B
 * (September 2024).
 */
typedef enum {
	/*
	 * Operating Case Temperature Ranges
	 */
	JEDEC_TEMP_CASE_A1T,
	JEDEC_TEMP_CASE_A2T,
	JEDEC_TEMP_CASE_A3T,
	JEDEC_TEMP_CASE_IT,
	JEDEC_TEMP_CASE_ET,
	JEDEC_TEMP_CASE_ST,
	JEDEC_TEMP_CASE_XT,
	JEDEC_TEMP_CASE_NT,
	JEDEC_TEMP_CASE_RT,
	/*
	 * Operating Ambient Temperature Ranges
	 */
	JEDEC_TEMP_AMB_CT,
	JEDEC_TEMP_AMB_IOT,
	JEDEC_TEMP_AMB_IPT,
	JEDEC_TEMP_AMB_IXT,
	JEDEC_TEMP_AMB_AO3T,
	JEDEC_TEMP_AMB_AO2T,
	JEDEC_TEMP_AMB_AO1T,
	/*
	 * Storage Temperature Ranges
	 */
	JEDEC_TEMP_STOR_2,
	JEDEC_TEMP_STOR_1B,
	JEDEC_TEMP_STOR_1A,
	JEDEC_TEMP_STOR_ST,
	/*
	 * Operating Junction Temperature Ranges
	 */
	JEDEC_TEMP_JNCT_A135,
	JEDEC_TEMP_JNCT_A130,
	JEDEC_TEMP_JNCT_A1T,
	JEDEC_TEMP_JNCT_A120,
	JEDEC_TEMP_JNCT_A115,
	JEDEC_TEMP_JNCT_A110,
	JEDEC_TEMP_JNCT_A2T,
	JEDEC_TEMP_JNCT_A100,
	JEDEC_TEMP_JNCT_A95,
	JEDEC_TEMP_JNCT_A90,
	JEDEC_TEMP_JNCT_A3T,
	JEDEC_TEMP_JNCT_LT135,
	JEDEC_TEMP_JNCT_LT130,
	JEDEC_TEMP_JNCT_LT125,
	JEDEC_TEMP_JNCT_LT120,
	JEDEC_TEMP_JNCT_LT115,
	JEDEC_TEMP_JNCT_LT110,
	JEDEC_TEMP_JNCT_LT105,
	JEDEC_TEMP_JNCT_LT100,
	JEDEC_TEMP_JNCT_IT,
	JEDEC_TEMP_JNCT_LT90,
	JEDEC_TEMP_JNCT_LT85,
	JEDEC_TEMP_JNCT_ET120,
	JEDEC_TEMP_JNCT_ET115,
	JEDEC_TEMP_JNCT_ET110,
	JEDEC_TEMP_JNCT_ET,
	JEDEC_TEMP_JNCT_ET100,
	JEDEC_TEMP_JNCT_ET95,
	JEDEC_TEMP_JNCT_ET90,
	JEDEC_TEMP_JNCT_ST,
	JEDEC_TEMP_JNCT_120,
	JEDEC_TEMP_JNCT_115,
	JEDEC_TEMP_JNCT_110,
	JEDEC_TEMP_JNCT_105,
	JEDEC_TEMP_JNCT_100,
	JEDEC_TEMP_JNCT_XT,
	JEDEC_TEMP_JNCT_90,
	JEDEC_TEMP_JNCT_NT
} libjedec_temp_range_t;
extern boolean_t libjedec_temp_range(libjedec_temp_range_t, int32_t *,
    int32_t *);

/*
 * This is a series of error codes that libjedec may produce while trying to
 * parse the overall SPD data structure. These represent a top-level failure and
 * have meaning when no nvlist_t is returned.
 */
typedef enum {
	/*
	 * Indicates that we didn't encounter a fatal error; however, we may
	 * have a specific parsing error that relates to a key in the nvlist.
	 */
	LIBJEDEC_SPD_OK	= 0,
	/*
	 * Indicates that we did not have enough memory while trying to
	 * construct the generated nvlist_t.
	 */
	LIBJEDEC_SPD_NOMEM,
	/*
	 * Indicates that the data that we found was insufficient to
	 * successfully parse basic information. The required size varies per
	 * SPD key byte type.
	 */
	LIBJEDEC_SPD_TOOSHORT,
	/*
	 * Indicates that we found an unsupported type of SPD data and therefore
	 * cannot parse this.
	 */
	LIBJEDEC_SPD_UNSUP_TYPE,
	/*
	 * Indicates that while we found a supported type of SPD data, we do not
	 * understand its revision.
	 */
	LIBJEDEC_SPD_UNSUP_REV
} spd_error_t;

/*
 * Decode a binary payload of SPD data, if possible. The returned nvlist is made
 * up of a series of keys described below. Parsing errors are broken into two
 * categories. Fatal errors set a value in the spd_error_t below. Non-fatal
 * errors, such as encountering a value which we don't have a translation for,
 * are in a nested errors nvlist_t indexed by key.
 *
 * The keys are all dot delineated to create a few different top-level
 * namespaces. These include:
 *
 * "meta" -- Which includes information about the SPD, encoding, and things like
 * the type of module.
 *
 * "dram" -- Parameters that are specific to the SDRAM dies present. What one
 * thinks of as a stick of DRAM consists of several different SDRAM dies on the
 * PCB. This includes things like the row and columns bits and timing
 * information.
 *
 * "channel" -- Parameters that are tied to an implementation of a channel. DDR4
 * has a single channel where as DDR5 and LPDDR[345] have some number of
 * sub-channels.
 *
 * "ddr4", "ddr5" -- These include information which is specific to the general
 * DDR standard. While we have tried to consolidate information between them
 * where applicable, some things are specific to the standard.
 *
 * "lp" -- These are parameters that are currently specific to one of the
 * low-power DDR specifications such as LPDDR5.
 *
 * "module" -- Parameters that are specific to the broader module and PCB
 * itself. This includes information like the height or devices present.
 *
 * "ddr4.rdimm", "ddr4.lrdimm", "ddr5.rdimm", etc. -- These are parameter that
 * are specific to a module being both the combination of a specific DDR
 * standard and a specific type of module. Common parameters are often in the
 * "module" section.
 *
 * "ddr3.mb", "ddr4.rcd", etc. -- These are generation-specific parameters that
 * refer to a specific component like the rcd found on RDIMMs and LRDIMMs or the
 * mb on LRDIMMs.
 *
 * "mfg" -- Manufacturing related information.
 *
 * "errors" -- The key for the errors nvlist_t. See the spd_error_kind_t
 * definition later on. Each error has both a numeric code and a string message.
 */
extern nvlist_t *libjedec_spd(const uint8_t *, size_t, spd_error_t *);

/*
 * The following are keys in the metadata nvlist_t. The SPD_KEY_NBYTES_TOTAL is
 * present in DDR4 and DDR5. The SPD_KEY_NBYTES_USED is only present on DDR4
 * right now. All supported SPD encodings have the raw revision information. If
 * the values for the total bytes or used bytes are set to undefined, then they
 * will not be present.
 *
 * DDR5 introduces an idea of a public beta level that gets reset between
 * external releases. It theoretically modifies every scion. DDR5 also
 * introduces a second revision that is for the module information. This will
 * not be present on systems prior to DDR5.
 */
#define	SPD_KEY_NBYTES_TOTAL	"meta.total-bytes"	/* uint32_t */
#define	SPD_KEY_NBYTES_USED	"meta.used-bytes"	/* uint32_t */
#define	SPD_KEY_REV_ENC	"meta.revision-encoding"	/* uint32_t */
#define	SPD_KEY_REV_ADD	"meta.revision-additions"	/* uint32_t */
#define	SPD_KEY_BETA	"meta.beta-version"		/* uint32_t */
#define	SPD_KEY_MOD_REV_ENC	"meta.module-revision-encoding"	/* uint32_t */
#define	SPD_KEY_MOD_REV_ADD	"meta.module-revision-additions" /* uint32_t */

/*
 * DRAM Type information. This indicates the standard that the device conforms
 * to. This enumeration's values match the JEDEC specification's values. This is
 * present for everything.
 */
typedef enum {
	SPD_DT_FAST_PAGE_MODE		= 0x01,
	SPD_DT_EDO			= 0x02,
	SPD_DT_PIPE_NIBBLE		= 0x03,
	SPD_DT_SDRAM			= 0x04,
	SPD_DT_ROM			= 0x05,
	SPD_DT_DDR_SGRAM		= 0x06,
	SPD_DT_DDR_SDRAM		= 0x07,
	SPD_DT_DDR2_SDRAM		= 0x08,
	SPD_DT_DDR2_SDRAM_FBDIMM	= 0x09,
	SPD_DT_DDR2_SDRAM_FDIMM_P	= 0x0a,
	SPD_DT_DDR3_SDRAM		= 0x0b,
	SPD_DT_DDR4_SDRAM		= 0x0c,
	SPD_DT_DDR4E_SDRAM		= 0x0e,
	SPD_DT_LPDDR3_SDRAM		= 0x0f,
	SPD_DT_LPDDR4_SDRAM		= 0x10,
	SPD_DT_LPDDR4X_SDRAM		= 0x11,
	SPD_DT_DDR5_SDRAM		= 0x12,
	SPD_DT_LPDDR5_SDRAM		= 0x13,
	SPD_DT_DDR5_NVDIMM_P		= 0x14,
	SPD_DT_LPDDR5X_SDRAM		= 0x15
} spd_dram_type_t;
#define	SPD_KEY_DRAM_TYPE	"meta.dram-type"	/* uint32_t (enum) */

typedef enum {
	SPD_MOD_TYPE_RDIMM,
	SPD_MOD_TYPE_UDIMM,
	SPD_MOD_TYPE_SODIMM,
	SPD_MOD_TYPE_LRDIMM,
	SPD_MOD_TYPE_MRDIMM,
	SPD_MOD_TYPE_DDIMM,
	SPD_MOD_TYPE_SOLDER,
	SPD_MOD_TYPE_MINI_RDIMM,
	SPD_MOD_TYPE_MINI_UDIMM,
	SPD_MOD_TYPE_MINI_CDIMM,
	SPD_MOD_TYPE_72b_SO_RDIMM,
	SPD_MOD_TYPE_72b_SO_UDIMM,
	SPD_MOD_TYPE_72b_SO_CDIMM,
	SPD_MOD_TYPE_16b_SO_DIMM,
	SPD_MOD_TYPE_32b_SO_DIMM,
	SPD_MOD_TYPE_CUDIMM,
	SPD_MOD_TYPE_CSODIMM,
	SPD_MOD_TYPE_CAMM2,
	SPD_MOD_TYPE_LPDIMM,
	SPD_MOD_TYPE_MICRO_DIMM
} spd_module_type_t;
#define	SPD_KEY_MOD_TYPE	"meta.module-type"	/* uint32_t (enum) */
typedef enum {
	SPD_MOD_NOT_HYBRID,
	SPD_MOD_HYBRID_NVDIMMM
} spd_module_hybrid_t;
#define	SPD_KEY_MOD_HYBRID_TYPE	"meta.hybrid-type"	/* uint32_t */

typedef enum {
	SPD_MOD_TYPE_NVDIMM_N,
	SPD_MOD_TYPE_NVDIMM_P,
	SPD_MOD_TYPE_NVDIMM_H
} spd_module_nvdimm_type_t;
#define	SPD_KEY_MOD_NVDIMM_TYPE	"meta.nvdimm-type"	/* uint32_t */

/*
 * Different SPD standards have different integrity rules. The regions covered
 * by the CRCs also vary. We end up with per-spec keys. All data types for these
 * are uint32_t's so that way we can record the expected CRC. We use a uint32_t
 * for consistency even though the data only fits in a uint16_t. Note, callers
 * must check to see if these exist. If there are keys with these names in the
 * errors object, then the rest of the data should be considered suspect, but we
 * will have attempted to parse everything we can. The DDR4 values are shared
 * across LPDDR3/4/4X. The DDR5 values are shared across LPDDR5/5X.
 */
#define	SPD_KEY_CRC_DDR3	"meta.crc-ddr3"		/* uint32_t */
#define	SPD_KEY_CRC_DDR3_LEN	"meta.crc-ddr3-len"	/* uint32_t */
#define	SPD_KEY_CRC_DDR4_BASE	"meta.crc-ddr4-base"	/* uint32_t */
#define	SPD_KEY_CRC_DDR4_BLK1	"meta.crc-ddr4-block1"	/* uint32_t */
#define	SPD_KEY_CRC_DDR5	"meta.crc-ddr5"		/* uint32_t */

/*
 * DDR5 adds a field in the SPD to describe how data should be hashed to compute
 * and compare to an attribute certification to authenticate modules. This is
 * only present in DDR5. We only add a value here if this is actually supported.
 */
typedef enum {
	SPD_HASH_SEQ_ALG_1
} spd_hash_seq_alg_t;
#define	SPD_KEY_HASH_SEQ	"meta.hash-sequence-algorithm"	/* uint32_t */

/*
 * This section contains information related to DRAM technology.
 */

/*
 * Bank, bank group, row, and column bits. These are all present in both DDR4
 * and DDR5. DDR4 allows cases where there are no bank groups. If no bits are
 * used, then this item is empty.
 */
#define	SPD_KEY_NROW_BITS	"dram.num-row-bits"	/* uint32_t */
#define	SPD_KEY_NCOL_BITS	"dram.num-column-bits"	/* uint32_t */
#define	SPD_KEY_NBANK_BITS	"dram.num-bank-bits"	/* uint32_t */
#define	SPD_KEY_NBGRP_BITS	"dram.num-bank-group-bits"	/* uint32_t */
#define	SPD_KEY_SEC_NROW_BITS	"dram.sec-num-row-bits"		/* uint32_t */
#define	SPD_KEY_SEC_NCOL_BITS	"dram.sec-num-column-bits"	/* uint32_t */
#define	SPD_KEY_SEC_NBANK_BITS	"dram.sec-num-bank-bits"	/* uint32_t */
#define	SPD_KEY_SEC_NBGRP_BITS	"dram.sec-num-bank-group-bits"	/* uint32_t */

/*
 * Die Density. This is the capacity that each die contains in bits.
 */
#define	SPD_KEY_DIE_SIZE	"dram.die-bit-size"	/* uint64_t */
#define	SPD_KEY_SEC_DIE_SIZE	"dram.sec-die-bit-size"	/* uint64_t */

/*
 * Package information. DRAM may be made up of a monolithic package type or
 * several different types. There is a boolean property present to indicate that
 * it is not monolithic. For these there is a die count and then a separate
 * notion of what the signal loading type is. If the property is present then we
 * will also have the die count and loading type for the secondary. Note, these
 * loading parameters are considered at the device balls as opposed to specific
 * signals.
 */
#define	SPD_KEY_PKG_NOT_MONO	"meta.non-monolithic-package"	/* key only */
#define	SPD_KEY_PKG_NDIE	"dram.package-die-count"	/* uint32_t */
#define	SPD_KEY_SEC_PKG_NDIE	"dram.sec-package-die-count"	/* uint32_t */
typedef enum {
	SPD_SL_UNSPECIFIED,
	SPD_SL_MUTLI_STACK,
	SPD_SL_3DS
} spd_signal_loading_t;
#define	SPD_KEY_PKG_SL		"dram.package-sig-loading"	/* uint32_t */
#define	SPD_KEY_SEC_PKG_SL	"dram.sec-package-sig-loading"	/* uint32_t */

/*
 * Post-package Repair. PPR is supported in DDR4, DDR5. LPDDR4, and LPDDR5. PPR
 * support is indicated by the presence of the spd_ppr_flags_t structure. If it
 * is not supported, then there will be no PPR related keys present. In some
 * cases the PPR granularity may not be known, in which case it is not present.
 */
typedef enum {
	SPD_PPR_F_HARD_PPR		= 1 << 0,
	SPD_PPR_F_SOFT_PPR		= 1 << 1,
	SPD_PPR_F_MBIST_PPR		= 1 << 2,
	SPD_PPR_F_PPR_UNDO		= 1 << 3
} spd_ppr_flags_t;

typedef enum {
	SPD_PPR_GRAN_BANK_GROUP,
	SPD_PPR_GRAN_BANK
} spd_ppr_gran_t;
#define	SPD_KEY_PPR		"dram.ppr-flags"	/* uint32_t (enum) */
#define	SPD_KEY_PPR_GRAN	"dram.ppr-gran"		/* uint32_t (enum) */

/*
 * Voltages in mV. This is an array of nominal voltages that are supported. DDR3
 * defines multiple voltages, but DDR4 and DDR5 only have a single voltage
 * (specific to the supply). DDR3 and DDR4 only defined V~DD~ in SPD. While
 * V~DQ~ and V~PP~ are defined in DDR5.
 */
#define	SPD_KEY_NOM_VDD		"dram.nominal-vdd"	/* uint32_t[] */
#define	SPD_KEY_NOM_VDDQ	"dram.nominal-vddq"	/* uint32_t[] */
#define	SPD_KEY_NOM_VPP		"dram.nominal-vpp"	/* uint32_t[] */

/*
 * DRAM module organization.
 *
 * This describes the number of ranks that exist on a per-channel basis. In
 * DDR4, there is only one channel and so this effectively covers the entire
 * module. In DDR5 and LPDDR there are multiple channels or sub-channels. The
 * rank mix may be symmetrical or asymmetrical. A key will be set if that's the
 * case.
 */
#define	SPD_KEY_RANK_ASYM	"dram.asymmetrical-ranks"	/* key */
#define	SPD_KEY_NRANKS		"channel.num-ranks"	/* uint32_t */

/*
 * DRAM and Module/Channel widths.
 *
 * A 'channel' refers to the entire interface between a memory
 * controller and memory. In DDR4 there is only a single channel that covers the
 * entire 72-bit (64-bit data, 8-bit ECC) bus. In DDR5 and LPDDR5 this is made
 * up of a pair of sub-channels. In LPDDR3/4 the device exposed a number of
 * channels, that are effecitvely similar in spirit to the DDR5 sub-channel. The
 * channel keys below cover whatever the smallest defined unit is. For DDR4 (and
 * earlier) this is the entire channel. For LPDDR3/4 these are the independent
 * channels in the SPD spec and for DDR5 and LPDDR5 these are sub-channels. The
 * channel width is split between a primary data and ECC size.
 *
 * In LPDDR3/4 a given DRAM die may support a varying number of channels. That
 * is stored in the num-channels calculation and otherwise set to 1 for all
 * other types of memory.
 *
 * Separately the individual DRAM dies themselves have a width which is
 * SPD_KEY_DRAM_WIDTH. This is the portion of each die that contributes to the
 * given channel.
 */
#define	SPD_KEY_DRAM_WIDTH	"dram.width"		/* uint32_t */
#define	SPD_KEY_SEC_DRAM_WIDTH	"dram.sec-width"	/* uint32_t */
#define	SPD_KEY_DRAM_NCHAN	"dram.num-channels"	/* uint32_t */
#define	SPD_KEY_NSUBCHAN	"module.num-subchan"	/* uint32_t */
#define	SPD_KEY_DATA_WIDTH	"channel.data-width"	/* uint32_t */
#define	SPD_KEY_ECC_WIDTH	"channel.ecc-width"	/* uint32_t */

/*
 * LPDDR offers a notion of a 'byte mode' where half of the I/Os can be shared
 * between multiple dies. This key is set when tihs is true.
 */
#define	SPD_KEY_LP_BYTE_MODE	"lp.byte-mode"	/* key */

/*
 * LPDDR3-5 have a signal loading matrix that indicates the amount of load that
 * is on different groups of signals. All values are a uint32_t of the count of
 * loads.
 */
#define	SPD_KEY_LP_LOAD_DSM	"lp.load-data-strobe-mask"
#define	SPD_KEY_LP_LOAD_CAC	"lp.load-command-address-clock"
#define	SPD_KEY_LP_LOAD_CS	"lp.load-chip-select"

/*
 * DDR3, DDR4, and LPDDR3-5/x specify specific timebases in the SPD data. DDR5
 * just requires a specific timebase and therefore does not define these keys.
 * This like all other time values is explicitly in ps.
 */
#define	SPD_KEY_MTB	"dram.median-time-base"		/* uint32_t */
#define	SPD_KEY_FTB	"dram.fine-time-base"		/* uint32_t */

/*
 * Supported CAS Latencies. This is an array of integers to indicate which index
 * CAS latencies are possible.
 */
#define	SPD_KEY_CAS	"dram.cas-latencies"		/* uint32_t [] */

/*
 * Time parameters. These are all in picoseconds. All values are uint64_t.
 */
#define	SPD_KEY_TCKAVG_MIN	"dram.t~CKAVG~min"
#define	SPD_KEY_TCKAVG_MAX	"dram.t~CKAVG~max"
#define	SPD_KEY_TAA_MIN		"dram.t~AA~min"
#define	SPD_KEY_TRCD_MIN	"dram.t~RCD~min"
#define	SPD_KEY_TRP_MIN		"dram.t~RP~min"
#define	SPD_KEY_TRAS_MIN	"dram.t~RAS~min"
#define	SPD_KEY_TRC_MIN		"dram.t~RC~min"
#define	SPD_KEY_TRFC1_MIN	"dram.t~RFC1~min"
#define	SPD_KEY_TRFC2_MIN	"dram.t~RFC2~min"
#define	SPD_KEY_TFAW		"dram.t~FAW~"
#define	SPD_KEY_TRRD_L_MIN	"dram.t~RRD_L~min"
#define	SPD_KEY_TCCD_L_MIN	"dram.t~CCD_S~min"
#define	SPD_KEY_TWR_MIN		"dram.t~WR~min"

/*
 * The following time are only used in DDR4. While some of the DDR4 and DDR5
 * write to read or write to write parameters are similar, because they use
 * different names for times, we distinguish them as different values.
 */
#define	SPD_KEY_TRFC4_MIN	"dram.t~RFC4~min"
#define	SPD_KEY_TRRD_S_MIN	"dram.t~RRD_S~min"
#define	SPD_KEY_TWTRS_MIN	"dram.t~WTR_S~min"
#define	SPD_KEY_TWTRL_MIN	"dram.t~WTR_L~min"

/*
 * The following times are specific to DDR5. t~CCD_L_WTR~ in DDR5 is the
 * equivalent to t~WTRS_L~min, same with t~CCD_S_WTR~.
 */
#define	SPD_KEY_TCCDLWR		"dram.t~CCD_L_WR"
#define	SPD_KEY_TCCDLWR2	"dram.t~CCD_L_WR2"
#define	SPD_KEY_TCCDLWTR	"dram.t~CCD_L_WTR"
#define	SPD_KEY_TCCDSWTR	"dram.t~CCD_S_WTR"
#define	SPD_KEY_TRTP		"dram.t~RTP~"
#define	SPD_KEY_TCCDM		"dram.t~CCD_M~"
#define	SPD_KEY_TCCDMWR		"dram.t~CCD_M_WR~"
#define	SPD_KEY_TCCDMWTR	"dram.t~CCD_M_WTR~"

/*
 * While prior DDR standards did have minimum clock times for certain
 * activities, these were first added to the SPD data in DDR5. All values for
 * these are uint32_t's and are in clock cycles.
 */
#define	SPD_KEY_TRRD_L_NCK	"dram.t~RRD_L~nCK"
#define	SPD_KEY_TCCD_L_NCK	"dram.t~CCD_L~nCK"
#define	SPD_KEY_TCCDLWR_NCK	"dram.t~CCD_L_WR~nCK"
#define	SPD_KEY_TCCDLWR2_NCK	"dram.t~CCD_L_WR2~nCK"
#define	SPD_KEY_TFAW_NCK	"dram.t~FAW~nCK"
#define	SPD_KEY_TCCDLWTR_NCK	"dram.t~CCD_L_WTR~nCK"
#define	SPD_KEY_TCCDSWTR_NCK	"dram.t~CCD_S_WTR~nCK"
#define	SPD_KEY_TRTP_NCK	"dram.t~RTP~nCK"
#define	SPD_KEY_TCCDM_NCK	"dram.t~CCD_M~nCK"
#define	SPD_KEY_TCCDMWR_NCK	"dram.t~CCD_M_WR~nCK"
#define	SPD_KEY_TCCDMWTR_NCK	"dram.t~CCD_M_WTR~nCK"

/*
 * The following times are only used in DDR5. The RFCx_dlr values are for 3DS
 * RDIMMs.
 */
#define	SPD_KEY_TRFCSB		"dram.t~RFCsb~"
#define	SPD_KEY_TRFC1_DLR	"dram.3ds-t~RFC1_dlr~"
#define	SPD_KEY_TRFC2_DLR	"dram.3ds-t~RFC2_dlr~"
#define	SPD_KEY_TRFCSB_DLR	"dram.3ds-t~RFCsb_dlr~"

/*
 * The following times are only used by LPDDR3-5, but like other variable timing
 * entries, we still use the "dram" prefix. These are per-bank and all bank row
 * precharges and minimum refresh recovery times.
 */
#define	SPD_KEY_TRPAB_MIN	"dram.t~RPab~"
#define	SPD_KEY_TRPPB_MIN	"dram.t~RPpb~"
#define	SPD_KEY_TRFCAB_MIN	"dram.t~RFCab~"
#define	SPD_KEY_TRFCPB_MIN	"dram.t~RFCpb~"

/*
 * These refer to the maximum activate window and the maximum activate count. In
 * cases where the MAC is unknown no key will be present. This was present in
 * DDR and LPDDR 3 and 4. It is no longer present in DDR and LPDDR4 5 and
 * therefore will not be present for those.
 */
#define	SPD_KEY_MAW	"dram.maw"		/* uint32_t */
#define	SPD_KEY_MAC	"dram.mac"		/* uint32_t */
#define	SPD_KEY_MAC_UNLIMITED	UINT32_MAX

/*
 * LPDDR3/4/4X have specific latency sets. The following enum, stored as a u32
 * contains these options.
 */
typedef enum {
	SPD_LP_RWLAT_WRITE_A	= 1 << 0,
	SPD_LP_RWLAT_WRITE_B	= 1 << 1,
	SPD_LP_RWLAT_DBIRD_EN	= 1 << 2
} spd_lp_rwlat_t;
#define	SPD_KEY_LP_RWLAT	"lp.read-write-latency"	/* uint32_t */

/*
 * Partial Automatic self-refresh (PASR) was introduced in DDR3 and continued in
 * DDR5. Automatic self-refresh (ASR) was only in DDR3. We treat it as a part of
 * the other DDR3 assorted features. The last DDR3 specific thing is the
 * extended temperature fresh rate.
 */
#define	SPD_KEY_DDR_PASR	"dram.pasr"		/* key */
typedef enum {
	SPD_DDR3_FEAT_ASR	= 1 << 0,
	SPD_DDR3_FEAT_DLL_OFF	= 1 << 1,
	SPD_DDR3_FEAT_RZQ_7	= 1 << 2,
	SPD_DDR3_FEAT_RZQ_6	= 1 << 3
} spd_ddr3_feat_t;
#define	SPD_KEY_DDR3_FEAT	"ddr3.asr"		/* uint32_t */
#define	SPD_KEY_DDR3_XTRR	"ddr3.xt-refresh-rate"	/* uint32_t */

/*
 * The following are DDR5 specific properties. BL32 indicates whether burst
 * length 32 mode is supported, which is a key. Along with the partial array
 * self refresh. The Duty Cycle Adjuster is an enumeration because there are
 * multiple modes. The wide temperature sensing is another DDR5 bit represented
 * as a key as well as an enum of fault handling.
 */
#define	SPD_KEY_DDR5_BL32	"ddr5.bl32"		/* key */
typedef enum {
	SPD_DCA_UNSPPORTED,
	SPD_DCA_1_OR_2_PHASE,
	SPD_DCA_4_PHASE
} spd_dca_t;
#define	SPD_KEY_DDR5_DCA	"ddr5.dca"		/* uint32_t */
#define	SPD_KEY_DDR5_WIDE_TS	"ddr5.wide-temp-sense"	/* key */
typedef enum {
	SPD_FLT_BOUNDED		= 1 << 0,
	SPD_FLT_WRSUP_MR9	= 1 << 1,
	SPD_FLT_WRSUP_MR15	= 1 << 2
} spd_fault_t;
#define	SPD_KEY_DDR5_FLT	"ddr5.fault-handling"	/* uint32_t */

/*
 * DDR5 allows for non-standard core timing options. This is indicated by a
 * single key that acts as a flag.
 */
#define	SPD_KEY_DDR5_NONSTD_TIME	"ddr5.non-standard-timing" /* key */

/*
 * DDR5 adds information about refresh management. This is split into
 * information about general refresh management and then optional adaptive
 * refresh management. There are three levels of adaptive refresh management
 * titled A, B, and C. Both the general refresh management and the adaptive
 * refresh management exist for both the primary and secondary types in
 * asymmetrical modules. Information about the RAAIMT and RAAMMT is only present
 * if refresh management is required. Similarly, BRC information is only present
 * if DRFM is supported. All values here are uint32_t's.
 */
typedef enum {
	SPD_RFM_F_REQUIRED	= 1 << 0,
	SPD_RFM_F_DRFM_SUP	= 1 << 1,
} spd_rfm_flags_t;
#define	SPD_KEY_DDR5_RFM_FLAGS_PRI	"ddr5.rfm.flags"
#define	SPD_KEY_DDR5_RFM_RAAIMT_PRI	"ddr5.rfm.raaimt"
#define	SPD_KEY_DDR5_RFM_RAAIMT_FGR_PRI	"ddr5.rfm.raaimt-fgr"
#define	SPD_KEY_DDR5_RFM_RAAMMT_PRI	"ddr5.rfm.raammt"
#define	SPD_KEY_DDR5_RFM_RAAMMT_FGR_PRI	"ddr5.rfm.raammt-fgr"
#define	SPD_KEY_DDR5_RFM_BRC_CFG_PRI	"ddr5.rfm.brc-config"

typedef enum {
	SPD_BRC_F_LVL_2		= 1 << 0,
	SPD_BRC_F_LVL_3		= 1 << 1,
	SPD_BRC_F_LVL_4		= 1 << 2
} spd_brc_flags_t;
#define	SPD_KEY_DDR5_RFM_BRC_SUP_PRI	"ddr5.rfm.brc-level"
#define	SPD_KEY_DDR5_RFM_RAA_DEC_PRI	"ddr5.rfm.raa-dec"
#define	SPD_KEY_DDR5_RFM_FLAGS_SEC	"ddr5.rfm.sec-flags"
#define	SPD_KEY_DDR5_RFM_RAAIMT_SEC	"ddr5.rfm.sec-raaimt"
#define	SPD_KEY_DDR5_RFM_RAAIMT_FGR_SEC	"ddr5.rfm.sec-raaimt-fgr"
#define	SPD_KEY_DDR5_RFM_RAAMMT_SEC	"ddr5.rfm.sec-raammt"
#define	SPD_KEY_DDR5_RFM_RAAMMT_FGR_SEC	"ddr5.rfm.sec-raammt-fgr"
#define	SPD_KEY_DDR5_RFM_BRC_CFG_SEC	"ddr5.rfm.sec-brc-config"
#define	SPD_KEY_DDR5_RFM_BRC_SUP_SEC	"ddr5.rfm.sec-brc-level"
#define	SPD_KEY_DDR5_RFM_RAA_DEC_SEC	"ddr5.rfm.sec-raa-dec"

#define	SPD_KEY_DDR5_ARFMA_FLAGS_PRI		"ddr5.arfm-a.flags"
#define	SPD_KEY_DDR5_ARFMA_RAAIMT_PRI		"ddr5.arfm-a.raaimt"
#define	SPD_KEY_DDR5_ARFMA_RAAIMT_FGR_PRI	"ddr5.arfm-a.raaimt-fgr"
#define	SPD_KEY_DDR5_ARFMA_RAAMMT_PRI		"ddr5.arfm-a.raammt"
#define	SPD_KEY_DDR5_ARFMA_RAAMMT_FGR_PRI	"ddr5.arfm-a.raammt-fgr"
#define	SPD_KEY_DDR5_ARFMA_BRC_CFG_PRI		"ddr5.arfm-a.brc-config"
#define	SPD_KEY_DDR5_ARFMA_BRC_SUP_PRI		"ddr5.arfm-a.brc-level"
#define	SPD_KEY_DDR5_ARFMA_RAA_DEC_PRI		"ddr5.arfm-a.raa-dec"
#define	SPD_KEY_DDR5_ARFMA_FLAGS_SEC		"ddr5.arfm-a.sec-flags"
#define	SPD_KEY_DDR5_ARFMA_RAAIMT_SEC		"ddr5.arfm-a.sec-raaimt"
#define	SPD_KEY_DDR5_ARFMA_RAAIMT_FGR_SEC	"ddr5.arfm-a.sec-raaimt-fgr"
#define	SPD_KEY_DDR5_ARFMA_RAAMMT_SEC		"ddr5.arfm-a.sec-raammt"
#define	SPD_KEY_DDR5_ARFMA_RAAMMT_FGR_SEC	"ddr5.arfm-a.sec-raammt-fgr"
#define	SPD_KEY_DDR5_ARFMA_BRC_CFG_SEC		"ddr5.arfm-a.sec-brc-config"
#define	SPD_KEY_DDR5_ARFMA_BRC_SUP_SEC		"ddr5.arfm-a.sec-brc-level"
#define	SPD_KEY_DDR5_ARFMA_RAA_DEC_SEC		"ddr5.arfm-a.sec-raa-dec"

#define	SPD_KEY_DDR5_ARFMB_FLAGS_PRI		"ddr5.arfm-b.flags"
#define	SPD_KEY_DDR5_ARFMB_RAAIMT_PRI		"ddr5.arfm-b.raaimt"
#define	SPD_KEY_DDR5_ARFMB_RAAIMT_FGR_PRI	"ddr5.arfm-b.raaimt-fgr"
#define	SPD_KEY_DDR5_ARFMB_RAAMMT_PRI		"ddr5.arfm-b.raammt"
#define	SPD_KEY_DDR5_ARFMB_RAAMMT_FGR_PRI	"ddr5.arfm-b.raammt-fgr"
#define	SPD_KEY_DDR5_ARFMB_BRC_CFG_PRI		"ddr5.arfm-b.brc-config"
#define	SPD_KEY_DDR5_ARFMB_BRC_SUP_PRI		"ddr5.arfm-b.brc-level"
#define	SPD_KEY_DDR5_ARFMB_RAA_DEC_PRI		"ddr5.arfm-b.raa-dec"
#define	SPD_KEY_DDR5_ARFMB_FLAGS_SEC		"ddr5.arfm-b.sec-flags"
#define	SPD_KEY_DDR5_ARFMB_RAAIMT_SEC		"ddr5.arfm-b.sec-raaimt"
#define	SPD_KEY_DDR5_ARFMB_RAAIMT_FGR_SEC	"ddr5.arfm-b.sec-raaimt-fgr"
#define	SPD_KEY_DDR5_ARFMB_RAAMMT_SEC		"ddr5.arfm-b.sec-raammt"
#define	SPD_KEY_DDR5_ARFMB_RAAMMT_FGR_SEC	"ddr5.arfm-b.sec-raammt-fgr"
#define	SPD_KEY_DDR5_ARFMB_BRC_CFG_SEC		"ddr5.arfm-b.sec-brc-config"
#define	SPD_KEY_DDR5_ARFMB_BRC_SUP_SEC		"ddr5.arfm-b.sec-brc-level"
#define	SPD_KEY_DDR5_ARFMB_RAA_DEC_SEC		"ddr5.arfm-b.sec-raa-dec"

#define	SPD_KEY_DDR5_ARFMC_FLAGS_PRI		"ddr5.arfm-c.flags"
#define	SPD_KEY_DDR5_ARFMC_RAAIMT_PRI		"ddr5.arfm-c.raaimt"
#define	SPD_KEY_DDR5_ARFMC_RAAIMT_FGR_PRI	"ddr5.arfm-c.raaimt-fgr"
#define	SPD_KEY_DDR5_ARFMC_RAAMMT_PRI		"ddr5.arfm-c.raammt"
#define	SPD_KEY_DDR5_ARFMC_RAAMMT_FGR_PRI	"ddr5.arfm-c.raammt-fgr"
#define	SPD_KEY_DDR5_ARFMC_BRC_CFG_PRI		"ddr5.arfm-c.brc-config"
#define	SPD_KEY_DDR5_ARFMC_BRC_SUP_PRI		"ddr5.arfm-c.brc-level"
#define	SPD_KEY_DDR5_ARFMC_RAA_DEC_PRI		"ddr5.arfm-c.raa-dec"
#define	SPD_KEY_DDR5_ARFMC_FLAGS_SEC		"ddr5.arfm-c.sec-flags"
#define	SPD_KEY_DDR5_ARFMC_RAAIMT_SEC		"ddr5.arfm-c.sec-raaimt"
#define	SPD_KEY_DDR5_ARFMC_RAAIMT_FGR_SEC	"ddr5.arfm-c.sec-raaimt-fgr"
#define	SPD_KEY_DDR5_ARFMC_RAAMMT_SEC		"ddr5.arfm-c.sec-raammt"
#define	SPD_KEY_DDR5_ARFMC_RAAMMT_FGR_SEC	"ddr5.arfm-c.sec-raammt-fgr"
#define	SPD_KEY_DDR5_ARFMC_BRC_CFG_SEC		"ddr5.arfm-c.sec-brc-config"
#define	SPD_KEY_DDR5_ARFMC_BRC_SUP_SEC		"ddr5.arfm-c.sec-brc-level"
#define	SPD_KEY_DDR5_ARFMC_RAA_DEC_SEC		"ddr5.arfm-c.sec-raa-dec"
/*
 * Module-type specific keys and values. These are often the intersection of
 * both the DDR standard and the module type. That is, a DDR4 and DDR5 RDIMM
 * expose some information that isn't quite the same. These often contain things
 * that are drive strengths and slew rates. These kinds of items fall into two
 * categories. Ones where there is a fixed resistance and one where there is a
 * qualitative range that depends on things like the specific parts present.
 */
typedef enum {
	SPD_DRIVE_LIGHT,
	SPD_DRIVE_MODERATE,
	SPD_DRIVE_STRONG,
	SPD_DRIVE_VERY_STRONG,
	SPD_DRIVE_WEAK
} spd_drive_t;

typedef enum {
	SPD_SLEW_SLOW,
	SPD_SLEW_MODERATE,
	SPD_SLEW_FAST
} spd_slew_t;

/*
 * DDR4 RDIMM and LRDIMM drive strengths. These all use the spd_drive_t. These
 * are all on the RCD. There is also a key for whether or not slew-control is
 * supported.
 *
 * DDR3 has similar, but not identical drive strengths. Rather than trying to
 * combine them awkwardly, we just have a separate set of definitions. These may
 * be made more uniform in the future. In DDR3 the LRDIMM does not incorporate a
 * register like in DDR4, therefore the MB has overlapping drive strength keys.
 */
#define	SPD_KEY_DDR3_RCD_DS_CAA	"ddr3.rcd.ca-a-drive-strength"
#define	SPD_KEY_DDR3_RCD_DS_CAB	"ddr3.rcd.ca-b-drive-strength"
#define	SPD_KEY_DDR3_RCD_DS_CTLA	"ddr3.rcd.cs-a-drive-strength"
#define	SPD_KEY_DDR3_RCD_DS_CTLB	"ddr3.rcd.cs-b-drive-strength"
#define	SPD_KEY_DDR3_RCD_DS_Y0	"ddr3.rcd.y0-drive-strength"
#define	SPD_KEY_DDR3_RCD_DS_Y1	"ddr3.rcd.y1-drive-strength"

#define	SPD_KEY_DDR3_MB_DS_Y0	"ddr3.mb.y0-drive-strength"
#define	SPD_KEY_DDR3_MB_DS_Y1	"ddr3.mb.y1-drive-strength"
#define	SPD_KEY_DDR3_MB_DS_CKE	"ddr3.mb.cke-drive-strength"
#define	SPD_KEY_DDR3_MB_DS_ODT	"ddr3.mb.cke-drive-strength"
#define	SPD_KEY_DDR3_MB_DS_CS	"ddr3.mb.cs-drive-strength"
#define	SPD_KEY_DDR3_MB_DS_CA	"ddr3.mb.ca-drive-strength"

#define	SPD_KEY_DDR4_RCD_SLEW	"ddr4.rcd.rcd-slew-control"	/* key */
#define	SPD_KEY_DDR4_RCD_DS_CKE	"ddr4.rcd.cke-drive-strength"
#define	SPD_KEY_DDR4_RCD_DS_ODT	"ddr4.rcd.odt-drive-strength"
#define	SPD_KEY_DDR4_RCD_DS_CA	"ddr4.rcd.ca-drive-strength"
#define	SPD_KEY_DDR4_RCD_DS_CS	"ddr4.rcd.cs-drive-strength"
#define	SPD_KEY_DDR4_RCD_DS_Y0	"ddr4.rcd.y0-drive-strength"
#define	SPD_KEY_DDR4_RCD_DS_Y1	"ddr4.rcd.y1-drive-strength"
#define	SPD_KEY_DDR4_RCD_DS_BCOM	"ddr4.rcd.bcom-drive-strength"
#define	SPD_KEY_DDR4_RCD_DS_BCK	"ddr4.rcd.bck-drive-strength"

/*
 * DDR3 LRDIMMs have the ability to specify the orientation of the memory
 * buffer. These describe the physical orientation relative to the edge
 * connector.
 */
typedef enum {
	SPD_ORNT_HORIZONTAL,
	SPD_ORNT_VERTICAL
} spd_orientation_t;
#define	SPD_KEY_DDR3_MB_ORIENT	"ddr3.mb.orientation"		/* uint32_t */

/*
 * DDR3 LRDIMMs have various extended and additive clock delays for various
 * signals. The extended delay is x/128 * tCK while the additive delay is x/32 *
 * tCK. We store these all as uint32_t keys where the value is the value of x
 * above. If there is no delay or the delay is not enabled, then the key will
 * not exist.
 */
#define	SPD_KEY_DDR3_MB_EXTD_Y		"ddr4.mb.y-extended-delay"
#define	SPD_KEY_DDR3_MB_EXTD_CS		"ddr4.mb.cs-extended-delay"
#define	SPD_KEY_DDR3_MB_EXTD_ODT	"ddr4.mb.odt-extended-delay"
#define	SPD_KEY_DDR3_MB_EXTD_CKE	"ddr4.mb.cke-extended-delay"
#define	SPD_KEY_DDR3_MB_ADDD_Y		"ddr4.mb.y-additive-delay"
#define	SPD_KEY_DDR3_MB_ADDD_CS		"ddr4.mb.cs-additive-delay"
#define	SPD_KEY_DDR3_MB_ADDD_ODT	"ddr4.mb.odt-additive-delay"
#define	SPD_KEY_DDR3_MB_ADDD_CKE	"ddr4.mb.cke-additive-delay"

/*
 * DDR3 LRDIMMs have the ability to control whether or not QxODT[1:0] is
 * asserted during reads or writes on each rank. There is a value for each of
 * the three primary speed buckets in DDR3: 800/1066, 1333/1600, and
 * 1866/2133. This is organized as a series of boolean_t[3] entries where each
 * entry corresponds to one of the three speeds.
 */
#define	SPD_KEY_DDR3_MB_R0_ODT0_RD	"ddr3.mb.r0-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R0_ODT1_RD	"ddr3.mb.r0-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R0_ODT0_WR	"ddr3.mb.r0-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R0_ODT1_WR	"ddr3.mb.r0-qxodt1-write-assert"
#define	SPD_KEY_DDR3_MB_R1_ODT0_RD	"ddr3.mb.r1-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R1_ODT1_RD	"ddr3.mb.r1-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R1_ODT0_WR	"ddr3.mb.r1-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R1_ODT1_WR	"ddr3.mb.r1-qxodt1-write-assert"
#define	SPD_KEY_DDR3_MB_R2_ODT0_RD	"ddr3.mb.r2-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R2_ODT1_RD	"ddr3.mb.r2-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R2_ODT0_WR	"ddr3.mb.r2-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R2_ODT1_WR	"ddr3.mb.r2-qxodt1-write-assert"
#define	SPD_KEY_DDR3_MB_R3_ODT0_RD	"ddr3.mb.r3-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R3_ODT1_RD	"ddr3.mb.r3-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R3_ODT0_WR	"ddr3.mb.r3-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R3_ODT1_WR	"ddr3.mb.r3-qxodt1-write-assert"
#define	SPD_KEY_DDR3_MB_R4_ODT0_RD	"ddr3.mb.r4-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R4_ODT1_RD	"ddr3.mb.r4-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R4_ODT0_WR	"ddr3.mb.r4-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R4_ODT1_WR	"ddr3.mb.r4-qxodt1-write-assert"
#define	SPD_KEY_DDR3_MB_R5_ODT0_RD	"ddr3.mb.r5-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R5_ODT1_RD	"ddr3.mb.r5-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R5_ODT0_WR	"ddr3.mb.r5-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R5_ODT1_WR	"ddr3.mb.r5-qxodt1-write-assert"
#define	SPD_KEY_DDR3_MB_R6_ODT0_RD	"ddr3.mb.r6-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R6_ODT1_RD	"ddr3.mb.r6-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R6_ODT0_WR	"ddr3.mb.r6-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R6_ODT1_WR	"ddr3.mb.r6-qxodt1-write-assert"
#define	SPD_KEY_DDR3_MB_R7_ODT0_RD	"ddr3.mb.r7-qxodt0-read-assert"
#define	SPD_KEY_DDR3_MB_R7_ODT1_RD	"ddr3.mb.r7-qxodt1-read-assert"
#define	SPD_KEY_DDR3_MB_R7_ODT0_WR	"ddr3.mb.r7-qxodt0-write-assert"
#define	SPD_KEY_DDR3_MB_R7_ODT1_WR	"ddr3.mb.r7-qxodt1-write-assert"

/*
 * DDR4 LRDIMMs specify the VrefDQ for each package rank. These are communicated
 * in terms of the DDR4 spec which specifies them as a percentage of the actual
 * voltage. This is always phrased in the spec as AB.CD%, so for example 60.25%.
 * We treat this percentage as a four digit unsigned value rather than trying to
 * play games with whether or not the value can be represented in floating
 * point. Divide the value by 100 to get the percentage. That is, 47.60% will be
 * encoded as 4760. All of these values are a uint32_t.
 */
#define	SPD_KEY_DDR4_VREFDQ_R0	"ddr4.lrdimm.VrefDQ-rank0"
#define	SPD_KEY_DDR4_VREFDQ_R1	"ddr4.lrdimm.VrefDQ-rank1"
#define	SPD_KEY_DDR4_VREFDQ_R2	"ddr4.lrdimm.VrefDQ-rank2"
#define	SPD_KEY_DDR4_VREFDQ_R3	"ddr4.lrdimm.VrefDQ-rank3"
#define	SPD_KEY_DDR4_VREFDQ_DB	"ddr4.lrdimm.VrefDQ-db"

/*
 * DDR4 LRDIMMs define the data buffer drive strength and termination in terms
 * of various data rate ranges. Specifically (0, 1866], (1866, 2400], and (2400,
 * 3200]. All of these values are measured in terms of Ohms. As such, all of
 * these values are an array of three uint32_t's whose values correspond to each
 * of those ranges. We define a few additional values for these to represent
 * cases where they are disabled or high-impedance.
 *
 * DDR3 LRDIMMs are similar, but their groups are 800/1066, 1333/1600, and
 * 1866/2133.
 */
#define	SPD_TERM_DISABLED	0
#define	SPD_TERM_HIZ		UINT32_MAX
#define	SPD_KEY_DDR4_MDQ_RTT	"ddr4.lrdimm.mdq-read-termination"
#define	SPD_KEY_DDR4_MDQ_DS	"ddr4.lrdimm.mdq-drive-strength"
#define	SPD_KEY_DDR4_DRAM_DS	"ddr4.lrdimm.dram-drive-strength"
#define	SPD_KEY_DDR4_RTT_WR	"ddr4.lrdimm.odt-read-termination-wr"
#define	SPD_KEY_DDR4_RTT_NOM	"ddr4.lrdimm.odt-read-termination-nom"
#define	SPD_KEY_DDR4_RTT_PARK_R0	"ddr4.lrdimm.odt-r0_1-rtt-park"
#define	SPD_KEY_DDR4_RTT_PARK_R2	"ddr4.lrdimm.odt-r2_3-rtt-park"

#define	SPD_KEY_DDR3_MDQ_DS	"ddr3.lrdimm.mdq-drive-strength"
#define	SPD_KEY_DDR3_MDQ_ODT	"ddr3.lrdimm.mdq-odt-strength"
#define	SPD_KEY_DDR3_RTT_WRT	"ddr3.lrdimm.mdq-odt-read-termination-wr"
#define	SPD_KEY_DDR3_RTT_NOM	"ddr3.lrdimm.mdq-odt-read-termination-nom"
#define	SPD_KEY_DDR3_DRAM_DS	"ddr3.lrdimm.dram-drive-strength"

/*
 * DDR3 LRDIMMs specify a minimum and maximum delay for the various supported
 * voltage types. These are stored as two uint64_t[3] arrays ordered as 1.25,
 * 1.35, and 1.5V. These are times in ps.
 */
#define	SPD_KEY_DDR3_MOD_MIN_DELAY	"ddr3.lrdimm.minimum-module-delay"
#define	SPD_KEY_DDR3_MOD_MAX_DELAY	"ddr3.lrdimm.maximum-module-delay"

/*
 * DDR3 LRDIMMs also have personality bytes that are loaded directly into the
 * memory buffer control words. We pass these through as a uint8_t[15].
 */
#define	SPD_KEY_DDR3_MB_PERS	"ddr3.lrdimm.personality"

/*
 * The last DDR4 LRDIMM specific component is whether or not the data buffer's
 * gain and decision feedback equalization are supported. These both are keys.
 */
#define	SPD_KEY_DDR4_DB_GAIN	"ddr4.lrdimm.db-gain-adjustment"
#define	SPD_KEY_DDR4_DB_DFE	"ddr4.lrdimm.decision-feedback-eq"

/*
 * DDR5 RDIMMs and LRDIMMs have specific enables for groups of pins. There are
 * then drive strength values which are encoded as a spd_drive_t. Note, prior to
 * DDR5 RDIMMs v1.1, these were differential impedance values measured in Ohms.
 * These have been normalized to the general drive strength enums. Separately
 * there are slew rates, those use the spd_slew_t. Because these use different
 * units between DDR4 and DDR5, we treat them as different keys.
 */
#define	SPD_KEY_DDR5_RCD_QACK_EN	"ddr5.rcd.qack-enabled"
#define	SPD_KEY_DDR5_RCD_QBCK_EN	"ddr5.rcd.qbck-enabled"
#define	SPD_KEY_DDR5_RCD_QCCK_EN	"ddr5.rcd.qcck-enabled"
#define	SPD_KEY_DDR5_RCD_QDCK_EN	"ddr5.rcd.qdck-enabled"
#define	SPD_KEY_DDR5_RCD_BCK_EN		"ddr5.rcd.bck-enabled"
#define	SPD_KEY_DDR5_RCD_QACA_EN	"ddr5.rcd.qaca-enabled"
#define	SPD_KEY_DDR5_RCD_QBCA_EN	"ddr5.rcd.qbca-enabled"
#define	SPD_KEY_DDR5_RCD_QxCS_EN	"ddr5.rcd.qxcs-enabled"
#define	SPD_KEY_DDR5_RCD_QxCA13_EN	"ddr5.rcd.qxca13-enabled"
#define	SPD_KEY_DDR5_RCD_QACS_EN	"ddr5.rcd.qacs-enabled"
#define	SPD_KEY_DDR5_RCD_QBCS_EN	"ddr5.rcd.qbcs-enabled"

/* Drive strengths use the spd_drive_t encoded as a uint32_t */
#define	SPD_KEY_DDR5_RCD_QACK_DS	"ddr5.rcd.qack-drive-strength"
#define	SPD_KEY_DDR5_RCD_QBCK_DS	"ddr5.rcd.qbck-drive-strength"
#define	SPD_KEY_DDR5_RCD_QCCK_DS	"ddr5.rcd.qcck-drive-strength"
#define	SPD_KEY_DDR5_RCD_QDCK_DS	"ddr5.rcd.qdck-drive-strength"
#define	SPD_KEY_DDR5_RCD_QxCS_DS	"ddr5.rcd.qxcs-drive-strength"
#define	SPD_KEY_DDR5_RCD_CA_DS		"ddr5.rcd.ca-drive-strength"

/* Slew rates use the spd_rate_t encoded as a uint32_t */
#define	SPD_KEY_DDR5_RCD_QCK_SLEW	"ddr5.rcd.qck-slew"
#define	SPD_KEY_DDR5_RCD_QCA_SLEW	"ddr5.rcd.qca-slew"
#define	SPD_KEY_DDR5_RCD_QCS_SLEW	"ddr5.rcd.qcs-slew"

/*
 * These are all specific to DDR5 LRDIMMs. The values are the same as above. The
 * RTT value is a value in Ohms. If RTT termination is disabled then the key
 * will not be present.
 */
#define	SPD_KEY_DDR5_RCD_BCS_EN		"ddr5.rcd.bcs-enabled" /* key */
#define	SPD_KEY_DDR5_RCD_BCOM_DS	"ddr5.rcd.bcom-drive-strength"
#define	SPD_KEY_DDR5_RCD_BCK_DS		"ddr5.rcd.bck-drive-strength"
#define	SPD_KEY_DDR5_RCD_RTT_TERM	"ddr5.rcd.dqs-rtt"
#define	SPD_KEY_DDR5_RCD_BCOM_SLEW	"ddr5.rcd.bcom-slew"
#define	SPD_KEY_DDR5_RCD_BCK_SLEW	"ddr5.rcd.bck-slew"

/*
 * DDR5 UDIMM specific values. Note, these are only present in UDIMM v1.1 and
 * therefore may be missing in older revisions.
 */

/*
 * Unbuffered clock configuration, drivers, and slew rates. The various -enabled
 * values are keys. The drive strengths and slew rates use the spd_drive_t and
 * spd_slew_t respectively encoded as uint32_t values.
 */
#define	SPD_KEY_DDR5_CKD_CHAQCK0_EN	"ddr5.ckd.cha-qck0_A-enabled"
#define	SPD_KEY_DDR5_CKD_CHAQCK1_EN	"ddr5.ckd.cha-qck1_A-enabled"
#define	SPD_KEY_DDR5_CKD_CHBQCK0_EN	"ddr5.ckd.chb-qck0_B-enabled"
#define	SPD_KEY_DDR5_CKD_CHBQCK1_EN	"ddr5.ckd.chb-qck1_B-enabled"
#define	SPD_KEY_DDR5_CKD_CHAQCK0_DS	"ddr5.ckd.cha-qck0_A-drive-strength"
#define	SPD_KEY_DDR5_CKD_CHAQCK1_DS	"ddr5.ckd.cha-qck1_A-drive-strength"
#define	SPD_KEY_DDR5_CKD_CHBQCK0_DS	"ddr5.ckd.chb-qck0_B-drive-strength"
#define	SPD_KEY_DDR5_CKD_CHBQCK1_DS	"ddr5.ckd.chb-qck1_B-drive-strength"
#define	SPD_KEY_DDR5_CKD_CHAQCK_SLEW	"ddr5.ckd.cha-qck_slew"
#define	SPD_KEY_DDR5_CKD_CHBQCK_SLEW	"ddr5.ckd.chb-qck_slew"

/*
 * DDR5 MRDIMM specific values. Note, these are only present in MRDIMM v1.1 and
 * therefore may be missing in older revisions. While these values are really
 * similar to the RDIMM variants, because they are taken from the MRCD instead
 * of the RCD specification, we define different keys.
 */
#define	SPD_KEY_DDR5_MRCD_QACK_EN	"ddr5.mrcd.qack-enabled"
#define	SPD_KEY_DDR5_MRCD_QBCK_EN	"ddr5.mrcd.qbck-enabled"
#define	SPD_KEY_DDR5_MRCD_QCCK_EN	"ddr5.mrcd.qcck-enabled"
#define	SPD_KEY_DDR5_MRCD_QDCK_EN	"ddr5.mrcd.qdck-enabled"
#define	SPD_KEY_DDR5_MRCD_BCK_EN	"ddr5.mrcd.bck-enabled"
#define	SPD_KEY_DDR5_MRCD_QACA_EN	"ddr5.mrcd.qaca-enabled"
#define	SPD_KEY_DDR5_MRCD_QBCA_EN	"ddr5.mrcd.qbca-enabled"
#define	SPD_KEY_DDR5_MRCD_BCS_EN	"ddr5.mrcd.bcs-enabled"
#define	SPD_KEY_DDR5_MRCD_QxCS_EN	"ddr5.mrcd.qxcs-enabled"
#define	SPD_KEY_DDR5_MRCD_QxCA13_EN	"ddr5.mrcd.qxca13-enabled"
#define	SPD_KEY_DDR5_MRCD_QACS_EN	"ddr5.mrcd.qacs-enabled"
#define	SPD_KEY_DDR5_MRCD_QBCS_EN	"ddr5.mrcd.qbcs-enabled"
#define	SPD_KEY_DDR5_MRCD_DCS1_EN	"ddr5.mrcd.dcs1-enabled"

/* Drive strengths use the spd_drive_t encoded as a uint32_t */
#define	SPD_KEY_DDR5_MRCD_QACK_DS	"ddr5.mrcd.qack-drive-strength"
#define	SPD_KEY_DDR5_MRCD_QBCK_DS	"ddr5.mrcd.qbck-drive-strength"
#define	SPD_KEY_DDR5_MRCD_QCCK_DS	"ddr5.mrcd.qcck-drive-strength"
#define	SPD_KEY_DDR5_MRCD_QDCK_DS	"ddr5.mrcd.qdck-drive-strength"
#define	SPD_KEY_DDR5_MRCD_QxCS_DS	"ddr5.mrcd.qxcs-drive-strength"
#define	SPD_KEY_DDR5_MRCD_CA_DS		"ddr5.mrcd.ca-drive-strength"
#define	SPD_KEY_DDR5_MRCD_BCOM_DS	"ddr5.mrcd.bcom-drive-strength"
#define	SPD_KEY_DDR5_MRCD_BCK_DS	"ddr5.mrcd.bck-drive-strength"

/* Slew rates use the spd_rate_t encoded as a uint32_t */
#define	SPD_KEY_DDR5_MRCD_QCK_SLEW	"ddr5.mrcd.qck-slew"
#define	SPD_KEY_DDR5_MRCD_QCA_SLEW	"ddr5.mrcd.qca-slew"
#define	SPD_KEY_DDR5_MRCD_QCS_SLEW	"ddr5.mrcd.qcs-slew"
#define	SPD_KEY_DDR5_MRCD_BCOM_SLEW	"ddr5.mrcd.bcom-slew"
#define	SPD_KEY_DDR5_MRCD_BCK_SLEW	"ddr5.mrcd.bck-slew"

typedef enum {
	SPD_MRCD_OUT_NORMAL,
	SPD_MRCD_OUT_DISABLED,
	SPD_MRCD_OUT_LOW
} spd_mrcd_output_ctrl_t;
#define	SPD_KEY_DDR5_MRCD_QxCS_OUT	"ddr5.mrcd.qxcs-output-control"

typedef enum {
	SPD_MRCD_DCA_CFG_0,
	SPD_MRCD_DCA_CFG_1
} spd_mrcd_dca_cfg_t;
#define	SPD_KEY_DDR5_MRCD_DCA_CFG	"ddr5.mrcd.dca-configuration"

typedef enum {
	SPD_MRDIMM_IRXT_UNMATCHED,
	SPD_MRDIMM_IRXT_MATCHED
} spd_mrdimm_irxt_t;
#define	SPD_KEY_DDR5_MRDIMM_IRXT	"ddr5.mrdimm.interface-rx-type"

/*
 * Module Properties. These are items that generally relate to the module as a
 * whole.
 */

/*
 * Connection Mapping. In DDR4 there is the ability to remap groups of pins from
 * the connector to the various package SDRAMs. Every 4 bits can be remapped to
 * either another upper or lower nibble in a package. Separately bits can also
 * be flipped between packages. These exist for all 64-bits of DQ and 8 bits of
 * CBs. If mirroring is set, then a key will be added for that pin group. For
 * each pin group, the mapping to a specific type of rewriting will be done. We
 * conventionally use 0, 1, 2, and 3 as the lower nibble and 4, 5, 6, 7 as the
 * upper nibble, though the actual pins will vary based on where they are.
 */
#define	SPD_KEY_DDR4_MAP_DQ0	"module.dq0-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ4	"module.dq4-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ8	"module.dq8-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ12	"module.dq12-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ16	"module.dq16-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ20	"module.dq20-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ24	"module.dq24-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ28	"module.dq28-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ32	"module.dq32-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ36	"module.dq36-map"	/* uint36_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ40	"module.dq40-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ44	"module.dq44-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ48	"module.dq48-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ52	"module.dq52-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ56	"module.dq56-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_DQ60	"module.dq60-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_CB0	"module.cb0-map"	/* uint32_t [4] */
#define	SPD_KEY_DDR4_MAP_CB4	"module.cb4-map"	/* uint32_t [4] */

/*
 * In addition, there is module level mapping in DDR3/DDR4 that is used to
 * indicate that odd ranks are mirrored. This is between the edge connector and
 * the DRAM itself. We only add a key when it is mirrored.
 */
#define	SPD_KEY_MOD_EDGE_MIRROR	"module.edge-odd-mirror"	/* key */

/*
 * Present devices. Modules often have multiple additional types of devices
 * present like temperature sensors, voltage regulators, registers, etc. The
 * following key indicates what all is present on this DIMM. Depending on the
 * DDR revision, we will then have additional keys with its ID, revision, name,
 * and compliant type. In a few cases we will define the type and presence based
 * on information. For example, DDR4 only allows a single type of temperature
 * sensor or SPD device. Even though we don't know the manufacturer, we will
 * still note this.
 *
 * Each of these items will have four keys. One for the manufacturer ID, one for
 * their string name, one for the device type, and one for the revision. Note,
 * while TS1 and TS2 are both flags in DDR5, they share common manufacturer
 * information, which is why there is only one entry here.
 *
 * For each device type there is a separate enum with supported types of devices
 * that can be present for these.
 */
typedef enum {
	SPD_DEVICE_TEMP_1	= 1 << 0,
	SPD_DEVICE_TEMP_2	= 1 << 1,
	SPD_DEVICE_HS		= 1 << 2,
	SPD_DEVICE_PMIC_0	= 1 << 3,
	SPD_DEVICE_PMIC_1	= 1 << 4,
	SPD_DEVICE_PMIC_2	= 1 << 5,
	SPD_DEVICE_CD_0		= 1 << 6,
	SPD_DEVICE_CD_1		= 1 << 7,
	SPD_DEVICE_RCD		= 1 << 8,
	SPD_DEVICE_DB		= 1 << 9,
	SPD_DEVICE_MRCD		= 1 << 10,
	SPD_DEVICE_MDB		= 1 << 11,
	SPD_DEVICE_DMB		= 1 << 12,
	SPD_DEVICE_SPD		= 1 << 13
} spd_device_t;
#define	SPD_KEY_DEVS		"module.devices"	/* uint32_t */

typedef enum {
	/* DDR3 */
	SPD_TEMP_T_TSE2002,
	/* DDR4 and LPDDR4 */
	SPD_TEMP_T_TSE2004av,
	/* DDR5 */
	SPD_TEMP_T_TS5111,
	SPD_TEMP_T_TS5110,
	SPD_TEMP_T_TS5211,
	SPD_TEMP_T_TS5210
} spd_temp_type_t;

typedef enum {
	/* DDR5 */
	SPD_PMIC_T_PMIC5000,
	SPD_PMIC_T_PMIC5010,
	SPD_PMIC_T_PMIC5100,
	SPD_PMIC_T_PMIC5020,
	SPD_PMIC_T_PMIC5120,
	SPD_PMIC_T_PMIC5200,
	SPD_PMIC_T_PMIC5030
} spd_pmic_type_t;

typedef enum {
	/* DDR5 */
	SPD_CD_T_DDR5CK01
} spd_cd_type_t;

typedef enum {
	/* DDR3 */
	SPD_RCD_T_SSTE32882,
	/* DDR4 */
	SPD_RCD_T_DDR4RCD01,
	SPD_RCD_T_DDR4RCD02,
	/* DDR5 */
	SPD_RCD_T_DDR5RCD01,
	SPD_RCD_T_DDR5RCD02,
	SPD_RCD_T_DDR5RCD03,
	SPD_RCD_T_DDR5RCD04,
	SPD_RCD_T_DDR5RCD05
} spd_rcd_type_t;

typedef enum {
	/* DDR4 */
	SPD_DB_T_DDR4DB01,
	SPD_DB_T_DDR4DB02,
	/* DDR5 */
	SPD_DB_T_DDR5DB01,
	SPD_DB_T_DDR5DB02,
	/*
	 * DDR3 LRDIMMs had a memory buffer that did not have a full
	 * desgination. We count them here.
	 */
	SPD_DB_T_DDR3MB
} spd_db_type_t;

typedef enum {
	/* DDR5 */
	SPD_MRCD_T_DDR5MRCD01,
	SPD_MRCD_T_DDR5MRCD02,
} spd_mrcd_type_t;

typedef enum {
	/* DDR5 */
	SPD_MDB_T_DDR5MDB01,
	SPD_MDB_T_DDR5MDB02
} spd_mdb_type_t;

typedef enum {
	/* DDR5 */
	SPD_DMB_T_DMB5011
} spd_dmb_type_t;

typedef enum {
	/* DDR4 */
	SPD_SPD_T_EE1004,
	/* DDR5 */
	SPD_SPD_T_SPD5118,
	SPD_SPD_T_ESPD5216,
	/* DDR3 */
	SPD_SPD_T_EE1002
} spd_spd_type_t;

#define	SPD_KEY_DEV_TEMP_MFG	"module.temp.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_TEMP_MFG_NAME	"module.temp.mfg-name"	/* string */
#define	SPD_KEY_DEV_TEMP_TYPE	"module.temp.type"	/* uint32_t */
#define	SPD_KEY_DEV_TEMP_REV	"module.temp.revision"	/* string */

#define	SPD_KEY_DEV_PMIC0_MFG	"module.pmic0.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_PMIC0_MFG_NAME	"module.pmic0.mfg-name"	/* string */
#define	SPD_KEY_DEV_PMIC0_TYPE	"module.pmic0.type"	/* uint32_t */
#define	SPD_KEY_DEV_PMIC0_REV	"module.pmic0.revision"	/* string */
#define	SPD_KEY_DEV_PMIC1_MFG	"module.pmic1.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_PMIC1_MFG_NAME	"module.pmic1.mfg-name"	/* string */
#define	SPD_KEY_DEV_PMIC1_TYPE	"module.pmic1.type"	/* uint32_t */
#define	SPD_KEY_DEV_PMIC1_REV	"module.pmic1.revision"	/* string */
#define	SPD_KEY_DEV_PMIC2_MFG	"module.pmic2.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_PMIC2_MFG_NAME	"module.pmic2.mfg-name"	/* string */
#define	SPD_KEY_DEV_PMIC2_TYPE	"module.pmic2.type"	/* uint32_t */
#define	SPD_KEY_DEV_PMIC2_REV	"module.pmic2.revision"	/* string */

#define	SPD_KEY_DEV_CD0_MFG	"module.cd0.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_CD0_MFG_NAME	"module.cd0.mfg-name"	/* string */
#define	SPD_KEY_DEV_CD0_TYPE	"module.cd0.type"	/* uint32_t */
#define	SPD_KEY_DEV_CD0_REV	"module.cd0.revision"	/* string */
#define	SPD_KEY_DEV_CD1_MFG	"module.cd1.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_CD1_MFG_NAME	"module.cd1.mfg-name"	/* string */
#define	SPD_KEY_DEV_CD1_TYPE	"module.cd1.type"	/* uint32_t */
#define	SPD_KEY_DEV_CD1_REV	"module.cd1.revision"	/* string */

#define	SPD_KEY_DEV_RCD_MFG	"module.rcd.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_RCD_MFG_NAME	"module.rcd.mfg-name"	/* string */
#define	SPD_KEY_DEV_RCD_TYPE	"module.rcd.type"	/* uint32_t */
#define	SPD_KEY_DEV_RCD_REV	"module.rcd.revision"	/* string */

#define	SPD_KEY_DEV_DB_MFG	"module.db.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_DB_MFG_NAME	"module.db.mfg-name"	/* string */
#define	SPD_KEY_DEV_DB_TYPE	"module.db.type"	/* uint32_t */
#define	SPD_KEY_DEV_DB_REV	"module.db.revision"	/* string */

#define	SPD_KEY_DEV_MRCD_MFG	"module.mrcd.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_MRCD_MFG_NAME	"module.mrcd.mfg-name"	/* string */
#define	SPD_KEY_DEV_MRCD_TYPE	"module.mrcd.type"	/* uint32_t */
#define	SPD_KEY_DEV_MRCD_REV	"module.mrcd.revision"	/* string */

#define	SPD_KEY_DEV_MDB_MFG	"module.mdb.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_MDB_MFG_NAME	"module.mdb.mfg-name"	/* string */
#define	SPD_KEY_DEV_MDB_TYPE	"module.mdb.type"	/* uint32_t */
#define	SPD_KEY_DEV_MDB_REV	"module.mdb.revision"	/* string */

#define	SPD_KEY_DEV_DMB_MFG	"module.dmb.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_DMB_MFG_NAME	"module.dmb.mfg-name"	/* string */
#define	SPD_KEY_DEV_DMB_TYPE	"module.dmb.type"	/* uint32_t */
#define	SPD_KEY_DEV_DMB_REV	"module.dmb.revision"	/* string */

#define	SPD_KEY_DEV_SPD_MFG	"module.spd.mfg-id"	/* uint32_t [2] */
#define	SPD_KEY_DEV_SPD_MFG_NAME	"module.spd.mfg-name"	/* string */
#define	SPD_KEY_DEV_SPD_TYPE	"module.spd.type"	/* uint32_t */
#define	SPD_KEY_DEV_SPD_REV	"module.spd.revision"	/* string */

/*
 * Module physical dimensions. DRAM modules provide information about their
 * height and their front and back thicknesses. All values are in millimeters.
 * In general, values are defined as 1 mm ranges in the form such as 18mm <
 * height <= 19mm or 2mm < thickness <= 3mm. As such in all these ranges we
 * encode it as the less than or equal to side of the thickness or height.
 *
 * However, at the extremes of thickness and height, it can be arbitrary. The
 * minimum height can be any value <= 15mm and the maximum is just > 45mm.
 * Similarly the maximum thickness is just any value greater than 15mm. For
 * these values, we define aliases that can be used to indicate we're in these
 * conditions for the height and thickness, allowing this to otherwise be the
 * common well understood value.
 */
#define	SPD_MOD_HEIGHT_LT15MM	15
#define	SPD_MOD_HEIGHT_GT45MM	46
#define	SPD_KEY_MOD_HEIGHT	"module.height"		/* uint32_t */
#define	SPD_MOD_THICK_GT15MM	16
#define	SPD_KEY_MOD_FRONT_THICK	"module.front-thickness"	/* uint32_t */
#define	SPD_KEY_MOD_BACK_THICK	"module.back-thickness"	/* uint32_t */

/*
 * This is the number of rows of DRAM dies on the module. In addition, DDR3 and
 * DDR4 provides the number of registers present on the device. This is not
 * present in DDR5.
 */
#define	SPD_KEY_MOD_NROWS	"module.dram-die-rows"		/* uint32_t */
#define	SPD_KEY_MOD_NREGS	"module.total-registers"	/* uint32_t */

/*
 * Operating temperature ranges. These ranges are defined by JEDEC. The code can
 * be translated with libjedec_temp_range() to transform it into a pair of
 * values.
 */
#define	SPD_KEY_MOD_OPER_TEMP	"module.operating-temperature"	/* uint32_t */

/*
 * Module reference card and design revision. JEDEC provides various reference
 * designs for modules and revisions of those.
 */
#define	SPD_KEY_MOD_REF_DESIGN	"module.reference-design"	/* string */
#define	SPD_KEY_MOD_DESIGN_REV	"module.design-revision"	/* uint32_t */

/*
 * Manufacturing Section. These keys are present if manufacturing related
 * information is made available. This space is not DIMM-revision specific. All
 * fields are defined in DDR4 and DDR5. Note, the SPD_KEY_MFG_DRAM_STEP is
 * optional and therefore an invalid value will result in this not being
 * present.
 */
#define	SPD_KEY_MFG_MOD_MFG_ID	"mfg.module-mfg-id"	/* uint32[2] */
#define	SPD_KEY_MFG_MOD_MFG_NAME	"mfg.module-mfg-name"	/* string */
#define	SPD_KEY_MFG_DRAM_MFG_ID	"mfg.dram-mfg-id"	/* uint32[2] */
#define	SPD_KEY_MFG_DRAM_MFG_NAME	"mfg.dram-mfg-name"	/* string */
#define	SPD_KEY_MFG_MOD_LOC_ID	"mfg.module-loc-id"	/* uint32 */
#define	SPD_KEY_MFG_MOD_YEAR	"mfg.module-year"	/* string */
#define	SPD_KEY_MFG_MOD_WEEK	"mfg.module-week"	/* string */
#define	SPD_KEY_MFG_MOD_PN	"mfg.module-pn"		/* string */
#define	SPD_KEY_MFG_MOD_SN	"mfg.module-sn"		/* string */
#define	SPD_KEY_MFG_MOD_REV	"mfg.module-rev"	/* string */
#define	SPD_KEY_MFG_DRAM_STEP	"mfg.dram-step"		/* string */

/*
 * The errors nvlist_t is designed such that it is a nested nvlist_t in the
 * returned data. Each key in that nvlist_t corresponds to a key that we would
 * otherwise produce. Each key is an nvlist_t that has two keys, a 'code' and a
 * 'message'.
 *
 * There is currently an additional top-level special key. This is the
 * 'incomplete' key. When data is too short to process an entry, rather than
 * flag every possible missing key (as most times the consumer will know the
 * amount of data they have), for the time being we will insert a single
 * incomplete key with a uint32_t whose value indicates the starting offset of
 * the key that we could not process. Note, this may not be the first byte that
 * was missing (if we had 100 bytes and a 20 byte key at offset 90, we would
 * insert 90).
 */
typedef enum {
	/*
	 * Indicates that the error occurred because we could not translate a
	 * given piece of information. For example, a value that we didn't know
	 * or a failure to look up something in a string table.
	 */
	SPD_ERROR_NO_XLATE,
	/*
	 * This indicates that we encountered an non-ASCII or unprintable
	 * character in an SPD string which should not be allowed per se.
	 */
	SPD_ERROR_UNPRINT,
	/*
	 * This indicates that there was no data for a given key. For example, a
	 * string that was all padded spaces.
	 */
	SPD_ERROR_NO_DATA,
	/*
	 * Indicates that some kind of internal error occurred.
	 */
	SPD_ERROR_INTERNAL,
	/*
	 * This indicates that there's something suspicious or weird to us about
	 * the data in question. The most common case is a bad CRC.
	 */
	SPD_ERROR_BAD_DATA
} spd_error_kind_t;
#define	SPD_KEY_INCOMPLETE	"incomplete"	/* uint32_t */
#define	SPD_KEY_ERRS		"errors"	/* nvlist_t */
#define	SPD_KEY_ERRS_CODE	"code"		/* uint32_t */
#define	SPD_KEY_ERRS_MSG	"message"	/* string */

#ifdef __cplusplus
}
#endif

#endif /* _LIBJEDEC_H */
