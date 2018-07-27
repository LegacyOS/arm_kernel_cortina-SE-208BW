/*
 * 	Copyright (c) 2008 Cortina Systems, Inc.
 * 	All Rights Reserved.
 *
 *	Description: 
 * 	Register define for Tantos 0G 5 Port 10/100Mbit/s Plus 2xMII 
 *	Single Chip Ethernet Switch Controller.
 *	
 *	Written by CH Hsu <ch.hsu@cortina-systems.com>
 * 	Principal Member of Technical Staff
 * 	Cortina Systems, Inc.
 *	
 *	History:
 *	Date		 Author			Description
 *	-----------	 ----------     --------------------
 *	Dec 24,2008	 CH HSU			Modify from Millinet
 *
 */

#ifndef _SL351x_TANTOS_H
#define _SL351x_TANTOS_H

#define REG32(addr) (*(volatile unsigned long  * const)(addr))
#define READ32(addr, value)	((value) = *((volatile uint32_t *)(addr)))
#define WRITE32(addr, value) (*((volatile uint32_t *)(addr)) = (value))
#define BIT(x) (1 << (x))

#define IFX_TANTOS_MAX_PORT	7
#define IFX_TANTOS_MAX_RMON	0x28
#define IFX_TANTOS_PROD_CODE 0x2599

#define IFX_TANTOS_READRMON		0x1
#define IFX_TANTOS_CLRRMON		0x2
#define IFX_TANTOS_CLRRMON_ALL	0x3

/* TCP/UDP control */
#define IFX_TANTOS_TCPUDP_MAX	0x8		/* max TCP/UDP filter number */
/* DiffServ */
#define IFX_TANTOS_MAX_IPTOS	0x40	/* 6 bits, 2^7 - 1 */
/* VLAN */
#define IFX_TANTOS_MAX_VLAN_NUM	15

/* registers */
/* for Port 0 */
#define TANTOS_REG_P0STS	0x00
#define TANTOS_REG_P0BCTL	0x01
#define TANTOS_REG_P0ECTL	0x02
#define TANTOS_REG_P0PBVM	0x03
#define TANTOS_REG_P0DVID	0x04
#define TANTOS_REG_P0ECSQ3	0x05
#define TANTOS_REG_P0ECSQ2	0x06
#define TANTOS_REG_P0ECSQ1	0x07
#define TANTOS_REG_P0ECSQ0	0x08
#define TANTOS_REG_P0ECWQ3	0x09
#define TANTOS_REG_P0ECWQ2	0x0A
#define TANTOS_REG_P0ECWQ1	0x0B
#define TANTOS_REG_P0ECWQ0	0x0C
#define TANTOS_REG_P0ICR	0x0D

/* for Port 1 */
#define TANTOS_REG_P1STS	0x20
#define TANTOS_REG_P1BCTL	0x21
#define TANTOS_REG_P1ECTL	0x22
#define TANTOS_REG_P1PBVM	0x23
#define TANTOS_REG_P1DVID	0x24
#define TANTOS_REG_P1ECSQ3	0x25
#define TANTOS_REG_P1ECSQ2	0x26
#define TANTOS_REG_P1ECSQ1	0x27
#define TANTOS_REG_P1ECSQ0	0x28
#define TANTOS_REG_P1ECWQ3	0x29
#define TANTOS_REG_P1ECWQ2	0x2A
#define TANTOS_REG_P1ECWQ1	0x2B
#define TANTOS_REG_P1ECWQ0	0x2C
#define TANTOS_REG_P1ICR	0x2D

/* for Port 2 */
#define TANTOS_REG_P2STS	0x40
#define TANTOS_REG_P2BCTL	0x41
#define TANTOS_REG_P2ECTL	0x42
#define TANTOS_REG_P2PBVM	0x43
#define TANTOS_REG_P2DVID	0x44
#define TANTOS_REG_P2ECSQ3	0x45
#define TANTOS_REG_P2ECSQ2	0x46
#define TANTOS_REG_P2ECSQ1	0x47
#define TANTOS_REG_P2ECSQ0	0x48
#define TANTOS_REG_P2ECWQ3	0x49
#define TANTOS_REG_P2ECWQ2	0x4A
#define TANTOS_REG_P2ECWQ1	0x4B
#define TANTOS_REG_P2ECWQ0	0x4C
#define TANTOS_REG_P2ICR	0x4D

/* for Port 3 */
#define TANTOS_REG_P3STS	0x60
#define TANTOS_REG_P3BCTL	0x61
#define TANTOS_REG_P3ECTL	0x62
#define TANTOS_REG_P3PBVM	0x63
#define TANTOS_REG_P3DVID	0x64
#define TANTOS_REG_P3ECSQ3	0x65
#define TANTOS_REG_P3ECSQ2	0x66
#define TANTOS_REG_P3ECSQ1	0x67
#define TANTOS_REG_P3ECSQ0	0x68
#define TANTOS_REG_P3ECWQ3	0x69
#define TANTOS_REG_P3ECWQ2	0x6A
#define TANTOS_REG_P3ECWQ1	0x6B
#define TANTOS_REG_P3ECWQ0	0x6C
#define TANTOS_REG_P3ICR	0x6D

/* for port 4 */
#define TANTOS_REG_P4STS	0x80
#define TANTOS_REG_P4BCTL	0x81
#define TANTOS_REG_P4ECTL	0x82
#define TANTOS_REG_P4PBVM	0x83
#define TANTOS_REG_P4DVID	0x84
#define TANTOS_REG_P4ECSQ3	0x85
#define TANTOS_REG_P4ECSQ2	0x86
#define TANTOS_REG_P4ECSQ1	0x87
#define TANTOS_REG_P4ECSQ0	0x88
#define TANTOS_REG_P4ECWQ3	0x89
#define TANTOS_REG_P4ECWQ2	0x8A
#define TANTOS_REG_P4ECWQ1	0x8B
#define TANTOS_REG_P4ECWQ0	0x8C
#define TANTOS_REG_P4ICR	0x8D

/* for port 5 */
#define TANTOS_REG_P5STS	0xA0
#define TANTOS_REG_P5BCTL	0xA1
#define TANTOS_REG_P5ECTL	0xA2
#define TANTOS_REG_P5PBVM	0xA3
#define TANTOS_REG_P5DVID	0xA4
#define TANTOS_REG_P5ECSQ3	0xA5
#define TANTOS_REG_P5ECSQ2	0xA6
#define TANTOS_REG_P5ECSQ1	0xA7
#define TANTOS_REG_P5ECSQ0	0xA8
#define TANTOS_REG_P5ECWQ3	0xA9
#define TANTOS_REG_P5ECWQ2	0xAA
#define TANTOS_REG_P5ECWQ1	0xAB
#define TANTOS_REG_P5ECWQ0	0xAC
#define TANTOS_REG_P5ICR	0xAD

/* for port 6 */
#define TANTOS_REG_P6STS	0xC0
#define TANTOS_REG_P6BCTL	0xC1
#define TANTOS_REG_P6ECTL	0xC2
#define TANTOS_REG_P6PBVM	0xC3
#define TANTOS_REG_P6DVID	0xC4
#define TANTOS_REG_P6ECSQ3	0xC5
#define TANTOS_REG_P6ECSQ2	0xC6
#define TANTOS_REG_P6ECSQ1	0xC7
#define TANTOS_REG_P6ECSQ0	0xC8
#define TANTOS_REG_P6ECWQ3	0xC9
#define TANTOS_REG_P6ECWQ2	0xCA
#define TANTOS_REG_P6ECWQ1	0xCB
#define TANTOS_REG_P6ECWQ0	0xCC
#define TANTOS_REG_P6ICR	0xCD

/* VLAN filters */
#define TANTOS_REG_VF0L		0x10
#define TANTOS_REG_VF0H		0x11
#define TANTOS_REG_VF1L		0x12
#define TANTOS_REG_VF1H		0x13
#define TANTOS_REG_VF2L		0x14
#define TANTOS_REG_VF2H		0x15
#define TANTOS_REG_VF3L		0x16
#define TANTOS_REG_VF3H		0x17
#define TANTOS_REG_VF4L		0x18
#define TANTOS_REG_VF4H		0x19
#define TANTOS_REG_VF5L		0x1A
#define TANTOS_REG_VF5H		0x1B
#define TANTOS_REG_VF6L		0x1C
#define TANTOS_REG_VF6H		0x1D
#define TANTOS_REG_VF7L		0x1E
#define TANTOS_REG_VF7H		0x1F
#define TANTOS_REG_VF8L		0x30
#define TANTOS_REG_VF8H		0x31
#define TANTOS_REG_VF9L		0x32
#define TANTOS_REG_VF9H		0x33
#define TANTOS_REG_VF10L	0x34
#define TANTOS_REG_VF10H	0x35
#define TANTOS_REG_VF11L	0x36
#define TANTOS_REG_VF11H	0x37
#define TANTOS_REG_VF12L	0x38
#define TANTOS_REG_VF12H	0x39
#define TANTOS_REG_VF13L	0x3A
#define TANTOS_REG_VF13H	0x3B
#define TANTOS_REG_VF14L	0x3C
#define TANTOS_REG_VF14H	0x3D
#define TANTOS_REG_VF15L	0x3E
#define TANTOS_REG_VF15H	0x3F

/* type filters */
#define TANTOS_REG_TF0		0x50
#define TANTOS_REG_TF1		0x51
#define TANTOS_REG_TF2		0x52
#define TANTOS_REG_TF3		0x53
#define TANTOS_REG_TF4		0x54
#define TANTOS_REG_TF5		0x55
#define TANTOS_REG_TF6		0x56
#define TANTOS_REG_TF7		0x57

/* diffserv mapping */
#define TANTOS_REG_DM0		0x58
#define TANTOS_REG_DM1		0x59
#define TANTOS_REG_DM2		0x5A
#define TANTOS_REG_DM3		0x5B
#define TANTOS_REG_DM4		0x5C
#define TANTOS_REG_DM5		0x5D
#define TANTOS_REG_DM6		0x5E
#define TANTOS_REG_DM7		0x5F

/* TCP/UDP filter */
#define TANTOS_REG_TUPF0	0x70
#define TANTOS_REG_TUPR0	0x71
#define TANTOS_REG_TUPF1	0x72
#define TANTOS_REG_TUPR1	0x73
#define TANTOS_REG_TUPF2	0x74
#define TANTOS_REG_TUPR2	0x75
#define TANTOS_REG_TUPF3	0x76
#define TANTOS_REG_TUPR3	0x77
#define TANTOS_REG_TUPF4	0x78
#define TANTOS_REG_TUPR4	0x79
#define TANTOS_REG_TUPF5	0x7A
#define TANTOS_REG_TUPR5	0x7B
#define TANTOS_REG_TUPF6	0x7C
#define TANTOS_REG_TUPR6	0x7D
#define TANTOS_REG_TUPF7	0x7E
#define TANTOS_REG_TUPR7	0x7F

/* protocol filter */
#define TANTOS_REG_PF0		0xB8
#define TANTOS_REG_PF1		0xB9
#define TANTOS_REG_PF2		0xBA
#define TANTOS_REG_PF3		0xBB

/* Phy initial control */
#define TANTOS_REG_PHYIC0	0xD0
#define TANTOS_REG_PHYIC1	0xD2
#define TANTOS_REG_PHYIC2	0xD4
#define TANTOS_REG_PHYIC3	0xD6

/* Phy initial data */
#define TANTOS_REG_PHYID0	0xD1
#define TANTOS_REG_PHYID1	0xD3
#define TANTOS_REG_PHYID2	0xD5
#define TANTOS_REG_PHYID3	0xD7

/* interrupt related */
#define TANTOS_REG_IE		0xD8
#define TANTOS_REG_IS		0xD9

/* type filter actions */
#define TANTOS_REG_TFA0		0xDA
#define TANTOS_REG_TFA1		0xDB

#define TANTOS_REG_PIOFGPM  0xDD

#define TANTOS_REG_CHM      0xE2
#define TANTOS_REG_MS       0xE3

/* GMII related */
#define TANTOS_REG_RGMIICR	0xF5

/* for IGMP */
#define TANTOS_REG_HIOR		0xF6

/* PPPoE Removal Session ID */
#define TANTOS_REG_PSIDR    0xF7

#define TANTOS_REG_CI0		0x100
#define TANTOS_REG_CI1		0x101
#define TANTOS_REG_GSHS		0x102
#define TANTOS_REG_ATC0		0x104
#define TANTOS_REG_ATC1		0x105
#define TANTOS_REG_ATC2		0x106
#define TANTOS_REG_ATC3		0x107
#define TANTOS_REG_ATC4		0x108
#define TANTOS_REG_ATC5		0x109
#define TANTOS_REG_ATS0		0x10A
#define TANTOS_REG_ATS1		0x10B
#define TANTOS_REG_ATS2		0x10C
#define TANTOS_REG_ATS3		0x10D
#define TANTOS_REG_ATS4		0x10E
#define TANTOS_REG_ATS5		0x10F
#define TANTOS_REG_IGMPTC0	0x110
#define TANTOS_REG_IGMPTC1	0x111
#define TANTOS_REG_IGMPTC2	0x112
#define TANTOS_REG_IGMPTC3	0x113
#define TANTOS_REG_IGMPTC4	0x114
#define TANTOS_REG_IGMPTC5	0x115
#define TANTOS_REG_IGMPTS0	0x116
#define TANTOS_REG_IGMPTS1	0x117
#define TANTOS_REG_IGMPTS2	0x118
#define TANTOS_REG_IGMPTS3	0x119
#define TANTOS_REG_IGMPTS4	0x11a

#define	TANTOS_REG_RMONCTL	0x11B
#define TANTOS_REG_RMONLOW	0x11C
#define TANTOS_REG_RMONHIGH	0x11D
#define TANTOS_REG_P5BC		0xA1
#define TANTOS_REG_SGC1     0xE0
#define TANTOS_REG_SGC2     0xE1
#define TANTOS_REG_CHM      0xE2
#define TANTOS_REG_MS       0xE3
#define TANTOS_REG_CI1		0x101
#define TANTOS_REG_MIIAC    0x120
#define TANTOS_REG_MIIWD    0x121
#define TANTOS_REG_MIIRD    0x122
/* registers */

/* Bit offsets */
#define BIT_0	0x1
#define BIT_1	0x2
#define BIT_2	0x4
#define BIT_3	0x8
#define BIT_4	0x10
#define BIT_5	0x20
#define BIT_6	0x40
#define BIT_7	0x80
#define BIT_8	0x100
#define BIT_9	0x200
#define BIT_10	0x400
#define BIT_11	0x800
#define BIT_12	0x1000
#define BIT_13	0x2000
#define BIT_14	0x4000
#define BIT_15	0x8000
#define BIT_16	0x10000

#define GLOBAL_BASE_ADD	IO_ADDRESS(SL2312_GLOBAL_BASE)
#define GPIO_BASE_ADD  	IO_ADDRESS(SL2312_GPIO_BASE)
#define GPIO_BASE_ADD1  IO_ADDRESS(SL2312_GPIO_BASE1)
enum GPIO_REG
{
    GPIO_DATA_OUT   = 0x00,
    GPIO_DATA_IN    = 0x04,
    GPIO_PIN_DIR    = 0x08,
    GPIO_BY_PASS    = 0x0c,
    GPIO_DATA_SET   = 0x10,
    GPIO_DATA_CLEAR = 0x14,
};

#endif //_SL351x_TANTOS_H
