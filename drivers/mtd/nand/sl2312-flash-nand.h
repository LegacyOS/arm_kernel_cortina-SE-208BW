#ifndef SL2312_FLASH_NAND_H
#define SL2312_FLASH_NAND_H

#include <linux/config.h>
#include <linux/wait.h>
#include <linux/spinlock.h>

/*Add function*/
static void nand_read_id(int chip_no,unsigned char *id);



#define	NFLASH_WiDTH8              0x00000000
#define	NFLASH_WiDTH16             0x00000400
#define	NFLASH_WiDTH32             0x00000800
#define NFLASH_CHIP0_EN            0x00000000  // 16th bit = 0
#define NFLASH_CHIP1_EN            0x00010000  // 16th bit = 1
#define	NFLASH_DIRECT              0x00004000
#define	NFLASH_INDIRECT            0x00000000

#define	NFLASH_DMA_FIFO            0x7000

#define	DWIDTH             NFLASH_WiDTH8
#define	PAGE512_SIZE              	0x200
#define	PAGE512_OOB_SIZE              	0x10
#define	PAGE512_RAW_SIZE              	0x210
#define	PAGE2K_SIZE              		0x800
#define	PAGE2K_OOB_SIZE              	0x40
#define	PAGE2K_RAW_SIZE              	0x840
#define	FLASH_TYPE_MASK             	0x1800
#define	FLASH_WIDTH_MASK             	0x0400
#define	FLASH_SIZE_MASK             	0x0300
#define	FLASH_SIZE_32 	            	0x0000
#define	FLASH_SIZE_64 	            	0x0100
#define	FLASH_SIZE_128 	            	0x0200
#define	FLASH_SIZE_256 	            	0x0300
#define	FLASH_TYPE_NAND             	0x1000
#define	FLASH_TYPE_NOR             	0x0800
#define	FLASH_TYPE_SERIAL             	0x0000
#define	FLASH_START_BIT             	0x80000000
#define	FLASH_RD             	0x00002000
#define	FLASH_WT             	0x00003000
#define	ECC_CHK_MASK             	0x00000003
#define	ECC_UNCORRECTABLE             	0x00000003
#define	ECC_1BIT_DATA_ERR             	0x00000001
#define	ECC_1BIT_ECC_ERR             	0x00000002
#define	ECC_NO_ERR             	0x00000000
#define	ECC_ERR_BYTE             	0x0000ff80
#define	ECC_ERR_BIT             	0x00000078

#define	ECC_CLR             	0x00000001
#define	ECC_PAUSE_EN             	0x00000002

#define	FLASH_CLR_FIFO             	0x8000

#define	STS_WP             	0x80
#define	STS_READY             	0x40
#define	STS_TRUE_READY             	0x40
#define	NFLASH_ENABLE             	0x00000004
#define	GLOBAL_MISC_CTRL			0x30

/* DMA Registers */
#define	DMA_MAIN_CFG 		   		0x00000024
#define	DMA_INT_TC_CLR				0x00000008
#define	DMA_TC						0x00000014
#define	DMA_ENABLE					1
#define	DMA_ABORT_INT					2

/* DMA Registers */
#define	DMA_INT 		   		0x00000000
#define	DMA_INT_TC 		   		0x00000004
#define	DMA_CHEN 		   		0x0000001c
#define	DMA_CSR						0x00000024
#define	DMA_SYNC					0x00000028

#define	DMA_CH0_TC    				0x1
#define	DMA_CH0_DISABLE    			0x0
#define	DMA_CH0_SYNC    			0x1
#define	DMA_CH0_CSR    				0x00000100
#define	DMA_CH0_CFG    				0x00000104
#define	DMA_CH0_SRC_ADDR    		0x00000108
#define	DMA_CH0_DST_ADDR    		0x0000010c
#define	DMA_CH0_LLP    				0x00000110
#define	DMA_CH0_SIZE    			0x00000114

#define	NCNT_EMPTY_OOB    			0x7F000000
#define	NCNT_512P_OOB    			0x0F000000
#define	NCNT_2kP_OOB    			0x3F000000
#define	NCNT_EMPTY_DATA    			0x000FFF00
#define	NCNT_512P_DATA    			0x0001FF00
#define	NCNT_2kP_DATA    			0x0007FF00
#define	NCNT_DATA_1    				0x00000000
#define	NCNT_DATA_2    				0x00000100
#define	NCNT_DATA_3    				0x00000200
#define	NCNT_DATA_4    				0x00000300
#define	NCNT_DATA_5    				0x00000400
#define	NCNT_EMPTY_ADDR    			0x00000070
#define	NCNT_ADDR_5	    			0x00000040
#define	NCNT_ADDR_4	    			0x00000030
#define	NCNT_ADDR_3	    			0x00000020
#define	NCNT_ADDR_2	    			0x00000010
#define	NCNT_ADDR_1	    			0x00000000
#define	NCNT_EMPTY_CMD    			0x00000003
#define	NCNT_CMD_3    			0x00000002
#define	NCNT_CMD_2    			0x00000001
#define	NCNT_CMD_1    			0x00000000



#endif /* SL2312_FLASH_NAND_H */
