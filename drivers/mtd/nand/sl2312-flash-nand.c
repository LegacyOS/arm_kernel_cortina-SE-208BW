/*
 *  drivers/mtd/cs_nand.c
 *
 *  Overview:
 *   This is the generic MTD driver for NAND flash devices. It should be
 *   capable of working with almost all NAND chips currently available.
 *   Basic support for AG-AND chips is provided.
 *
 *	Additional technical information is available on
 *	http://www.linux-mtd.infradead.org/tech/nand.html
 *
 *  Copyright (C) 2000 Steven J. Hill (sjhill@realitydiluted.com)
 * 		  2002 Thomas Gleixner (tglx@linutronix.de)
 *
 *  02-08-2004  tglx: support for strange chips, which cannot auto increment
 *		pages on read / read_oob
 *
 *  03-17-2004  tglx: Check ready before auto increment check. Simon Bayes
 *		pointed this out, as he marked an auto increment capable chip
 *		as NOAUTOINCR in the board driver.
 *		Make reads over block boundaries work too
 *
 *  04-14-2004	tglx: first working version for 2k page size chips
 *
 *  05-19-2004  tglx: Basic support for Renesas AG-AND chips
 *
 *  09-24-2004  tglx: add support for hardware controllers (e.g. ECC) shared
 *		among multiple independend devices. Suggestions and initial patch
 *		from Ben Dooks <ben-mtd@fluff.org>
 *
 *  12-05-2004	dmarlin: add workaround for Renesas AG-AND chips "disturb" issue.
 *		Basically, any block not rewritten may lose data when surrounding blocks
 *		are rewritten many times.  JFFS2 ensures this doesn't happen for blocks
 *		it uses, but the Bad Block Table(s) may not be rewritten.  To ensure they
 *		do not lose data, force them to be rewritten when some of the surrounding
 *		blocks are erased.  Rather than tracking a specific nearby block (which
 *		could itself go bad), use a page address 'mask' to select several blocks
 *		in the same area, and rewrite the BBT when any of them are erased.
 *
 *  01-03-2005	dmarlin: added support for the device recovery command sequence for Renesas
 *		AG-AND chips.  If there was a sudden loss of power during an erase operation,
 * 		a "device recovery" operation must be performed when power is restored
 * 		to ensure correct operation.
 *
 *  01-20-2005	dmarlin: added support for optional hardware specific callback routine to
 *		perform extra error status checks on erase and write failures.  This required
 *		adding a wrapper function for csnand_read_ecc.
 *
 * 08-20-2005	vwool: suspend/resume added
 *
 * Credits:
 *	David Woodhouse for adding multichip support
 *
 *	Aleph One Ltd. and Toby Churchill Ltd. for supporting the
 *	rework for 2K page size chips
 *
 * TODO:
 *	Enable cached programming for 2k page size chips
 *	Check, if mtd->ecctype should be set to MTD_ECC_HW
 *	if we have HW ecc support.
 *	The AG-AND chips have nice features for speed improvement,
 *	which are not supported yet. Read / program 4 pages in one go.
 *
 * $Id: sl2312-flash-nand.c,v 1.10 2009/06/24 03:24:10 middle Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/nand.h>
#include <linux/mtd/nand_ecc.h>
#include <linux/mtd/compatmac.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
#ifdef CONFIG_MTD_PARTITIONS
#include <linux/mtd/partitions.h>
#endif
#include <asm/io.h>
#include <asm/hardware.h>
#include <asm/arch/sl2312.h>
#include <linux/mtd/kvctl.h>
#include "sl2312-flash-nand.h" 
#include "../maps/sl2312_flashmap.h" 

#include <asm/arch/ipi.h>

#define FORCE_DMA_ACCESS 1


/*
 * MTD structure for sl2312 NDFMC
 */
static struct mtd_info *csmtd = NULL;
static int nand_page=0,nand_col=0;
int debug_f = 0;
static u_char *tmpbuf, *tmpoobbuf,*write_data,*read_data;
//static u_char write_data[2112], read_data[2112];
static unsigned int *pread, *pwrite;
unsigned int ADD,ADD2,ADD3,ADD4,ADD5;
 
/* Define default oob placement schemes for large and small page devices */
#ifdef CONFIG_YAFFS_FS
static struct nand_oobinfo nand_oob_8 = {
	.useecc = MTD_NANDECC_AUTOPLACE,
	.eccbytes = 3,
	.eccpos = {0, 1, 2},
	.oobfree = { {3, 2}, {6, 2} }
};

//static struct nand_oobinfo nand_oob_16 = {
//	.useecc = MTD_NANDECC_AUTOPLACE,
//	.eccbytes = 6,
//	.eccpos = {0, 1, 2, 3, 6, 7},
//	.oobfree = { {8, 8} }
//};

static struct nand_oobinfo nand_oob_16 = {
	.useecc = MTD_NANDECC_AUTOPLACE,
	.eccbytes = 6,
	.eccpos = {8,9,10,13,14,15},
	.oobfree = { {0, 4},{7, 1} }
};

static struct nand_oobinfo nand_oob_64 = {
	.useecc = MTD_NANDECC_AUTOPLACE,
	.eccbytes = 24,
	.eccpos = {
		40, 41, 42, 43, 44, 45, 46, 47,
		48, 49, 50, 51, 52, 53, 54, 55,
		56, 57, 58, 59, 60, 61, 62, 63},
	.oobfree = { {4, 36} } 
};
#else
static struct nand_oobinfo nand_oob_16 = {
	.useecc = MTD_NANDECC_AUTOPLACE,
	.eccbytes = 3,
	.eccpos = {0, 1, 2},
	.oobfree = { {8, 8} }
};

static struct nand_oobinfo nand_oob_64 = {
	.useecc = MTD_NANDECC_AUTOPLACE,
	.eccbytes = 12,
	.eccpos = {
		52, 53, 54, 55,56, 57, 
		58, 59, 60, 61, 62, 63},
	.oobfree = { {2, 38} }
};
#endif
/* This is used for padding purposes in csnand_write_oob */
static u_char ffchars[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

static uint8_t bbt_pattern[] = {'B', 'b', 't', '0' };
static uint8_t mirror_pattern[] = {'1', 't', 'b', 'B' };
static struct nand_bbt_descr cs_bbt_main_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION,// | NAND_BBT_PERCHIP,
	.offs = 8,
	.len = 4,
	.veroffs = 12,
	.maxblocks = 4,
	.pattern = bbt_pattern
};

static struct nand_bbt_descr cs_bbt_mirror_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION ,//| NAND_BBT_PERCHIP,
	.offs = 8,
	.len = 4,
	.veroffs = 12,
	.maxblocks = 4,
	.pattern = mirror_pattern
};

/*
 * Define partitions for flash device   
 */
/* the base address of FLASH control register */
#define FLASH_CONTROL_BASE_ADDR	    (IO_ADDRESS(SL2312_FLASH_CTRL_BASE))
#define SL2312_GLOBAL_BASE_ADDR     (IO_ADDRESS(SL2312_GLOBAL_BASE))
//#define SL2312_FLASH_BASE_ADDR      (IO_ADDRESS(SL2312_FLASH_BASE)) 
#define SL2312_FLASH_BASE_ADDR       FLASH_VADDR(SL2312_FLASH_BASE)
static unsigned int CHIP_EN; 
#if FORCE_DMA_ACCESS
#define DMA_CONTROL_PHY_BASE       IO_ADDRESS(SL2312_GENERAL_DMA_BASE)
unsigned int READ_DMA_REG(unsigned int addr)
{
    unsigned int *base;
    unsigned int data;
    
    base = (unsigned int *)(DMA_CONTROL_PHY_BASE + addr);
    data = *base;
    return (data);
}

void WRITE_DMA_REG(unsigned int addr,unsigned int data)
{
    unsigned int *base;
    
    base = (unsigned int *)(DMA_CONTROL_PHY_BASE + addr);
    *base = data;
    return;
}
dma_addr_t          read_dma, write_dma;
#endif

unsigned int FLASH_READ_REG(unsigned int addr)
{
    unsigned int *base;
    unsigned int data;
    
    base = (unsigned int *)(FLASH_CONTROL_BASE_ADDR + addr);
    data = *base;
    return (data);
}

void FLASH_WRITE_REG(unsigned int addr,unsigned int data)
{
    unsigned int *base;
    
    base = (unsigned int *)(FLASH_CONTROL_BASE_ADDR + addr);
    *base = data;
    return;
}

unsigned int FLASH_READ_DATA(unsigned int addr)
{
    unsigned char *base;
    unsigned int data;
    
    base = (unsigned char *)(SL2312_FLASH_BASE_ADDR + addr);
    data = *base;
    return (data); 
}

void FLASH_WRITE_DATA(unsigned int addr,unsigned int data)
{
    unsigned char *base;
    
    base = (unsigned char *)(SL2312_FLASH_BASE_ADDR + addr);
    *base = data;
    return;
}
#ifdef CONFIG_SL2312_SHARE_PIN
void sl2312flash_enable_nand_flash(void)
{
    unsigned int    reg_val;
    
    reg_val = readl(SL2312_GLOBAL_BASE_ADDR + GLOBAL_MISC_CTRL);
    reg_val = reg_val & ~NFLASH_ENABLE;
    writel(reg_val,SL2312_GLOBAL_BASE_ADDR + GLOBAL_MISC_CTRL);
    return;
}

void sl2312flash_disable_nand_flash(void)
{
    unsigned int    reg_val;
    
    reg_val = readl(SL2312_GLOBAL_BASE_ADDR + GLOBAL_MISC_CTRL);
    reg_val = reg_val | NFLASH_ENABLE;
    writel(reg_val,SL2312_GLOBAL_BASE_ADDR + GLOBAL_MISC_CTRL);
    return;    
}
#endif
/* the offset of FLASH control register */
enum NFLASH_REGISTER {
	NFLASH_ID     			= 0x0000,
	NFLASH_STATUS 			= 0x0008,
	NFLASH_TYPE   			= 0x000c,
	NFLASH_ACCESS			= 0x0030,
	NFLASH_COUNT			= 0x0034,
	NFLASH_CMD_ADDR 		= 0x0038,
	NFLASH_ADDRESS			= 0x003C,
	NFLASH_DATA				= 0x0040,
	NFLASH_TIMING   		= 0x004C,
	NFLASH_ECC_STATUS		= 0x0050,
	NFLASH_ECC_CONTROL		= 0x0054,
	NFLASH_ECC_OOB			= 0x005c,
	NFLASH_ECC_CODE_GEN0	= 0x0060,
	NFLASH_ECC_CODE_GEN1	= 0x0064,
	NFLASH_ECC_CODE_GEN2	= 0x0068,
	NFLASH_ECC_CODE_GEN3	= 0x006C,
	NFLASH_FIFO_CONTROL		= 0x0070,
	NFLASH_FIFO_STATUS		= 0x0074,
	NFLASH_FIFO_ADDRESS		= 0x0078,
	NFLASH_FIFO_DATA		= 0x007c,
};	

extern struct nand_oobinfo jffs2_oobinfo;

/*
 * NAND low-level MTD interface functions
 */
static void csnand_write_buf(struct mtd_info *mtd, const u_char *buf, int len);
static void csnand_read_buf(struct mtd_info *mtd, u_char *buf, int len);
static int csnand_verify_buf(struct mtd_info *mtd, const u_char *buf, int len);

static int csnand_read (struct mtd_info *mtd, loff_t from, size_t len, size_t * retlen, u_char * buf);
static int csnand_read_ecc (struct mtd_info *mtd, loff_t from, size_t len,
			  size_t * retlen, u_char * buf, u_char * eccbuf, struct nand_oobinfo *oobsel);
static int csnand_read_oob (struct mtd_info *mtd, loff_t from, size_t len, size_t * retlen, u_char * buf);
static int csnand_write (struct mtd_info *mtd, loff_t to, size_t len, size_t * retlen, const u_char * buf);
static int csnand_write_ecc (struct mtd_info *mtd, loff_t to, size_t len,
			   size_t * retlen, const u_char * buf, u_char * eccbuf, struct nand_oobinfo *oobsel);
static int csnand_write_oob (struct mtd_info *mtd, loff_t to, size_t len, size_t * retlen, const u_char *buf);
static int csnand_writev (struct mtd_info *mtd, const struct kvec *vecs,
			unsigned long count, loff_t to, size_t * retlen);
static int csnand_writev_ecc (struct mtd_info *mtd, const struct kvec *vecs,
			unsigned long count, loff_t to, size_t * retlen, u_char *eccbuf, struct nand_oobinfo *oobsel);
static int csnand_erase (struct mtd_info *mtd, struct erase_info *instr);
static void csnand_sync (struct mtd_info *mtd);

/* Some internal functions */
static int csnand_write_page (struct mtd_info *mtd, struct nand_chip *this, int page, u_char *oob_buf,
		struct nand_oobinfo *oobsel, int mode);
#ifdef CONFIG_MTD_NAND_VERIFY_WRITE
static int csnand_verify_pages (struct mtd_info *mtd, struct nand_chip *this, int page, int numpages,
	u_char *oob_buf, struct nand_oobinfo *oobsel, int chipnr, int oobmode);
#else
#define csnand_verify_pages(...) (0)
#endif

static int csnand_get_device (struct nand_chip *this, struct mtd_info *mtd, int new_state);


/*
*	read device ready pin
*/
static int csnand_device_ready(struct mtd_info *mtd)
{
	int ready;
	
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif	
	//if(debug_f)
	//	printk("%s : -->\n",__func__);
	FLASH_WRITE_REG(NFLASH_DATA,0xffffffff);
RD_STATUS:	
	FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0); //set 31b = 0
	FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_EMPTY_ADDR);//0x7f000070); //set only command no address and two data
	
	FLASH_WRITE_REG(NFLASH_CMD_ADDR, NAND_CMD_STATUS); //write read status command
	
	ready = FLASH_START_BIT|FLASH_RD|DWIDTH|CHIP_EN; //set start bit & 8bits read command
	FLASH_WRITE_REG(NFLASH_ACCESS, ready); 
	
	while(ready&FLASH_START_BIT) //polling flash access 31b
    {
        ready=FLASH_READ_REG(NFLASH_ACCESS);
        //sl2312_flash_delay();
		schedule();
    }	
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif	
      	ready=FLASH_READ_REG(NFLASH_DATA)&0xff;
      	if(ready==0xff)
	    	goto RD_STATUS;
      	if(debug_f)
		printk("%s : <--\n",__func__);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif		
	return (ready & NAND_STATUS_READY);//NAND_STATUS_FAIL);
}

/**
 * csnand_release_device - [GENERIC] release chip
 * @mtd:	MTD device structure
 *
 * Deselect, release chip lock and wake up anyone waiting on the device
 */
static void csnand_release_device (struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;

	/* De-select the NAND device */
	this->select_chip(mtd, -1);
	//if(debug_f)
	//	printk("%s : -->\n",__func__);
	if (this->controller) {
		/* Release the controller and the chip */
		spin_lock(&this->controller->lock);
		this->controller->active = NULL;
		this->state = FL_READY;
		wake_up(&this->controller->wq);
		spin_unlock(&this->controller->lock);
	} else {
		/* Release the chip */
		spin_lock(&this->chip_lock);
		this->state = FL_READY;
		wake_up(&this->wq);
		spin_unlock(&this->chip_lock);
	}
}

/**
 * csnand_read_byte - [DEFAULT] read one byte from the chip
 * @mtd:	MTD device structure
 *
 * Default read function for 8bit buswith
 */
static u_char csnand_read_byte(struct mtd_info *mtd)
{
	unsigned int    data=0, page=0, col=0, tmp, i;
        struct nand_chip *this = mtd->priv;
        //printk ("******************** %s !! \n\n",__func__);
        if(debug_f)
		printk("%s : -->\n",__func__);
       // printk ("**************************sl2312_nand_read_byte !! \n");
        //page = FLASH_READ_REG(NFLASH_ADDRESS)&0xffffff00;
        //col  = FLASH_READ_REG(NFLASH_ADDRESS)&0x000000ff; 
        page = nand_page;
        col  = nand_col;
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif		
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif	        
        
#ifdef CONFIG_GEMINI_NAND_INDIRECT
		unsigned int nopcode,dent_bit,tt,tofs;

			ADD5=ADD4=ADD3=ADD2=0;
			if(mtd->oobblock < PAGE512_RAW_SIZE)
				ADD5 = (page>>24)&0xff;
				
    		ADD5=(page>>16)&0xff; 
			ADD4=(page>>8)&0xff;
			ADD3=(page)&0xff;
#if FORCE_DMA_ACCESS	
		pread = (unsigned int *) read_data; 
		//memset(read_data, 0xff, (mtd->oobblock+mtd->oobsize));
		WRITE_DMA_REG(DMA_SYNC, DMA_CH0_SYNC);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_CLR_FIFO); //clear fifo
		WRITE_DMA_REG(DMA_MAIN_CFG, DMA_ENABLE); //enable DMA
		WRITE_DMA_REG(DMA_CH0_SRC_ADDR, (NFLASH_DMA_FIFO+SL2312_FLASH_CTRL_BASE)); //src_address
		WRITE_DMA_REG(DMA_CH0_DST_ADDR, read_dma); //dest_address
		WRITE_DMA_REG(DMA_CH0_LLP, 0x0); //LLP
		WRITE_DMA_REG(DMA_CH0_SIZE, ((mtd->oobblock+mtd->oobsize)/4)); //size
		WRITE_DMA_REG(DMA_CH0_CFG, DMA_ABORT_INT); //CFG
		WRITE_DMA_REG(DMA_CH0_CSR, 0x112c3); //CSR
#endif	    
    	dent_bit=FLASH_READ_REG(NFLASH_TYPE);
		switch(dent_bit&FLASH_SIZE_MASK)
		{
			case FLASH_SIZE_32:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_3|NCNT_CMD_1);//0x0f01ff20);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_64:
			case FLASH_SIZE_128:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_4|NCNT_CMD_1);//0x0f01ff30);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_256:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_2kP_OOB|NCNT_2kP_DATA|NCNT_ADDR_5|NCNT_CMD_2);//0x3f07ff41);
			    nopcode = (NAND_CMD_READSTART<<8)|NAND_CMD_READ0;//0x00003000;
			break;
		}
		nopcode |= (ADD5<<24);
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, nopcode); //write address 0x00
		
		nopcode = 0x0|(ADD4<<24)|(ADD3<<16)|(ADD2<<8);
		FLASH_WRITE_REG(NFLASH_ADDRESS, nopcode); //write address 0x00
		tt = (col/4);
		tofs = (col%4);
#if FORCE_DMA_ACCESS	
		
		// set dma fifo port
		FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_START_BIT|FLASH_RD);
		nopcode=READ_DMA_REG(DMA_TC);
		while(!(nopcode&DMA_CH0_TC)) //polling flash access 31b
      	{
          nopcode=READ_DMA_REG(DMA_TC); 
          udelay(2);
      	}
	    nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL); 		
		while(nopcode&FLASH_START_BIT) //polling flash access 31b
      	{
          nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL);
          udelay(2);
      	}
      	
      	//Disable channel 0 DMA
      	WRITE_DMA_REG(DMA_CH0_CSR, DMA_CH0_DISABLE);
      	//DMA TC int status Rg
      	//write clear int
      	WRITE_DMA_REG(DMA_INT_TC_CLR, DMA_CH0_TC);
      	//Flash status Reg
      	//write clear fifo_int
      	FLASH_WRITE_REG(NFLASH_STATUS, 0x20000);
      	data = read_data[col];
		
		
#else			
		for(i=0;i<((mtd->oobblock+mtd->oobsize)/4);i++)
        {	
        	nopcode = FLASH_START_BIT | FLASH_RD|NFLASH_CHIP0_EN|NFLASH_WiDTH32|NFLASH_INDIRECT; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode); 
			while(nopcode&FLASH_START_BIT) //polling flash access 31b
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(2);
        	   schedule();
      		}
      		    
      		dent_bit = FLASH_READ_REG(NFLASH_DATA);    

    		if(i==tt)
    		{
    			if((tofs&ECC_CHK_MASK)==0x01)
    				dent_bit>>=8;
    			else if((tofs&ECC_CHK_MASK)==0x02)
    				dent_bit>>=16;
    			else if((tofs&ECC_CHK_MASK)==0x03)
    				dent_bit>>=24;
    				
    			data = (unsigned char)dent_bit;
    		}
      		    
		}
#endif		
#else  //direct       	
		for(i=0;i<(mtd->oobblock+mtd->oobsize);i++)
        {
        	if(i==col)
				data = (unsigned char)FLASH_READ_DATA((page<<this->page_shift) +i);      
			else
				tmp = (unsigned char)FLASH_READ_DATA((page<<this->page_shift) +i);      
		}
#endif				
            		  

#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif	          
        if(debug_f)
		printk("%s : <--\n",__func__);    
        return data&0xff;
}

/**
 * csnand_write_byte - [DEFAULT] write one byte to the chip
 * @mtd:	MTD device structure
 * @byte:	pointer to data byte to write
 *
 * Default write function for 8it buswith
 */
static void csnand_write_byte(struct mtd_info *mtd, u_char byte)
{

	//writeb(byte, this->IO_ADDR_W);
	int i, page=0,col=0;
	struct nand_chip *this = mtd->priv;
	u_char *databuf, *oobbuf;
        size_t  retlen;
        retlen=0;
	if(debug_f)
		printk("%s : -->\n",__func__); 
	databuf = &(this->data_buf[0]);
		oobbuf = &(this->data_buf[mtd->oobblock]);
		for (i = 0; i < mtd->oobsize; i++)
			oobbuf[i] = 0xff;	
						
	//if(len <= (mtd->oobblock+mtd->oobsize))
	{
		//addr = FLASH_READ_REG(NFLASH_ADDRESS);
		//page = FLASH_READ_REG(NFLASH_ADDRESS)&0xffffff00;
		//col  = FLASH_READ_REG(NFLASH_ADDRESS)&0x000000ff; 
		page = nand_page;
        col  = nand_col;
		
		csnand_read_ecc (mtd, (page<<this->page_shift), mtd->oobblock , &retlen, databuf, oobbuf, NULL);
        
        	databuf[col] = byte;
        	
        csnand_write_ecc (mtd, (page<<this->page_shift), mtd->oobblock, &retlen, databuf, oobbuf, NULL);

	}

	if(debug_f)
		printk("%s : <--\n",__func__);
}

/**
 * csnand_read_byte16 - [DEFAULT] read one byte endianess aware from the chip
 * @mtd:	MTD device structure
 *
 * Default read function for 16bit buswith with
 * endianess conversion
 */
//static u_char csnand_read_byte16(struct mtd_info *mtd)
//{
//	struct nand_chip *this = mtd->priv;
//	return (u_char) cpu_to_le16(readw(this->IO_ADDR_R));
//}

/**
 * csnand_write_byte16 - [DEFAULT] write one byte endianess aware to the chip
 * @mtd:	MTD device structure
 * @byte:	pointer to data byte to write
 *
 * Default write function for 16bit buswith with
 * endianess conversion
 */
//static void csnand_write_byte16(struct mtd_info *mtd, u_char byte)
//{
//	struct nand_chip *this = mtd->priv;
//	writew(le16_to_cpu((u16) byte), this->IO_ADDR_W);
//}

/**
 * csnand_read_word - [DEFAULT] read one word from the chip
 * @mtd:	MTD device structure
 *
 * Default read function for 16bit buswith without
 * endianess conversion
 */
//static u16 csnand_read_word(struct mtd_info *mtd)
//{
//	struct nand_chip *this = mtd->priv;
//	return readw(this->IO_ADDR_R);
//}

/**
 * csnand_write_word - [DEFAULT] write one word to the chip
 * @mtd:	MTD device structure
 * @word:	data word to write
 *
 * Default write function for 16bit buswith without
 * endianess conversion
 */
//static void csnand_write_word(struct mtd_info *mtd, u16 word)
//{
//	struct nand_chip *this = mtd->priv;
//	writew(word, this->IO_ADDR_W);
//}

/**
 * csnand_select_chip - [DEFAULT] control CE line
 * @mtd:	MTD device structure
 * @chip:	chipnumber to select, -1 for deselect
 *
 * Default select function for 1 chip devices.
 */
static void csnand_select_chip(struct mtd_info *mtd, int chip)
{
	struct nand_chip *this = mtd->priv;
	switch(chip) {
	case -1:
		CHIP_EN = NFLASH_CHIP0_EN;	
		break;
	case 0:
		CHIP_EN = NFLASH_CHIP0_EN;
		break;
	case 1:
		CHIP_EN = NFLASH_CHIP1_EN;
		break;

	default:
		//BUG();
		CHIP_EN = NFLASH_CHIP0_EN;
	}
}



/**
 * csnand_read_buf - [DEFAULT] read chip data into buffer
 * @mtd:	MTD device structure
 * @buf:	buffer to store date
 * @len:	number of bytes to read
 *
 * Default read function for 8bit buswith
 */
static void csnand_read_buf(struct mtd_info *mtd, u_char *buf, int len)
{
	int i, page=0,col=0,addr=0,tmp=0,j;
	struct nand_chip *this = mtd->priv;

	//struct nand_chip *this = mtd->priv;
	
	
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif			
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif	
	if(len <= (mtd->oobblock+mtd->oobsize))
	{
		//addr = FLASH_READ_REG(NFLASH_ADDRESS);
		//page = FLASH_READ_REG(NFLASH_ADDRESS)&0xffffff00;
		//col  = FLASH_READ_REG(NFLASH_ADDRESS)&0x000000ff; 
		page = nand_page;
        col  = nand_col;
        addr = (page<<this->page_shift);
        if(debug_f)
		printk("%s : -->len : %x ,page: %x , col: %x\n",__func__,(unsigned int) len, page,col);
#ifdef CONFIG_GEMINI_NAND_INDIRECT
	unsigned int nopcode,dent_bit;

			ADD5=ADD4=ADD3=ADD2=0;
			if(mtd->oobblock < PAGE512_RAW_SIZE)
				ADD5 = (page>>24)&0xff;
				
    		ADD5=(page>>16)&0xff; 
			ADD4=(page>>8)&0xff;
			ADD3=(page)&0xff;
#if FORCE_DMA_ACCESS	
		pread = (unsigned int *) read_data; 
		//memset(read_data, 0xff, (mtd->oobblock+mtd->oobsize));
		WRITE_DMA_REG(DMA_SYNC, DMA_CH0_SYNC);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_CLR_FIFO); //clear fifo
		WRITE_DMA_REG(DMA_MAIN_CFG, DMA_ENABLE); //enable DMA
		WRITE_DMA_REG(DMA_CH0_SRC_ADDR, (NFLASH_DMA_FIFO+SL2312_FLASH_CTRL_BASE)); //src_address
		WRITE_DMA_REG(DMA_CH0_DST_ADDR, read_dma); //dest_address
		WRITE_DMA_REG(DMA_CH0_LLP, 0x0); //LLP
		WRITE_DMA_REG(DMA_CH0_SIZE, ((mtd->oobblock+mtd->oobsize)/4)); //size
		WRITE_DMA_REG(DMA_CH0_CFG, DMA_ABORT_INT); //CFG
		WRITE_DMA_REG(DMA_CH0_CSR, 0x112c3); //CSR
#endif	
    
    	dent_bit=FLASH_READ_REG(NFLASH_TYPE);
		switch(dent_bit&FLASH_SIZE_MASK)
		{
			case FLASH_SIZE_32:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_3|NCNT_CMD_1);//0x0f01ff20);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_64:
			case FLASH_SIZE_128:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_4|NCNT_CMD_1);//0x0f01ff30);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_256:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_2kP_OOB|NCNT_2kP_DATA|NCNT_ADDR_5|NCNT_CMD_2);//0x3f07ff41);
			    nopcode = (NAND_CMD_READSTART<<8)|NAND_CMD_READ0;//0x00003000;
			break;
		}
		nopcode |= (ADD5<<24);
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, nopcode); //write address 0x00
		
		nopcode = 0x0|(ADD4<<24)|(ADD3<<16)|(ADD2<<8);
		FLASH_WRITE_REG(NFLASH_ADDRESS, nopcode); //write address 0x00
#if FORCE_DMA_ACCESS	
		
		// set dma fifo port
		FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_START_BIT|FLASH_RD);

		nopcode=READ_DMA_REG(DMA_TC);
		while(!(nopcode&DMA_CH0_TC)) //polling flash access 31b
      	{
          nopcode=READ_DMA_REG(DMA_TC); 
          udelay(2);
      	}
	    nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL); 		
		while(nopcode&FLASH_START_BIT) //polling flash access 31b
      	{
          nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL);
          udelay(2);
      	}
      	
      	//Disable channel 0 DMA
      	WRITE_DMA_REG(DMA_CH0_CSR, DMA_CH0_DISABLE);
      	//DMA TC int status Rg
      	//write clear int
      	WRITE_DMA_REG(DMA_INT_TC_CLR, DMA_CH0_TC);
      	//Flash status Reg
      	//write clear fifo_int
      	FLASH_WRITE_REG(NFLASH_STATUS, 0x20000);
      	memcpy(buf, &read_data[col], len);
		
		
#else				
		pread = (unsigned int *) read_data;
		for(i=0,j=0;i<((mtd->oobblock+mtd->oobsize)/4);i++)
        {
			nopcode = FLASH_START_BIT | FLASH_RD|NFLASH_CHIP0_EN|NFLASH_WiDTH32|NFLASH_INDIRECT; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode);
			while(nopcode&FLASH_START_BIT) //polling flash access 31b
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(1);
      		}
      		    
      		pread[i] = FLASH_READ_REG(NFLASH_DATA);    
      		
      	}
      	memcpy(buf, &read_data[col], len);
#endif      	
#else	//direct	
		
		//for (i=col; i<((mtd->oobblock+mtd->oobsize)-col); i++)
		for (i=0,j=0; i<(mtd->oobblock+mtd->oobsize); i++)
		{
			tmp = (unsigned char)FLASH_READ_DATA(addr+i);
			if((i>=col)&&(i<(len+col)))
			{
				buf[j] = (unsigned char)tmp;//(unsigned char)FLASH_READ_DATA(addr+i);
				j++;
			}
			//else
			//	tmp = (unsigned char)FLASH_READ_DATA(addr+i);
		}
#endif		
	}
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif		
	if(debug_f)
		printk("%s : <--\n",__func__);
}

/**
 * csnand_verify_buf - [DEFAULT] Verify chip data against buffer
 * @mtd:	MTD device structure
 * @buf:	buffer containing the data to compare
 * @len:	number of bytes to compare
 *
 * Default verify function for 8bit buswith
 */
static int csnand_verify_buf(struct mtd_info *mtd, const u_char *buf, int len)
{
	int i, page=0;
	struct nand_chip *this = mtd->priv;
	u_char *datatmp, *oobtmp;
	size_t  retlen;
	retlen=0;
	
	datatmp = kmalloc (mtd->oobblock,GFP_KERNEL);
	oobtmp = kmalloc (mtd->oobsize,GFP_KERNEL);
	
	if ((!datatmp)||(!oobtmp)) {
		printk (" Unable to allocate SL2312 NAND MTD device structure.\n");
		
	}
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif
	page = nand_page;
	if(debug_f)
		printk("%s : -->page : %x  datatmp:%p ,oobtmp: %p \n",__func__,page,datatmp,oobtmp);
#ifdef CONFIG_GEMINI_NAND_INDIRECT
	unsigned int nopcode,dent_bit,tt, *prddata,*prdoob;
	
		FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
			ADD5=ADD4=ADD3=ADD2=0;
			if(mtd->oobblock < PAGE512_RAW_SIZE)
				ADD5 = (page>>24)&0xff;
				
    		ADD5=(page>>16)&0xff; 
			ADD4=(page>>8)&0xff;
			ADD3=(page)&0xff;
#if FORCE_DMA_ACCESS	
		pread = (unsigned int *) read_data; 
		//memset(read_data, 0xff, (mtd->oobblock+mtd->oobsize));
		WRITE_DMA_REG(DMA_SYNC, DMA_CH0_SYNC);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_CLR_FIFO); //clear fifo
		WRITE_DMA_REG(DMA_MAIN_CFG, DMA_ENABLE); //enable DMA
		WRITE_DMA_REG(DMA_CH0_SRC_ADDR, (NFLASH_DMA_FIFO+SL2312_FLASH_CTRL_BASE)); //src_address
		WRITE_DMA_REG(DMA_CH0_DST_ADDR, read_dma); //dest_address
		WRITE_DMA_REG(DMA_CH0_LLP, 0x0); //LLP
		WRITE_DMA_REG(DMA_CH0_SIZE, ((mtd->oobblock+mtd->oobsize)/4)); //size
		WRITE_DMA_REG(DMA_CH0_CFG, DMA_ABORT_INT); //CFG
		WRITE_DMA_REG(DMA_CH0_CSR, 0x112c3); //CSR
#endif	    
    	dent_bit=FLASH_READ_REG(NFLASH_TYPE);
		switch(dent_bit&FLASH_SIZE_MASK)
		{
			case FLASH_SIZE_32:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_3|NCNT_CMD_1);//0x0f01ff20);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_64:
			case FLASH_SIZE_128:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_4|NCNT_CMD_1);//0x0f01ff30);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_256:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_2kP_OOB|NCNT_2kP_DATA|NCNT_ADDR_5|NCNT_CMD_2);//0x3f07ff41);
			    nopcode = (NAND_CMD_READSTART<<8)|NAND_CMD_READ0;//0x00003000;
			break;
		}
		nopcode |= (ADD5<<24);
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, nopcode); //write address 0x00
		
		nopcode = 0x0|(ADD4<<24)|(ADD3<<16)|(ADD2<<8);
		FLASH_WRITE_REG(NFLASH_ADDRESS, nopcode); //write address 0x00
		
		prddata = (unsigned int *)datatmp;
		prdoob = (unsigned int *)oobtmp;
#if FORCE_DMA_ACCESS	
		
		// set dma fifo port
		FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_START_BIT|FLASH_RD);
		nopcode=READ_DMA_REG(DMA_TC);
		while(!(nopcode&DMA_CH0_TC)) //polling flash access 31b
      	{
          nopcode=READ_DMA_REG(DMA_TC); 
          udelay(2);
      	}
	    nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL); 		
		while(nopcode&FLASH_START_BIT) //polling flash access 31b
      	{
          nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL);
          udelay(2);
      	}
      	
      	//Disable channel 0 DMA
      	WRITE_DMA_REG(DMA_CH0_CSR, DMA_CH0_DISABLE);
      	//DMA TC int status Rg
      	//write clear int
      	WRITE_DMA_REG(DMA_INT_TC_CLR, DMA_CH0_TC);
      	//Flash status Reg
      	//write clear fifo_int
      	FLASH_WRITE_REG(NFLASH_STATUS, 0x20000);
      	memcpy(datatmp, &read_data[0], mtd->oobblock);
      	memcpy(oobtmp, &read_data[mtd->oobblock], mtd->oobsize);
		
		
#else		
		for(i=0;i<((mtd->oobblock+mtd->oobsize)/4);i++)
        {	
        	nopcode = FLASH_START_BIT | FLASH_RD|NFLASH_CHIP0_EN|NFLASH_WiDTH32|NFLASH_INDIRECT; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode); 
			while(nopcode&FLASH_START_BIT) //polling flash access 31b
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(2);
        	   schedule();
      		}
      		    
      		dent_bit = FLASH_READ_REG(NFLASH_DATA);    
      		if(i<(mtd->oobblock/4))
      		    prddata[i] = dent_bit;
      		else
      			prdoob[i-(mtd->oobblock/4)] = dent_bit;

		}

#endif
#else  //direct		
	//printk("%s (%x): oobtmp",__func__,page);
	int j;
	for(i=0,j=0;i<(mtd->oobblock+mtd->oobsize);i++)
	{
		if(i<mtd->oobblock)
			datatmp[i] = (unsigned char)FLASH_READ_DATA(page*mtd->oobblock +i);
		else
		{
			oobtmp[j] = (unsigned char)FLASH_READ_DATA(page*mtd->oobblock +i);
			//printk("  %02x",oobtmp[i]);
			j++;
		}
	}
	//printk("\n");
	///* read oobdata */
	//for (i = 0; i <  mtd->oobsize; i++) 
	//	oobtmp[i] =(unsigned char) FLASH_READ_DATA(page*mtd->oobblock + mtd->oobblock + i);
#endif		
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif	
	if(len==mtd->oobblock)
	{
		for (i=0; i<len; i++)
		{
			if (buf[i] != datatmp[i])
			{
				kfree(datatmp);
				kfree(oobtmp);
				printk("Data verify error -> page: %x, byte: %x \n",nand_page,i);
				return i;
			}
		}
	}
	else if(len == mtd->oobsize)
	{
		for (i=0; i<len; i++)
		{
			if (buf[i] != oobtmp[i])
			{
				//int j ;
				//printk("\nbuf :\n");
				//for(j=0;j<mtd->oobsize;j++)
				//	printk("  %02x",buf[j]);
				//printk("\n");
				//printk("\oobtmp :\n");
				//for(j=0;j<mtd->oobsize;j++)
				//	printk("  %02x",oobtmp[j]);
				//printk("\n");
				kfree(datatmp);
				kfree(oobtmp);
				printk("OOB verify error -> page: %x, byte: %x \n",nand_page,i);
				return i;
			}
		}
	}
	else
	{
		printk (KERN_WARNING "verify length not match 0x%08x\n", len);
		kfree(datatmp);
		kfree(oobtmp);
		return -1;
	}

	kfree(datatmp);
	kfree(oobtmp);
	if(debug_f)
		printk("%s : <--\n",__func__);
	return 0;

}


/**
 * csnand_write_buf16 - [DEFAULT] write buffer to chip
 * @mtd:	MTD device structure
 * @buf:	data buffer
 * @len:	number of bytes to write
 *
 * Default write function for 16bit buswith
 */
//static void csnand_write_buf16(struct mtd_info *mtd, const u_char *buf, int len)
//{
//	int i;
//	struct nand_chip *this = mtd->priv;
//	u16 *p = (u16 *) buf;
//	len >>= 1;
//
//	//for (i=0; i<len; i++)
//	//	writew(p[i], this->IO_ADDR_W);
//
//}

/**
 * csnand_read_buf16 - [DEFAULT] read chip data into buffer
 * @mtd:	MTD device structure
 * @buf:	buffer to store date
 * @len:	number of bytes to read
 *
 * Default read function for 16bit buswith
 */
//static void csnand_read_buf16(struct mtd_info *mtd, u_char *buf, int len)
//{
//	int i;
//	struct nand_chip *this = mtd->priv;
//	u16 *p = (u16 *) buf;
//	len >>= 1;
//
//	//for (i=0; i<len; i++)
//	//	p[i] = readw(this->IO_ADDR_R);
//}

/**
 * csnand_verify_buf16 - [DEFAULT] Verify chip data against buffer
 * @mtd:	MTD device structure
 * @buf:	buffer containing the data to compare
 * @len:	number of bytes to compare
 *
 * Default verify function for 16bit buswith
 */
//static int csnand_verify_buf16(struct mtd_info *mtd, const u_char *buf, int len)
//{
//	int i;
//	struct nand_chip *this = mtd->priv;
//	u16 *p = (u16 *) buf;
//	len >>= 1;
//
//	//for (i=0; i<len; i++)
//	//	if (p[i] != readw(this->IO_ADDR_R))
//	//		return -EFAULT;
//
//	return 0;
//}

/**
 * csnand_block_bad - [DEFAULT] Read bad block marker from the chip
 * @mtd:	MTD device structure
 * @ofs:	offset from device start
 * @getchip:	0, if the chip is already selected
 *
 * Check, if the block is bad.
 */
 
static int csnand_block_bad(struct mtd_info *mtd, loff_t ofs, int getchip)
{
	static unsigned char *tmpbuf, *tmpoobbuf;
	size_t  retlen;
	int page, chipnr, res = 0;
	struct nand_chip *this = mtd->priv;
	unsigned short bad;
	if(debug_f)
		printk("%s : -->\n",__func__);
	if (getchip) {
		page = (int)(ofs >> this->page_shift);
		chipnr = (int)(ofs >> this->chip_shift);

		/* Grab the lock and see if the device is available */
		csnand_get_device (this, mtd, FL_READING);
		
		/* Select the NAND device */
		this->select_chip(mtd, chipnr);
	} else
		page = (int) ofs;
	
	if (getchip)
		csnand_read_ecc (mtd, (page<<this->page_shift), mtd->oobblock , &retlen, tmpbuf, tmpoobbuf, NULL);
	else
		csnand_read_ecc (mtd, page, mtd->oobblock , &retlen, tmpbuf, tmpoobbuf, NULL);
	
	if(((mtd->oobblock < PAGE512_RAW_SIZE)&&(tmpoobbuf[5] != 0xff))||((mtd->oobblock > PAGE512_RAW_SIZE)&&(tmpoobbuf[0] != 0xff)))
	{

		if(debug_f)
		printk("%s : <--\n",__func__);
		return 1;
	}
	
	if(debug_f)
		printk("%s : <--\n",__func__);

	return res;
}

/**
 * csnand_default_block_markbad - [DEFAULT] mark a block bad
 * @mtd:	MTD device structure
 * @ofs:	offset from device start
 *
 * This is the default implementation, which can be overridden by
 * a hardware specific driver.
*/

static int csnand_default_block_markbad(struct mtd_info *mtd, loff_t ofs)
{
	struct nand_chip *this = mtd->priv;
	u_char buf[2] = {0, 0};
	size_t	retlen;
	int block;
	if(debug_f)
		printk("%s : -->\n",__func__);
	/* Get block number */
	block = ((int) ofs) >> this->bbt_erase_shift;
	if (this->bbt)
		this->bbt[block >> 2] |= 0x01 << ((block & 0x03) << 1);

	/* Do we have a flash based bad block table ? */
	if (this->options & NAND_USE_FLASH_BBT)
		return nand_update_bbt (mtd, ofs);

	/* We write two bytes, so we dont have to mess with 16 bit access */
	//ofs += mtd->oobsize + (this->badblockpos & ~0x01);
	ofs += (this->badblockpos & ~0x01);
	return csnand_write_oob (mtd, ofs , 2, &retlen, buf);
}

/**
 * csnand_check_wp - [GENERIC] check if the chip is write protected
 * @mtd:	MTD device structure
 * Check, if the device is write protected
 *
 * The function expects, that the device is already selected
 */
static int csnand_check_wp (struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;
	/* Check the WP bit */
	int ready;
	
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif	
	//if(debug_f)
	//	printk("%s : -->\n",__func__);
	FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0); //set 31b = 0
	FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_EMPTY_ADDR|NCNT_ADDR_1);//0x7f000070); //set only command no address and two data
	
	FLASH_WRITE_REG(NFLASH_CMD_ADDR, NAND_CMD_STATUS); //write read status command
	
	ready = FLASH_START_BIT|FLASH_RD|DWIDTH|CHIP_EN; //set start bit & 8bits read command
	FLASH_WRITE_REG(NFLASH_ACCESS, ready); 
	
	while(ready&FLASH_START_BIT) //polling flash access 31b
    {
        ready=FLASH_READ_REG(NFLASH_ACCESS);
        //sl2312_flash_delay();
		schedule();
    }	
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif	
      	ready=FLASH_READ_REG(NFLASH_DATA)&0xff;
      	if(debug_f)
		printk("%s : <--\n",__func__);
//#ifdef CONFIG_SL2312_SHARE_PIN	
//	mtd_unlock();				// sl2312 share pin lock
//#endif		
	return (ready & NAND_STATUS_WP) ? 0 : 1;
}

/**
 * csnand_block_checkbad - [GENERIC] Check if a block is marked bad
 * @mtd:	MTD device structure
 * @ofs:	offset from device start
 * @getchip:	0, if the chip is already selected
 * @allowbbt:	1, if its allowed to access the bbt area
 *
 * Check, if the block is bad. Either by reading the bad block table or
 * calling of the scan function.
 */
static int csnand_block_checkbad (struct mtd_info *mtd, loff_t ofs, int getchip, int allowbbt)
{
	struct nand_chip *this = mtd->priv;
	if(debug_f)
		printk("%s : -->\n",__func__);
	if (!this->bbt)
		return this->block_bad(mtd, ofs, getchip);

	/* Return info from the table */
	return nand_isbad_bbt (mtd, ofs, allowbbt);
}

/*
 * Wait for the ready pin, after a command
 * The timeout is catched later.
 */
static void csnand_wait_ready(struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;
	unsigned long	timeo = jiffies + 2;

	/* wait until command is processed or timeout occures */
	do {
		if (this->dev_ready(mtd))
			return;
		touch_softlockup_watchdog();
	} while (time_before(jiffies, timeo));
}

/**
 * csnand_command - [DEFAULT] Send command to NAND device
 * @mtd:	MTD device structure
 * @command:	the command to be sent
 * @column:	the column address for this command, -1 if none
 * @page_addr:	the page address for this command, -1 if none
 *
 * Send command to NAND device. This function is used for small page
 * devices (256/512 Bytes per page)
 */
static void csnand_command (struct mtd_info *mtd, unsigned command, int column, int page_addr)
{
	register struct nand_chip *this = mtd->priv;
	int opcode;
	//if(debug_f)
	//	printk("%s : -->\n",__func__);
		
	/* Begin command latch cycle */
	this->hwcontrol(mtd, NAND_CTL_SETCLE);
	/*
	 * Write out the command to the device.
	 */
	if (command == NAND_CMD_SEQIN) {
		int readcmd;
    
		if (column >= mtd->oobblock) {
			/* OOB area */
			column -= mtd->oobblock;
			readcmd = NAND_CMD_READOOB;
		} else if (column < 256) {
			/* First 256 bytes --> READ0 */
			readcmd = NAND_CMD_READ0;
		} else {
			column -= 256;
			readcmd = NAND_CMD_READ1;
		}
		//this->write_byte(mtd, readcmd);
	}
	//this->write_byte(mtd, command);
    
	/* Set ALE and clear CLE to start address cycle */
	this->hwcontrol(mtd, NAND_CTL_CLRCLE);
    
	if (column != -1 || page_addr != -1) {
		this->hwcontrol(mtd, NAND_CTL_SETALE);
    
		/* Serially input address */
		if (column != -1) {
			/* Adjust columns for 16 bit buswidth */
			if (this->options & NAND_BUSWIDTH_16)
				column >>= 1;
				nand_col=column;
			//this->write_byte(mtd, column);
		}
		if (page_addr != -1) {
			nand_page = page_addr;
			//this->write_byte(mtd, (unsigned char) (page_addr & 0xff));
			//this->write_byte(mtd, (unsigned char) ((page_addr >> 8) & 0xff));
			/* One more address cycle for devices > 32MiB */
			//if (this->chipsize > (32 << 20))
				//this->write_byte(mtd, (unsigned char) ((page_addr >> 16) & 0x0f));
		}
		/* Latch in address */
		this->hwcontrol(mtd, NAND_CTL_CLRALE);
	}

	/*
	 * program and erase have their own busy handlers
	 * status and sequential in needs no delay
	*/
	switch (command) {

	case NAND_CMD_PAGEPROG:
	case NAND_CMD_ERASE1:
	case NAND_CMD_ERASE2:
	case NAND_CMD_SEQIN:
	case NAND_CMD_STATUS:
		/*
		 * Write out the command to the device.
		 */
		if (column != -1 || page_addr != -1) {
			
			/* Serially input address */
			if (column != -1)
				//FLASH_WRITE_REG(NFLASH_ADDRESS,column);
				nand_col=column;
				
			opcode = FLASH_READ_REG(NFLASH_ADDRESS);
			
			if (page_addr != -1) 
				//FLASH_WRITE_REG(NFLASH_ADDRESS,opcode|(page_addr<<8));
				nand_page = page_addr;
			
		}
		return;

	case NAND_CMD_RESET:
		if (this->dev_ready)	
			break;
		FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0); //set 31b = 0
		FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_EMPTY_DATA|NCNT_EMPTY_ADDR|NCNT_CMD_1);//0x7f0fff70); //set only command and no other data
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, NAND_CMD_RESET); //write reset command
		
		opcode = FLASH_START_BIT|FLASH_RD|DWIDTH|CHIP_EN; //set start bit & 8bits read command
		FLASH_WRITE_REG(NFLASH_ACCESS, opcode); 
		
		while(opcode&FLASH_START_BIT) //polling flash access 31b
      	{
           opcode=FLASH_READ_REG(NFLASH_ACCESS);
           //sl2312_flash_delay();
           schedule();
      	}
      	udelay(2);
		//while ( !(csnand_device_ready(mtd) & 0x40));
		while ( !((FLASH_READ_REG(NFLASH_DATA)&0xff) & 0x40));
		{
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif	
			//sl2312_flash_delay();
			schedule();
			return;
		}

	/* This applies to read commands */
	default:
		/*
		 * If we don't have access to the busy pin, we apply the given
		 * command delay
		*/
		if (!this->dev_ready) {
			udelay (this->chip_delay);
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif				
			return;
		}
	}
	/* Apply this short delay always to ensure that we do wait tWB in
	 * any case on any machine. */
	ndelay (100);

	csnand_wait_ready(mtd);
}

/**
 * csnand_command_lp - [DEFAULT] Send command to NAND large page device
 * @mtd:	MTD device structure
 * @command:	the command to be sent
 * @column:	the column address for this command, -1 if none
 * @page_addr:	the page address for this command, -1 if none
 *
 * Send command to NAND device. This is the version for the new large page devices
 * We dont have the seperate regions as we have in the small page devices.
 * We must emulate NAND_CMD_READOOB to keep the code compatible.
 *
 */
#if 0 
static void csnand_command_lp (struct mtd_info *mtd, unsigned command, int column, int page_addr)
{
	register struct nand_chip *this = mtd->priv;

	/* Emulate NAND_CMD_READOOB */
	if (command == NAND_CMD_READOOB) {
		column += mtd->oobblock;
		command = NAND_CMD_READ0;
	}


	/* Begin command latch cycle */
	this->hwcontrol(mtd, NAND_CTL_SETCLE);
	/* Write out the command to the device. */
	this->write_byte(mtd, (command & 0xff));
	/* End command latch cycle */
	this->hwcontrol(mtd, NAND_CTL_CLRCLE);

	if (column != -1 || page_addr != -1) {
		this->hwcontrol(mtd, NAND_CTL_SETALE);

		/* Serially input address */
		if (column != -1) {
			/* Adjust columns for 16 bit buswidth */
			if (this->options & NAND_BUSWIDTH_16)
				column >>= 1;
			this->write_byte(mtd, column & 0xff);
			this->write_byte(mtd, column >> 8);
		}
		if (page_addr != -1) {
			this->write_byte(mtd, (unsigned char) (page_addr & 0xff));
			this->write_byte(mtd, (unsigned char) ((page_addr >> 8) & 0xff));
			/* One more address cycle for devices > 128MiB */
			if (this->chipsize > (128 << 20))
				this->write_byte(mtd, (unsigned char) ((page_addr >> 16) & 0xff));
		}
		/* Latch in address */
		this->hwcontrol(mtd, NAND_CTL_CLRALE);
	}

	/*
	 * program and erase have their own busy handlers
	 * status, sequential in, and deplete1 need no delay
	 */
	switch (command) {

	case NAND_CMD_CACHEDPROG:
	case NAND_CMD_PAGEPROG:
	case NAND_CMD_ERASE1:
	case NAND_CMD_ERASE2:
	case NAND_CMD_SEQIN:
	case NAND_CMD_STATUS:
	case NAND_CMD_DEPLETE1:
		return;

	/*
	 * read error status commands require only a short delay
	 */
	case NAND_CMD_STATUS_ERROR:
	case NAND_CMD_STATUS_ERROR0:
	case NAND_CMD_STATUS_ERROR1:
	case NAND_CMD_STATUS_ERROR2:
	case NAND_CMD_STATUS_ERROR3:
		udelay(this->chip_delay);
		return;

	case NAND_CMD_RESET:
		if (this->dev_ready)
			break;
		udelay(this->chip_delay);
		this->hwcontrol(mtd, NAND_CTL_SETCLE);
		this->write_byte(mtd, NAND_CMD_STATUS);
		this->hwcontrol(mtd, NAND_CTL_CLRCLE);
		while ( !(this->read_byte(mtd) & NAND_STATUS_READY));
		return;

	case NAND_CMD_READ0:
		/* Begin command latch cycle */
		this->hwcontrol(mtd, NAND_CTL_SETCLE);
		/* Write out the start read command */
		this->write_byte(mtd, NAND_CMD_READSTART);
		/* End command latch cycle */
		this->hwcontrol(mtd, NAND_CTL_CLRCLE);
		/* Fall through into ready check */

	/* This applies to read commands */
	default:
		/*
		 * If we don't have access to the busy pin, we apply the given
		 * command delay
		*/
		if (!this->dev_ready) {
			udelay (this->chip_delay);
			return;
		}
	}

	/* Apply this short delay always to ensure that we do wait tWB in
	 * any case on any machine. */
	ndelay (100);

	csnand_wait_ready(mtd);
}
#endif 
/**
 * csnand_get_device - [GENERIC] Get chip for selected access
 * @this:	the nand chip descriptor
 * @mtd:	MTD device structure
 * @new_state:	the state which is requested
 *
 * Get the device and lock it for exclusive access
 */
static int csnand_get_device (struct nand_chip *this, struct mtd_info *mtd, int new_state)
{
	struct nand_chip *active;
	spinlock_t *lock;
	wait_queue_head_t *wq;
	DECLARE_WAITQUEUE (wait, current);

	lock = (this->controller) ? &this->controller->lock : &this->chip_lock;
	wq = (this->controller) ? &this->controller->wq : &this->wq;
retry:
	active = this;
	spin_lock(lock);

	/* Hardware controller shared among independend devices */
	if (this->controller) {
		if (this->controller->active)
			active = this->controller->active;
		else
			this->controller->active = this;
	}
	if (active == this && this->state == FL_READY) {
		this->state = new_state;
		spin_unlock(lock);
		return 0;
	}
	if (new_state == FL_PM_SUSPENDED) {
		spin_unlock(lock);
		return (this->state == FL_PM_SUSPENDED) ? 0 : -EAGAIN;
	}
	set_current_state(TASK_UNINTERRUPTIBLE);
	add_wait_queue(wq, &wait);
	spin_unlock(lock);
	schedule();
	remove_wait_queue(wq, &wait);
	goto retry;
}

/**
 * csnand_wait - [DEFAULT]  wait until the command is done
 * @mtd:	MTD device structure
 * @this:	NAND chip structure
 * @state:	state to select the max. timeout value
 *
 * Wait for command done. This applies to erase and program only
 * Erase can take up to 400ms and program up to 20ms according to
 * general NAND and SmartMedia specs
 *
*/
static int csnand_wait(struct mtd_info *mtd, struct nand_chip *this, int state)
{

	unsigned long	timeo = jiffies;
	int	status;

	if (state == FL_ERASING)
		 timeo += (HZ * 400) / 1000;
	else
		 timeo += (HZ * 20) / 1000;

	/* Apply this short delay always to ensure that we do wait tWB in
	 * any case on any machine. */
	//ndelay (100);

	if ((state == FL_ERASING) && (this->options & NAND_IS_AND))
		this->cmdfunc (mtd, NAND_CMD_STATUS_MULTI, -1, -1);
	else
		this->cmdfunc (mtd, NAND_CMD_STATUS, -1, -1);

	while (time_before(jiffies, timeo)) {
		/* Check, if we were interrupted */
		if (this->state != state)
			return 0;

		if (this->dev_ready) {
			if (this->dev_ready(mtd))
				break;
		} else {
			if (this->read_byte(mtd) & NAND_STATUS_READY)
				break;
		}
		cond_resched();
	}
	status = (int) this->read_byte(mtd);
	return status;
}

/**
 * csnand_write_page - [GENERIC] write one page
 * @mtd:	MTD device structure
 * @this:	NAND chip structure
 * @page: 	startpage inside the chip, must be called with (page & this->pagemask)
 * @oob_buf:	out of band data buffer
 * @oobsel:	out of band selecttion structre
 * @cached:	1 = enable cached programming if supported by chip
 *
 * Nand_page_program function is used for write and writev !
 * This function will always program a full page of data
 * If you call it with a non page aligned buffer, you're lost :)
 *
 * Cached programming is not supported yet.
 */
static int csnand_write_page (struct mtd_info *mtd, struct nand_chip *this, int page,
	u_char *oob_buf,  struct nand_oobinfo *oobsel, int cached)
{
	int 	i, status;
	u_char	ecc_code[32];
	int	eccmode = oobsel->useecc ? this->eccmode : NAND_ECC_NONE;
	int  	*oob_config = oobsel->eccpos;
	int	datidx = 0, eccidx = 0, eccsteps = this->eccsteps;
	int	eccbytes = 0;
	if(debug_f)
		printk("%s : -->page: %x\n",__func__,(unsigned int) page);
	/* FIXME: Enable cached programming */
	cached = 0;

	/* Send command to begin auto page programming */
	this->cmdfunc (mtd, NAND_CMD_SEQIN, 0x00, page);
	nand_col = 0;
	/* Write out complete page of data, take care of eccmode */
	switch (eccmode) {
	/* No ecc, write all */
	case NAND_ECC_NONE:
#ifndef CONFIG_YAFFS_FS		
		printk (KERN_WARNING "Writing data without ECC to NAND-FLASH is not recommended\n");
#endif		
		FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0);
		//this->write_buf(mtd, this->data_poi, mtd->oobblock);
		break;
	
	/* Software ecc 3/256, write all */
	case NAND_ECC_SOFT:
		FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0);
		for (; eccsteps; eccsteps--) {
			this->calculate_ecc(mtd, &this->data_poi[datidx], ecc_code);			
			if(debug_f)
					printk("%s : -->calculate_ecc: %x %x %x\n",__func__,ecc_code[0],ecc_code[1],ecc_code[2]);
			for (i = 0; i < 3; i++, eccidx++)
			{
				oob_buf[oob_config[eccidx]] = ecc_code[i];
				if(debug_f)
					printk("oob_buf[oob_config[eccidx]]: %x, oob_config[eccidx]:%x\n",oob_buf[oob_config[eccidx]],oob_config[eccidx]);
			}
			datidx += this->eccsize;
		}
		//this->write_buf(mtd, this->data_poi, mtd->oobblock);
		break;
		
	/* Hardware ecc 3 byte / 256 data, write first half, get ecc, then second, if 512 byte pagesize */	
	case NAND_ECC_HW3_256:		
		break;
				
	/* Hardware ecc 3 byte / 512 byte data, write full page */	
	case NAND_ECC_HW3_512:	
		FLASH_WRITE_REG(NFLASH_ECC_CONTROL, FLASH_START_BIT|ECC_CLR); //set 31b = 0

	/* Hardware ecc 6 byte / 512 byte data, write full page */	
	case NAND_ECC_HW6_512:	
		break;
		
	default:
		printk (KERN_WARNING "Invalid NAND_ECC_MODE %d\n", this->eccmode);
		FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0); 
		eccbytes = this->eccbytes;
		for (; eccsteps; eccsteps--) {
			/* enable hardware ecc logic for write */
			this->enable_hwecc(mtd, NAND_ECC_WRITE);
			this->write_buf(mtd, &this->data_poi[datidx], this->eccsize);
			this->calculate_ecc(mtd, &this->data_poi[datidx], ecc_code);
			for (i = 0; i < eccbytes; i++, eccidx++)
				oob_buf[oob_config[eccidx]] = ecc_code[i];
			/* If the hardware ecc provides syndromes then
			 * the ecc code must be written immidiately after
			 * the data bytes (words) */
			//if (this->options & NAND_HWECC_SYNDROME)
			//	this->write_buf(mtd, ecc_code, eccbytes);
			datidx += this->eccsize;
		}
		break;
	}
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif	
  
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif

#ifdef CONFIG_GEMINI_NAND_INDIRECT
	unsigned int nopcode,dent_bit,tt,*pwt;
	ADD5=ADD4=ADD3=ADD2=0;
	if(mtd->oobblock < PAGE512_RAW_SIZE)
				ADD5 = (page>>24)&0xff;
				
    		ADD5=(page>>16)&0xff; 
			ADD4=(page>>8)&0xff;
			ADD3=(page)&0xff;
#if FORCE_DMA_ACCESS	
		pwrite = (unsigned int *) write_data;
		
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_CLR_FIFO); //clear fifo
		WRITE_DMA_REG(DMA_MAIN_CFG, DMA_ENABLE); //enable DMA
		WRITE_DMA_REG(DMA_CH0_SRC_ADDR, write_dma); //src_address
		WRITE_DMA_REG(DMA_CH0_DST_ADDR, NFLASH_DMA_FIFO+SL2312_FLASH_CTRL_BASE); //dest_address
		WRITE_DMA_REG(DMA_CH0_LLP, 0x0); //LLP
		WRITE_DMA_REG(DMA_CH0_SIZE, ((mtd->oobblock+mtd->oobsize)/4)); //size
		WRITE_DMA_REG(DMA_CH0_CFG, DMA_ABORT_INT); //CFG
		WRITE_DMA_REG(DMA_CH0_CSR, 0x11295); //CSR
#endif		
	dent_bit=FLASH_READ_REG(NFLASH_TYPE);
		switch(dent_bit&FLASH_SIZE_MASK)
		{
			case FLASH_SIZE_32:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_3|NCNT_CMD_1);//0x0f01ff21); 
		    	//nopcode = 0x00001080;
			break;
			
			case FLASH_SIZE_64:
			case FLASH_SIZE_128:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_4|NCNT_CMD_1);//0x0f01ff31); 
		    	//nopcode = 0x00001080;
			break;
			
			case FLASH_SIZE_256:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_2kP_OOB|NCNT_2kP_DATA|NCNT_ADDR_5|NCNT_CMD_2);//0x3f07ff41); 
		    	//nopcode = 0x00001080;
			break;
		}
		nopcode = (NAND_CMD_PAGEPROG<<8)|NAND_CMD_SEQIN;//0x00001080;
		nopcode |= (ADD5<<24);
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, nopcode); 
		    
		nopcode = 0x0|(ADD4<<24)|(ADD3<<16)|(ADD2<<8);
		FLASH_WRITE_REG(NFLASH_ADDRESS, nopcode); 
		pwt = (unsigned int *) this->data_poi;
#if FORCE_DMA_ACCESS	

		memcpy(write_data, this->data_poi, mtd->oobblock);
		
#else		
		for(i=0;i<(mtd->oobblock/4);i++)
		{
			tt = pwt[i];			
			FLASH_WRITE_REG(NFLASH_DATA, tt); 
			nopcode = FLASH_START_BIT | FLASH_WT |NFLASH_CHIP0_EN|NFLASH_WiDTH32|NFLASH_INDIRECT; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode); 
			
			while(nopcode&FLASH_START_BIT) 
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(2);
        	   schedule();
      		}    		 	
		}
#endif		
#else 	//direct 	
	for(i=0;i<mtd->oobblock;i++)
	{
		//udelay(5);
		FLASH_WRITE_DATA((page<<this->page_shift)+i,this->data_poi[i]);
		
	}
#endif

	nand_col = mtd->oobblock;
	/* Write out OOB data */
	if (this->options & NAND_HWECC_SYNDROME)
	{
		printk("page write : NAND_HWECC_SYNDROME\n");
		//this->write_buf(mtd, &oob_buf[oobsel->eccbytes], mtd->oobsize - oobsel->eccbytes);
	}
	else
	{
		//this->write_buf(mtd, oob_buf, mtd->oobsize);
#ifdef CONFIG_GEMINI_NAND_INDIRECT
		pwt = (unsigned int *) oob_buf;
#if FORCE_DMA_ACCESS	
		memcpy(&write_data[mtd->oobblock], oob_buf, mtd->oobsize);
		
		// set dma fifo port
		FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_START_BIT|FLASH_WT);//0x80003000);
		//nopcode=READ_DMA_REG(DMA_TC);
		//while(!(nopcode&0x01)) //polling flash access 31b
      	//{
        //  nopcode=READ_DMA_REG(DMA_TC); 
        //  udelay(2);
      	//}
	    nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL); 		
		while(nopcode&FLASH_START_BIT) //polling flash access 31b
      	{
          nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL);
          udelay(2);
      	}
      	
      	//Disable channel 0 DMA
      	WRITE_DMA_REG(DMA_CH0_CSR, DMA_CH0_DISABLE);
      	//DMA TC int status Rg
      	//write clear int
      	WRITE_DMA_REG(DMA_INT_TC_CLR, DMA_CH0_TC);
      	//Flash status Reg
      	//write clear fifo_int
      	FLASH_WRITE_REG(NFLASH_STATUS, 0x20000);
      		
		
#else		
		for(i=0;i<(mtd->oobsize/4);i++)
		{
			tt = pwt[i];
			FLASH_WRITE_REG(NFLASH_DATA, tt); //write address 0x00
			nopcode = FLASH_START_BIT | FLASH_WT |NFLASH_CHIP0_EN|NFLASH_INDIRECT|NFLASH_WiDTH32; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode); 
			
			while(nopcode&FLASH_START_BIT) //polling flash access 31b
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(2);
        	   schedule();
      		}    		 	
		}
	
#endif		
	
#else 	//direct
    	for(i=0;i<mtd->oobsize;i++)
    	{
    		//udelay(5);
			FLASH_WRITE_DATA((page<<this->page_shift)+mtd->oobblock+i,oob_buf[i]);
		}
#endif 		
		
	}

	/* Send command to actually program the data */
	this->cmdfunc (mtd, cached ? NAND_CMD_CACHEDPROG : NAND_CMD_PAGEPROG, -1, -1);

	if (!cached) {
		/* call wait ready function */
		status = this->waitfunc (mtd, this, FL_WRITING);

		/* See if operation failed and additional status checks are available */
		if ((status & NAND_STATUS_FAIL) && (this->errstat)) {
			status = this->errstat(mtd, this, FL_WRITING, status, page);
		}

		/* See if device thinks it succeeded */
		if (status & NAND_STATUS_FAIL) {
			DEBUG (MTD_DEBUG_LEVEL0, "%s: " "Failed write, page 0x%08x, ", __FUNCTION__, page);
			return -EIO;
		}
	} else {
		/* FIXME: Implement cached programming ! */
		/* wait until cache is ready*/
		// status = this->waitfunc (mtd, this, FL_CACHEDRPG);
	}
	return 0;
}

/**
 * csnand_read - [MTD Interface] MTD compability function for csnand_do_read_ecc
 * @mtd:	MTD device structure
 * @from:	offset to read from
 * @len:	number of bytes to read
 * @retlen:	pointer to variable to store the number of read bytes
 * @buf:	the databuffer to put data
 *
 * This function simply calls csnand_do_read_ecc with oob buffer and oobsel = NULL
 * and flags = 0xff
 */
static int csnand_read (struct mtd_info *mtd, loff_t from, size_t len, size_t * retlen, u_char * buf)
{
	return csnand_do_read_ecc (mtd, from, len, retlen, buf, NULL, &mtd->oobinfo, 0xff);
}


/**
 * csnand_read_ecc - [MTD Interface] MTD compability function for csnand_do_read_ecc
 * @mtd:	MTD device structure
 * @from:	offset to read from
 * @len:	number of bytes to read
 * @retlen:	pointer to variable to store the number of read bytes
 * @buf:	the databuffer to put data
 * @oob_buf:	filesystem supplied oob data buffer
 * @oobsel:	oob selection structure
 *
 * This function simply calls csnand_do_read_ecc with flags = 0xff
 */
static int csnand_read_ecc (struct mtd_info *mtd, loff_t from, size_t len,
			  size_t * retlen, u_char * buf, u_char * oob_buf, struct nand_oobinfo *oobsel)
{
	/* use userspace supplied oobinfo, if zero */
	if (oobsel == NULL)
		oobsel = &mtd->oobinfo;
	return csnand_do_read_ecc(mtd, from, len, retlen, buf, oob_buf, oobsel, 0xff);
}


/**
 * csnand_do_read_ecc - [MTD Interface] Read data with ECC
 * @mtd:	MTD device structure
 * @from:	offset to read from
 * @len:	number of bytes to read
 * @retlen:	pointer to variable to store the number of read bytes
 * @buf:	the databuffer to put data
 * @oob_buf:	filesystem supplied oob data buffer (can be NULL)
 * @oobsel:	oob selection structure
 * @flags:	flag to indicate if csnand_get_device/csnand_release_device should be preformed
 *		and how many corrected error bits are acceptable:
 *		  bits 0..7 - number of tolerable errors
 *		  bit  8    - 0 == do not get/release chip, 1 == get/release chip
 *
 * NAND read with ECC
 */
int csnand_do_read_ecc (struct mtd_info *mtd, loff_t from, size_t len,
			     size_t * retlen, u_char * buf, u_char * oob_buf,
			     struct nand_oobinfo *oobsel, int flags)
{

	int i, j, col, realpage, page, end, ecc, chipnr, sndcmd = 1;
	int read = 0, oob = 0, ecc_status = 0, ecc_failed = 0;
	struct nand_chip *this = mtd->priv;
	u_char *data_poi, *oob_data = oob_buf;
	u_char ecc_calc[32];
	u_char ecc_code[32];
        int eccmode, eccsteps;
	int	*oob_config, datidx;
	int	blockcheck = (1 << (this->phys_erase_shift - this->page_shift)) - 1;
	int	eccbytes;
	int	compareecc = 1;
	int	oobreadlen;

	
	DEBUG (MTD_DEBUG_LEVEL3, "csnand_read_ecc: from = 0x%08x, len = %i\n", (unsigned int) from, (int) len);

	/* Do not allow reads past end of device */
	if ((from + len) > mtd->size) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_read_ecc: Attempt read beyond end of device\n");
		*retlen = 0;
		return -EINVAL;
	}

	if(debug_f)
		printk("%s : -->form : %x, len: %x \n",__func__,(unsigned int) from, (unsigned int) len);
		
	/* Grab the lock and see if the device is available */
	//if (flags & csnand_get_device)
		csnand_get_device (this, mtd, FL_READING);

	/* Autoplace of oob data ? Use the default placement scheme */
	if (oobsel->useecc == MTD_NANDECC_AUTOPLACE)
		oobsel = this->autooob;

	eccmode = oobsel->useecc ? this->eccmode : NAND_ECC_NONE;
	oob_config = oobsel->eccpos;

	/* Select the NAND device */
	chipnr = (int)(from >> this->chip_shift);
	this->select_chip(mtd, chipnr);

	/* First we calculate the starting page */
	realpage = (int) (from >> this->page_shift);
	page = realpage & this->pagemask;

	
	/* Get raw starting column */
	col = from & (mtd->oobblock - 1);

	end = mtd->oobblock;
	ecc = this->eccsize;
	eccbytes = this->eccbytes;

	if ((eccmode == NAND_ECC_NONE) || (this->options & NAND_HWECC_SYNDROME))
		compareecc = 0;

	oobreadlen = mtd->oobsize;
	if (this->options & NAND_HWECC_SYNDROME)
		oobreadlen -= oobsel->eccbytes;

#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif		

	/* Loop until all data read */
	while (read < len) {

		int aligned = (!col && (len - read) >= end);
		/*
		 * If the read is not page aligned, we have to read into data buffer
		 * due to ecc, else we read into return buffer direct
		 */
		if (aligned)
			data_poi = &buf[read];
		else
			data_poi = this->data_buf;

		/* Check, if we have this page in the buffer
		 *
		 * FIXME: Make it work when we must provide oob data too,
		 * check the usage of data_buf oob field
		 */
		if (realpage == this->pagebuf && !oob_buf) {
			/* aligned read ? */
			if (aligned)
				memcpy (data_poi, this->data_buf, end);
			goto readdata;
		}

		/* Check, if we must send the read command */
		if (sndcmd) {
			this->cmdfunc (mtd, NAND_CMD_READ0, 0x00, page);
			sndcmd = 0;
		}

		/* get oob area, if we have no oob buffer from fs-driver */
		if (!oob_buf || oobsel->useecc == MTD_NANDECC_AUTOPLACE ||
			oobsel->useecc == MTD_NANDECC_AUTOPL_USR)
			oob_data = &this->data_buf[end];

		eccsteps = this->eccsteps;
		nand_col = 0;
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif	
#ifdef CONFIG_GEMINI_NAND_INDIRECT
	unsigned int nopcode,dent_bit;

			ADD5=ADD4=ADD3=ADD2=0;

    		if(mtd->oobblock < PAGE512_RAW_SIZE)
				ADD5 = (page>>24)&0xff;
				
    		ADD5=(page>>16)&0xff; 
			ADD4=(page>>8)&0xff;
			ADD3=(page)&0xff;
    		
#if FORCE_DMA_ACCESS	
		pread = (unsigned int *) read_data; 
		//memset(read_data, 0xff, (mtd->oobblock+mtd->oobsize));
		WRITE_DMA_REG(DMA_SYNC, DMA_CH0_SYNC);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_CLR_FIFO); //clear fifo
		WRITE_DMA_REG(DMA_MAIN_CFG, DMA_ENABLE); //enable DMA
		WRITE_DMA_REG(DMA_CH0_SRC_ADDR, (NFLASH_DMA_FIFO+SL2312_FLASH_CTRL_BASE)); //src_address
		WRITE_DMA_REG(DMA_CH0_DST_ADDR, read_dma); //dest_address
		WRITE_DMA_REG(DMA_CH0_LLP, 0x0); //LLP
		WRITE_DMA_REG(DMA_CH0_SIZE, ((mtd->oobblock+mtd->oobsize)/4)); //size
		WRITE_DMA_REG(DMA_CH0_CFG, DMA_ABORT_INT); //CFG
		WRITE_DMA_REG(DMA_CH0_CSR, 0x112c3); //CSR
#endif	
    
    	dent_bit=FLASH_READ_REG(NFLASH_TYPE);
		switch(dent_bit&FLASH_SIZE_MASK)
		{
			case FLASH_SIZE_32:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_3|NCNT_CMD_1);//0x0f01ff20);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_64:
			case FLASH_SIZE_128:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_4|NCNT_CMD_1);//0x0f01ff30);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_256:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_2kP_OOB|NCNT_2kP_DATA|NCNT_ADDR_5|NCNT_CMD_2);//0x3f07ff41);
			    nopcode = (NAND_CMD_READSTART<<8)|NAND_CMD_READ0;//0x00003000;
			break;
		}
		nopcode |= (ADD5<<24);
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, nopcode); //write address 0x00
		
		nopcode = 0x0|(ADD4<<24)|(ADD3<<16)|(ADD2<<8);
		FLASH_WRITE_REG(NFLASH_ADDRESS, nopcode); //write address 0x00
#if FORCE_DMA_ACCESS	
		
		// set dma fifo port
		FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_START_BIT|FLASH_RD);
		nopcode=READ_DMA_REG(DMA_TC);
		while(!(nopcode&DMA_CH0_TC)) //polling flash access 31b
      	{
          nopcode=READ_DMA_REG(DMA_TC); 
          udelay(2);
      	}
	    nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL); 		
		while(nopcode&FLASH_START_BIT) //polling flash access 31b
      	{
          nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL);
          udelay(2);
      	}
      	
      	//Disable channel 0 DMA
      	WRITE_DMA_REG(DMA_CH0_CSR, DMA_CH0_DISABLE);
      	//DMA TC int status Rg
      	//write clear int
      	WRITE_DMA_REG(DMA_INT_TC_CLR, DMA_CH0_TC);
      	//Flash status Reg
      	//write clear fifo_int
      	FLASH_WRITE_REG(NFLASH_STATUS, 0x20000);
      	memcpy(data_poi, &read_data[0], end);
      	memcpy(&oob_data[mtd->oobsize - oobreadlen], &read_data[mtd->oobblock+mtd->oobsize - oobreadlen], oobreadlen);
		
#else				
		pread = (unsigned int *) read_data;
		for(i=0,j=0;i<((mtd->oobblock+mtd->oobsize)/4);i++)
        {
			nopcode = FLASH_START_BIT | FLASH_RD|NFLASH_CHIP0_EN|NFLASH_WiDTH32|NFLASH_INDIRECT; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode);
			while(nopcode&FLASH_START_BIT) //polling flash access 31b
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(1);
      		}
      		    
      		pread[i] = FLASH_READ_REG(NFLASH_DATA);    
      		
      	}
      	memcpy(data_poi, &read_data[0], len);
      	memcpy(&oob_data[mtd->oobsize - oobreadlen], &read_data[mtd->oobblock+mtd->oobsize - oobreadlen], oobreadlen);
#endif      	
#else	//direct	
		int addr=0,tmp=0;
		addr = (page<<this->page_shift);
		//for (i=col; i<((mtd->oobblock+mtd->oobsize)-col); i++)
		for (i=0,j=0; i<(mtd->oobblock); i++)
		{
			tmp = (unsigned char)FLASH_READ_DATA(addr+i);
			data_poi[j] = (unsigned char)tmp;//(unsigned char)FLASH_READ_DATA(addr+i);
			j++;
			
		}
		for (i=0,j=0; i<(mtd->oobsize); i++)
		{
			tmp = (unsigned char)FLASH_READ_DATA(addr+i+mtd->oobblock);
			if( i>= (mtd->oobsize - oobreadlen))
			{
				oob_data[i] = (unsigned char)tmp;//(unsigned char)FLASH_READ_DATA(addr+i);
				j++;
				if(j>oobreadlen)
					break;
			}
		}
#endif	
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif	
		
		switch (eccmode) {
		case NAND_ECC_NONE: {	/* No ECC, Read in a page */
			FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0);
			
			static unsigned long lastwhinge = 0;
			if ((lastwhinge / HZ) != (jiffies / HZ)) {
#ifndef CONFIG_YAFFS_FS					
				printk (KERN_WARNING "Reading data from NAND FLASH without ECC is not recommended\n");
#endif				
				lastwhinge = jiffies;
			}
			//this->read_buf(mtd, data_poi, end);
			break;
		}

		case NAND_ECC_SOFT:	/* Software ECC 3/256: Read in a page + oob data */
			FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0);
			//this->read_buf(mtd, data_poi, end);
			
			for (i = 0, datidx = 0; eccsteps; eccsteps--, i+=3, datidx += ecc)
			{
				this->calculate_ecc(mtd, &data_poi[datidx], &ecc_calc[i]);
				if(debug_f)
					printk("%s : -->calculate_ecc(%x): %x %x %x\n",__func__,i,ecc_code[i],ecc_code[i+1],ecc_code[i+2]);
			}
			break;
		case NAND_ECC_HW3_512:	
			case NAND_ECC_HW6_512: /* Hardware ECC 3/6 byte / 512 byte data : Read in a page  */
				FLASH_WRITE_REG(NFLASH_ECC_CONTROL, FLASH_START_BIT|ECC_CLR); //set 31b = 0
				break;
		default:
			for (i = 0, datidx = 0; eccsteps; eccsteps--, i+=eccbytes, datidx += ecc) {
				this->enable_hwecc(mtd, NAND_ECC_READ);
				//this->read_buf(mtd, &data_poi[datidx], ecc);

				/* HW ecc with syndrome calculation must read the
				 * syndrome from flash immidiately after the data */
				if (!compareecc) {
					/* Some hw ecc generators need to know when the
					 * syndrome is read from flash */
					this->enable_hwecc(mtd, NAND_ECC_READSYN);
					//this->read_buf(mtd, &oob_data[i], eccbytes);
					/* We calc error correction directly, it checks the hw
					 * generator for an error, reads back the syndrome and
					 * does the error correction on the fly */
					ecc_status = this->correct_data(mtd, &data_poi[datidx], &oob_data[i], &ecc_code[i]);
					if ((ecc_status == -1) || (ecc_status > (flags && 0xff))) {
						DEBUG (MTD_DEBUG_LEVEL0, "csnand_read_ecc: "
							"Failed ECC read, page 0x%08x on chip %d\n", page, chipnr);
						ecc_failed++;
					}
				} else {
					this->calculate_ecc(mtd, &data_poi[datidx], &ecc_calc[i]);
				}
			}
			break;
		}
		nand_col = mtd->oobblock;
		/* read oobdata */
		//this->read_buf(mtd, &oob_data[mtd->oobsize - oobreadlen], oobreadlen);

		/* Skip ECC check, if not requested (ECC_NONE or HW_ECC with syndromes) */
		if (!compareecc)
			goto readoob;

		/* Pick the ECC bytes out of the oob data */
		for (j = 0; j < oobsel->eccbytes; j++)
			ecc_code[j] = oob_data[oob_config[j]];

		/* correct data, if neccecary */
		for (i = 0, j = 0, datidx = 0; i < this->eccsteps; i++, datidx += ecc) {
			ecc_status = this->correct_data(mtd, &data_poi[datidx], &ecc_code[j], &ecc_calc[j]);

			/* Get next chunk of ecc bytes */
			j += eccbytes;

			/* Check, if we have a fs supplied oob-buffer,
			 * This is the legacy mode. Used by YAFFS1
			 * Should go away some day
			 */
			if (oob_buf && oobsel->useecc == MTD_NANDECC_PLACE) {
				int *p = (int *)(&oob_data[mtd->oobsize]);
				p[i] = ecc_status;
			}

			if ((ecc_status == -1) || (ecc_status > (flags && 0xff))) {
				DEBUG (MTD_DEBUG_LEVEL0, "csnand_read_ecc: " "Failed ECC read, page 0x%08x\n", page);
				ecc_failed++;
			}
		}

	readoob:
		/* check, if we have a fs supplied oob-buffer */
		if (oob_buf) {
			/* without autoplace. Legacy mode used by YAFFS1 */
			switch(oobsel->useecc) {
			case MTD_NANDECC_AUTOPLACE:
			case MTD_NANDECC_AUTOPL_USR:
				/* Walk through the autoplace chunks */
				for (i = 0; oobsel->oobfree[i][1]; i++) {
					int from = oobsel->oobfree[i][0];
					int num = oobsel->oobfree[i][1];
					memcpy(&oob_buf[oob], &oob_data[from], num);
					oob += num;
				}
				break;
			case MTD_NANDECC_PLACE:
				/* YAFFS1 legacy mode */
				oob_data += this->eccsteps * sizeof (int);
			default:
				oob_data += mtd->oobsize;
			}
		}
	readdata:
		/* Partial page read, transfer data into fs buffer */
		if (!aligned) {
			for (j = col; j < end && read < len; j++)
				buf[read++] = data_poi[j];
			this->pagebuf = realpage;
		} else
			read += mtd->oobblock;

		/* Apply delay or wait for ready/busy pin
		 * Do this before the AUTOINCR check, so no problems
		 * arise if a chip which does auto increment
		 * is marked as NOAUTOINCR by the board driver.
		*/
		if (!this->dev_ready)
			udelay (this->chip_delay);
		else
			csnand_wait_ready(mtd);

		if (read == len)
			break;

		/* For subsequent reads align to page boundary. */
		col = 0;
		/* Increment page address */
		realpage++;

		page = realpage & this->pagemask;
		/* Check, if we cross a chip boundary */
		if (!page) {
			chipnr++;
			this->select_chip(mtd, -1);
			this->select_chip(mtd, chipnr);
		}
		/* Check, if the chip supports auto page increment
		 * or if we have hit a block boundary.
		*/
		if (!NAND_CANAUTOINCR(this) || !(page & blockcheck))
			sndcmd = 1;
	}

	/* Deselect and wake up anyone waiting on the device */
//	if (flags & csnand_get_device)
		csnand_release_device(mtd);

	/*
	 * Return success, if no ECC failures, else -EBADMSG
	 * fs driver will take care of that, because
	 * retlen == desired len and result == -EBADMSG
	 */
	*retlen = read;
	return ecc_failed ? -EBADMSG : 0;
}

/**
 * csnand_read_oob - [MTD Interface] NAND read out-of-band
 * @mtd:	MTD device structure
 * @from:	offset to read from
 * @len:	number of bytes to read
 * @retlen:	pointer to variable to store the number of read bytes
 * @buf:	the databuffer to put data
 *
 * NAND read out-of-band data from the spare area
 */
static int csnand_read_oob (struct mtd_info *mtd, loff_t from, size_t len, size_t * retlen, u_char * buf)
{
	int i, col, page, chipnr;
	struct nand_chip *this = mtd->priv;
	int	blockcheck = (1 << (this->phys_erase_shift - this->page_shift)) - 1;
	if(debug_f)
		printk("%s : -->from :%x, len : %x \n",__func__,(unsigned int) from,(unsigned int) len);
	DEBUG (MTD_DEBUG_LEVEL3, "csnand_read_oob: from = 0x%08x, len = %i\n", (unsigned int) from, (int) len);

	/* Shift to get page */
	page = (int)(from >> this->page_shift);
	chipnr = (int)(from >> this->chip_shift);

	/* Mask to get column */
	col = from & (mtd->oobsize - 1);

	/* Initialize return length value */
	*retlen = 0;

	/* Do not allow reads past end of device */
	if ((from + len) > mtd->size) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_read_oob: Attempt read beyond end of device\n");
		*retlen = 0;
		return -EINVAL;
	}

	/* Grab the lock and see if the device is available */
	csnand_get_device (this, mtd , FL_READING);

	/* Select the NAND device */
	this->select_chip(mtd, chipnr);

	/* Send the read command */
	this->cmdfunc (mtd, NAND_CMD_READOOB, col, page & this->pagemask);
	/*
	 * Read the data, if we read more than one page
	 * oob data, let the device transfer the data !
	 */
	i = 0;
	
	while (i < len) {
		int thislen = mtd->oobsize - col;
		nand_col = mtd->oobblock;
		thislen = min_t(int, thislen, len);
		this->read_buf(mtd, &buf[i], thislen);
		i += thislen;

		/* Read more ? */
		if (i < len) {
			page++;
			nand_page = page;
			col = 0;

			/* Check, if we cross a chip boundary */
			if (!(page & this->pagemask)) {
				chipnr++;
				this->select_chip(mtd, -1);
				this->select_chip(mtd, chipnr);
			}

			/* Apply delay or wait for ready/busy pin
			 * Do this before the AUTOINCR check, so no problems
			 * arise if a chip which does auto increment
			 * is marked as NOAUTOINCR by the board driver.
			 */
			if (!this->dev_ready)
				udelay (this->chip_delay);
			else
				csnand_wait_ready(mtd);

			/* Check, if the chip supports auto page increment
			 * or if we have hit a block boundary.
			*/
			if (!NAND_CANAUTOINCR(this) || !(page & blockcheck)) {
				/* For subsequent page reads set offset to 0 */
			        this->cmdfunc (mtd, NAND_CMD_READOOB, 0x0, page & this->pagemask);
			}
		}
	}

	/* Deselect and wake up anyone waiting on the device */
	csnand_release_device(mtd);

	/* Return happy */
	*retlen = len;
	return 0;
}

/**
 * csnand_read_raw - [GENERIC] Read raw data including oob into buffer
 * @mtd:	MTD device structure
 * @buf:	temporary buffer
 * @from:	offset to read from
 * @len:	number of bytes to read
 * @ooblen:	number of oob data bytes to read
 *
 * Read raw data including oob into buffer
 */
int csnand_read_raw (struct mtd_info *mtd, uint8_t *buf, loff_t from, size_t len, size_t ooblen)
{
	struct nand_chip *this = mtd->priv;
	int page = (int) (from >> this->page_shift);
	int chip = (int) (from >> this->chip_shift);
	int sndcmd = 1;
	int cnt = 0;
	int pagesize = mtd->oobblock + mtd->oobsize;
	int	blockcheck = (1 << (this->phys_erase_shift - this->page_shift)) - 1;
	if(debug_f)
		printk("%s : -->from: %x ,len: %x \n",__func__,(unsigned int) from,(unsigned int) len);
	/* Do not allow reads past end of device */
	if ((from + len) > mtd->size) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_read_raw: Attempt read beyond end of device\n");
		return -EINVAL;
	}

	/* Grab the lock and see if the device is available */
	csnand_get_device (this, mtd , FL_READING);

	this->select_chip (mtd, chip);

	/* Add requested oob length */
	len += ooblen;

	while (len) {
		if (sndcmd)
			this->cmdfunc (mtd, NAND_CMD_READ0, 0, page & this->pagemask);
		sndcmd = 0;

		this->read_buf (mtd, &buf[cnt], pagesize);

		len -= pagesize;
		cnt += pagesize;
		page++;
		nand_page = page;

		if (!this->dev_ready)
			udelay (this->chip_delay);
		else
			csnand_wait_ready(mtd);

		/* Check, if the chip supports auto page increment */
		if (!NAND_CANAUTOINCR(this) || !(page & blockcheck))
			sndcmd = 1;
	}

	/* Deselect and wake up anyone waiting on the device */
	csnand_release_device(mtd);
	return 0;
}


/**
 * csnand_prepare_oobbuf - [GENERIC] Prepare the out of band buffer
 * @mtd:	MTD device structure
 * @fsbuf:	buffer given by fs driver
 * @oobsel:	out of band selection structre
 * @autoplace:	1 = place given buffer into the oob bytes
 * @numpages:	number of pages to prepare
 *
 * Return:
 * 1. Filesystem buffer available and autoplacement is off,
 *    return filesystem buffer
 * 2. No filesystem buffer or autoplace is off, return internal
 *    buffer
 * 3. Filesystem buffer is given and autoplace selected
 *    put data from fs buffer into internal buffer and
 *    retrun internal buffer
 *
 * Note: The internal buffer is filled with 0xff. This must
 * be done only once, when no autoplacement happens
 * Autoplacement sets the buffer dirty flag, which
 * forces the 0xff fill before using the buffer again.
 *
*/
static u_char * csnand_prepare_oobbuf (struct mtd_info *mtd, u_char *fsbuf, struct nand_oobinfo *oobsel,
		int autoplace, int numpages)
{
	struct nand_chip *this = mtd->priv;
	int i, len, ofs;

	/* Zero copy fs supplied buffer */
	if (fsbuf && !autoplace)
		return fsbuf;

	/* Check, if the buffer must be filled with ff again */
	if (this->oobdirty) {
		memset (this->oob_buf, 0xff,
			mtd->oobsize << (this->phys_erase_shift - this->page_shift));
		this->oobdirty = 0;
	}

	/* If we have no autoplacement or no fs buffer use the internal one */
	if (!autoplace || !fsbuf)
		return this->oob_buf;

	/* Walk through the pages and place the data */
	this->oobdirty = 1;
	ofs = 0;
	while (numpages--) {
		for (i = 0, len = 0; len < mtd->oobavail; i++) {
			int to = ofs + oobsel->oobfree[i][0];
			int num = oobsel->oobfree[i][1];
			memcpy (&this->oob_buf[to], fsbuf, num);
			len += num;
			fsbuf += num;
		}
		ofs += mtd->oobavail;
	}
	return this->oob_buf;
}

#define NOTALIGNED(x) (x & (mtd->oobblock-1)) != 0

/**
 * csnand_write_buf - [DEFAULT] write buffer to chip
 * @mtd:	MTD device structure
 * @buf:	data buffer
 * @len:	number of bytes to write
 *
 * Default write function for 8bit buswith
 */
static void csnand_write_buf(struct mtd_info *mtd, const u_char *buf, int len)
{
	int i, page=0,col=0;
	struct nand_chip *this = mtd->priv;
	u_char *databuf, *oobbuf;
        size_t  retlen;
        retlen=0;
	if(debug_f)
		printk("%s : -->len: %x \n",__func__,(unsigned int) len);
	databuf = &(this->data_buf[0]);
		oobbuf = &(this->data_buf[mtd->oobblock]);
		for (i = 0; i < mtd->oobsize; i++)
			oobbuf[i] = 0xff;	
						
	if(len <= (mtd->oobblock+mtd->oobsize))
	{
		//addr = FLASH_READ_REG(NFLASH_ADDRESS);
		//page = FLASH_READ_REG(NFLASH_ADDRESS)&0xffffff00;
		//col  = FLASH_READ_REG(NFLASH_ADDRESS)&0x000000ff; 
		page = nand_page;
        col  = nand_col;
		
		csnand_read_ecc (mtd, (page<<this->page_shift), mtd->oobblock , &retlen, databuf, oobbuf, NULL);
        
        for(i=col;i<len;i++)
        	databuf[col+i] = buf[i];
        	
        csnand_write_ecc (mtd, (page<<this->page_shift), mtd->oobblock, &retlen, databuf, oobbuf, NULL);

	}

	if(debug_f)
		printk("%s : <--\n",__func__);
}

/**
 * csnand_write - [MTD Interface] compability function for csnand_write_ecc
 * @mtd:	MTD device structure
 * @to:		offset to write to
 * @len:	number of bytes to write
 * @retlen:	pointer to variable to store the number of written bytes
 * @buf:	the data to write
 *
 * This function simply calls csnand_write_ecc with oob buffer and oobsel = NULL
 *
*/
static int csnand_write (struct mtd_info *mtd, loff_t to, size_t len, size_t * retlen, const u_char * buf)
{
	return (csnand_write_ecc (mtd, to, len, retlen, buf, NULL, NULL));
}

/**
 * csnand_write_ecc - [MTD Interface] NAND write with ECC
 * @mtd:	MTD device structure
 * @to:		offset to write to
 * @len:	number of bytes to write
 * @retlen:	pointer to variable to store the number of written bytes
 * @buf:	the data to write
 * @eccbuf:	filesystem supplied oob data buffer
 * @oobsel:	oob selection structure
 *
 * NAND write with ECC
 */
static int csnand_write_ecc (struct mtd_info *mtd, loff_t to, size_t len,
			   size_t * retlen, const u_char * buf, u_char * eccbuf, struct nand_oobinfo *oobsel)
{
	int startpage, page, ret = -EIO, oob = 0, written = 0, chipnr;
	int autoplace = 0, numpages, totalpages;
	struct nand_chip *this = mtd->priv;
	u_char *oobbuf, *bufstart;
	int	ppblock = (1 << (this->phys_erase_shift - this->page_shift));
	
	DEBUG (MTD_DEBUG_LEVEL3, "csnand_write_ecc: to = 0x%08x, len = %i\n", (unsigned int) to, (int) len);

	/* Initialize retlen, in case of early exit */
	*retlen = 0;
	
	/* Do not allow write past end of device */
	if ((to + len) > mtd->size) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_write_ecc: Attempt to write past end of page\n");
		return -EINVAL;
	}

	/* reject writes, which are not page aligned */
	if (NOTALIGNED (to) || NOTALIGNED(len)) {
		printk (KERN_NOTICE "csnand_write_ecc: Attempt to write not page aligned data\n");
		return -EINVAL;
	}

	/* Grab the lock and see if the device is available */
	csnand_get_device (this, mtd, FL_WRITING);

	/* Calculate chipnr */
	chipnr = (int)(to >> this->chip_shift);
	/* Select the NAND device */
	this->select_chip(mtd, chipnr);

	/* Check, if it is write protected */
	if (csnand_check_wp(mtd))
		goto out;

	/* if oobsel is NULL, use chip defaults */
	if (oobsel == NULL)
		oobsel = &mtd->oobinfo;

	/* Autoplace of oob data ? Use the default placement scheme */
	if (oobsel->useecc == MTD_NANDECC_AUTOPLACE) {
		oobsel = this->autooob;
		autoplace = 1;
	}
	if (oobsel->useecc == MTD_NANDECC_AUTOPL_USR)
		autoplace = 1;

	/* Setup variables and oob buffer */
	totalpages = len >> this->page_shift;
	page = (int) (to >> this->page_shift);
	/* Invalidate the page cache, if we write to the cached page */
	if (page <= this->pagebuf && this->pagebuf < (page + totalpages))
		this->pagebuf = -1;

	/* Set it relative to chip */
	page &= this->pagemask;
	startpage = page;
	if(debug_f)
		printk("%s : -->to: %x ,len: %x totalpages:%x,startpage %x,ppblock %x, numpages %x\n",__func__,(unsigned int) to,(unsigned int) len,(unsigned int) totalpages,(unsigned int) startpage,(unsigned int) ppblock,(unsigned int) numpages);
		
	/* Calc number of pages we can write in one go */
	numpages = min (ppblock - (startpage  & (ppblock - 1)), totalpages);
	oobbuf = csnand_prepare_oobbuf (mtd, eccbuf, oobsel, autoplace, numpages);
	bufstart = (u_char *)buf;
	//printk(" %s  oob :\n",__func__);
	//int i;
	//for(i=0;i<mtd->oobsize;i++)
	//	printk("  %02x",oobbuf[i]);
	//	printk("\n");
	/* Loop until all data is written */
	while (written < len) {

		this->data_poi = (u_char*) &buf[written];
		/* Write one page. If this is the last page to write
		 * or the last page in this block, then use the
		 * real pageprogram command, else select cached programming
		 * if supported by the chip.
		 */
		ret = csnand_write_page (mtd, this, page, &oobbuf[oob], oobsel, (--numpages > 0));
		if (ret) {
			DEBUG (MTD_DEBUG_LEVEL0, "csnand_write_ecc: write_page failed %d\n", ret);
			goto out;
		}
		/* Next oob page */
		oob += mtd->oobsize;
		/* Update written bytes count */
		written += mtd->oobblock;
		if (written == len)
			goto cmp;

		/* Increment page address */
		page++;
		nand_page = page;

		/* Have we hit a block boundary ? Then we have to verify and
		 * if verify is ok, we have to setup the oob buffer for
		 * the next pages.
		*/
		if (!(page & (ppblock - 1))){
						
			int ofs;
			this->data_poi = bufstart;
			ret = csnand_verify_pages (mtd, this, startpage,
				page - startpage,
				oobbuf, oobsel, chipnr, (eccbuf != NULL));
			if (ret) {
				DEBUG (MTD_DEBUG_LEVEL0, "csnand_write_ecc: verify_pages failed %d\n", ret);
				goto out;
			}
			*retlen = written;
			/*bufstart need to update for Verify the remaining pages */
			bufstart += (page - startpage) * mtd->oobblock ;

			ofs = autoplace ? mtd->oobavail : mtd->oobsize;
			if (eccbuf)
				eccbuf += (page - startpage) * ofs;
			totalpages -= page - startpage;
			numpages = min (totalpages, ppblock);
			page &= this->pagemask;
			startpage = page;
			oobbuf = csnand_prepare_oobbuf (mtd, eccbuf, oobsel,
					autoplace, numpages);
			oob = 0;			
			/* Check, if we cross a chip boundary */
			if (!page) {
				chipnr++;
				this->select_chip(mtd, -1);
				this->select_chip(mtd, chipnr);
			}
		}
	}
	/* Verify the remaining pages */
cmp:
	this->data_poi = bufstart;
 	ret = csnand_verify_pages (mtd, this, startpage, totalpages,
		oobbuf, oobsel, chipnr, (eccbuf != NULL));
	if (!ret)
	{
		*retlen = written;
		//printk("ret: %x retlen : %x   written :%x\n",ret, *retlen, written);
	}
	else
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_write_ecc: verify_pages failed %d\n", ret);
	
	if(debug_f)
		printk("%s : <--\n",__func__);
out:
	/* Deselect and wake up anyone waiting on the device */
	csnand_release_device(mtd);

	return ret;
}


/**
 * csnand_write_oob - [MTD Interface] NAND write out-of-band
 * @mtd:	MTD device structure
 * @to:		offset to write to
 * @len:	number of bytes to write
 * @retlen:	pointer to variable to store the number of written bytes
 * @buf:	the data to write
 *
 * NAND write out-of-band
 */
static int csnand_write_oob (struct mtd_info *mtd, loff_t to, size_t len, size_t * retlen, const u_char * buf)
{
	int column, page, status, ret = -EIO, chipnr, i, j;
	struct nand_chip *this = mtd->priv;

	DEBUG (MTD_DEBUG_LEVEL3, "csnand_write_oob: to = 0x%08x, len = %i\n", (unsigned int) to, (int) len);
	if(debug_f)
		printk("%s : -->to: %x ,len: %x \n",__func__, (unsigned int) to,(unsigned int)  len);
	/* Shift to get page */
	page = (int) (to >> this->page_shift);
	chipnr = (int) (to >> this->chip_shift);

	/* Mask to get column */
	column = to & (mtd->oobsize - 1);

	/* Initialize return length value */
	*retlen = 0;

	/* Do not allow write past end of page */
	if ((column + len) > mtd->oobsize) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_write_oob: Attempt to write past end of page\n");
		return -EINVAL;
	}

	/* Grab the lock and see if the device is available */
	csnand_get_device (this, mtd, FL_WRITING);

	/* Select the NAND device */
	this->select_chip(mtd, chipnr);

	/* Reset the chip. Some chips (like the Toshiba TC5832DC found
	   in one of my DiskOnChip 2000 test units) will clear the whole
	   data page too if we don't do this. I have no clue why, but
	   I seem to have 'fixed' it in the doc2000 driver in
	   August 1999.  dwmw2. */
	this->cmdfunc(mtd, NAND_CMD_RESET, -1, -1);

	/* Check, if it is write protected */
	if (csnand_check_wp(mtd))
		goto out;

	/* Invalidate the page cache, if we write to the cached page */
	if (page == this->pagebuf)
		this->pagebuf = -1;

	//page = nand_page;
    //col  = nand_col;
	nand_page = page;	
	//csnand_read_ecc (mtd, (page<<this->page_shift), mtd->oobblock , &retlen, this->data_buf, &(this->data_buf[mtd->oobblock]), NULL);
	nand_col = 0;
	this->read_buf(mtd, this->data_buf, (mtd->oobblock+mtd->oobsize));
	
	//printk(" %s  read oob(%x) :\n",__func__,page);
	//for(i=0;i<mtd->oobsize;i++)
	//	printk("  %02x",this->data_buf[mtd->oobblock+i]);
	//	printk("\n");
		
	for(j=column,i=0;j<(column+len);j++,i++)
    	this->data_buf[mtd->oobblock+j] = buf[i];
    
    //printk(" %s after buf :\n",__func__);
	//for(i=0;i<mtd->oobsize;i++)
	//	printk("  %02x",buf[i]);
	//	printk("\n");
    //printk(" %s after oob :\n",__func__);
	//for(i=0;i<mtd->oobsize;i++)
	//	printk("  %02x",this->data_buf[mtd->oobblock+i]);
	//	printk("\n");
			
    this->cmdfunc (mtd, NAND_CMD_SEQIN, mtd->oobblock, page & this->pagemask);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif    
#ifdef CONFIG_GEMINI_NAND_INDIRECT

	unsigned int nopcode,dent_bit,tt,*pwt;
	ADD5=ADD4=ADD3=ADD2=0;
	if(mtd->oobblock < PAGE512_RAW_SIZE)
				ADD5 = (page>>24)&0xff;
				
    		ADD5=(page>>16)&0xff; 
			ADD4=(page>>8)&0xff;
			ADD3=(page)&0xff;
#if FORCE_DMA_ACCESS	
		pwrite = (unsigned int *) write_data;
		
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_CLR_FIFO); //clear fifo
		WRITE_DMA_REG(DMA_MAIN_CFG, DMA_ENABLE); //enable DMA
		WRITE_DMA_REG(DMA_CH0_SRC_ADDR, write_dma); //src_address
		WRITE_DMA_REG(DMA_CH0_DST_ADDR, NFLASH_DMA_FIFO+SL2312_FLASH_CTRL_BASE); //dest_address
		WRITE_DMA_REG(DMA_CH0_LLP, 0x0); //LLP
		WRITE_DMA_REG(DMA_CH0_SIZE, ((mtd->oobblock+mtd->oobsize)/4)); //size
		WRITE_DMA_REG(DMA_CH0_CFG, DMA_ABORT_INT); //CFG
		WRITE_DMA_REG(DMA_CH0_CSR, 0x11295); //CSR
#endif		
	dent_bit=FLASH_READ_REG(NFLASH_TYPE);
		switch(dent_bit&FLASH_SIZE_MASK)
		{
			case FLASH_SIZE_32:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_3|NCNT_CMD_1);//0x0f01ff21); 
		    	//nopcode = 0x00001080;
			break;
			
			case FLASH_SIZE_64:
			case FLASH_SIZE_128:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_4|NCNT_CMD_1);//0x0f01ff31); 
		    	//nopcode = 0x00001080;
			break;
			
			case FLASH_SIZE_256:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_2kP_OOB|NCNT_2kP_DATA|NCNT_ADDR_5|NCNT_CMD_2);//0x3f07ff41); 
		    	//nopcode = 0x00001080;
			break;
		}
		nopcode = (NAND_CMD_PAGEPROG<<8)|NAND_CMD_SEQIN;//0x00001080;
		nopcode |= (ADD5<<24);
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, nopcode); 
		    
		nopcode = 0x0|(ADD4<<24)|(ADD3<<16)|(ADD2<<8);
		FLASH_WRITE_REG(NFLASH_ADDRESS, nopcode); 
		pwt = (unsigned int *) this->data_buf;
#if FORCE_DMA_ACCESS	

		memcpy(write_data, this->data_buf, (mtd->oobblock+mtd->oobsize));
		// set dma fifo port
		FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_START_BIT|FLASH_WT);//0x80003000);
		nopcode=READ_DMA_REG(DMA_TC);
		while(!(nopcode&DMA_CH0_TC)) //polling flash access 31b
      	{
          nopcode=READ_DMA_REG(DMA_TC); 
          udelay(2);
      	}
	    nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL); 		
		while(nopcode&FLASH_START_BIT) //polling flash access 31b
      	{
          nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL);
          udelay(2);
      	}
      	
      	//Disable channel 0 DMA
      	WRITE_DMA_REG(DMA_CH0_CSR, DMA_CH0_DISABLE);
      	//DMA TC int status Rg
      	//write clear int
      	WRITE_DMA_REG(DMA_INT_TC_CLR, DMA_CH0_TC);
      	//Flash status Reg
      	//write clear fifo_int
      	FLASH_WRITE_REG(NFLASH_STATUS, 0x20000);
      		
		
#else		
		for(i=0;i<((mtd->oobblock+mtd->oobsize)/4);i++)
		{
			tt = pwt[i];			
			FLASH_WRITE_REG(NFLASH_DATA, tt); 
			nopcode = FLASH_START_BIT | FLASH_WT |NFLASH_CHIP0_EN|NFLASH_WiDTH32|NFLASH_INDIRECT; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode); 
			
			while(nopcode&FLASH_START_BIT) 
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(2);
        	   schedule();
      		}    		 	
		}
#endif		
#else 	  //direct
	//printk("\n %s write oob(%x) :\n",__func__,page);
	for(i=0;i<(mtd->oobblock+mtd->oobsize);i++)
	{
		//udelay(5);
		FLASH_WRITE_DATA((page<<this->page_shift)+i,this->data_buf[i]);
		//if(i>=mtd->oobblock)
		//	printk("  %02x");
		
	}
	//printk("\n");
#endif
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
	//if (NAND_MUST_PAD(this)) {
	//	nand_col = mtd->oobblock + column;
	//	memset(tmpoobbuf, 0xff, mtd->oobsize);
	//	memcpy(tmpoobbuf, buf,len);
	//	this->write_buf(mtd, tmpoobbuf, len);
	//	///* Write out desired data */
	//	//this->cmdfunc (mtd, NAND_CMD_SEQIN, mtd->oobblock, page & this->pagemask);
	//	///* prepad 0xff for partial programming */
	//	//this->write_buf(mtd, ffchars, column);
	//	///* write data */
	//	//this->write_buf(mtd, buf, len);
	//	///* postpad 0xff for partial programming */
	//	//this->write_buf(mtd, ffchars, mtd->oobsize - (len+column));
	//} else {
	//	/* Write out desired data */
	//	this->cmdfunc (mtd, NAND_CMD_SEQIN, mtd->oobblock + column, page & this->pagemask);
	//	nand_col = mtd->oobblock + column;
	//	/* write data */
	//	this->write_buf(mtd, buf, len);
	//}
	/* Send command to program the OOB data */
	this->cmdfunc (mtd, NAND_CMD_PAGEPROG, -1, -1);

	status = this->waitfunc (mtd, this, FL_WRITING);

	/* See if device thinks it succeeded */
	if (status & NAND_STATUS_FAIL) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_write_oob: " "Failed write, page 0x%08x\n", page);
		ret = -EIO;
		goto out;
	}
	/* Return happy */
	*retlen = len;

#ifdef CONFIG_MTD_NAND_VERIFY_WRITE
#ifndef CONFIG_YAFFS_FS //CONFIG_YAFFS_DOES_ECC
	/* add if define CONFIG_YAFFS_DOES_ECC then do not verify oob data.(pagesize = 0x200)
	 * Because yaffs will modify byte 5 : pageStatus; set to 0 to delete the chunk 
	 * But it will write a 0xff buffer with byte 5 0x0.
	 * If you do verify oob data then you get error. Because it just set byte 5 to 0x0
	 */
	/* Send command to read back the data */
	this->cmdfunc (mtd, NAND_CMD_READOOB, column, page & this->pagemask);
	nand_col = mtd->oobblock;
	if (this->verify_buf(mtd, buf, len)) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_write_oob: " "Failed write verify, page 0x%08x\n", page);
		ret = -EIO;
		goto out;
	}
#endif	
#endif
	ret = 0;
out:
	/* Deselect and wake up anyone waiting on the device */
	csnand_release_device(mtd);

	return ret;
}


/**
 * csnand_writev - [MTD Interface] compabilty function for csnand_writev_ecc
 * @mtd:	MTD device structure
 * @vecs:	the iovectors to write
 * @count:	number of vectors
 * @to:		offset to write to
 * @retlen:	pointer to variable to store the number of written bytes
 *
 * NAND write with kvec. This just calls the ecc function
 */
static int csnand_writev (struct mtd_info *mtd, const struct kvec *vecs, unsigned long count,
		loff_t to, size_t * retlen)
{
	return (csnand_writev_ecc (mtd, vecs, count, to, retlen, NULL, NULL));
}

/**
 * csnand_writev_ecc - [MTD Interface] write with iovec with ecc
 * @mtd:	MTD device structure
 * @vecs:	the iovectors to write
 * @count:	number of vectors
 * @to:		offset to write to
 * @retlen:	pointer to variable to store the number of written bytes
 * @eccbuf:	filesystem supplied oob data buffer
 * @oobsel:	oob selection structure
 *
 * NAND write with iovec with ecc
 */
static int csnand_writev_ecc (struct mtd_info *mtd, const struct kvec *vecs, unsigned long count,
		loff_t to, size_t * retlen, u_char *eccbuf, struct nand_oobinfo *oobsel)
{
	int i, page, len, total_len, ret = -EIO, written = 0, chipnr;
	int oob, numpages, autoplace = 0, startpage;
	struct nand_chip *this = mtd->priv;
	int	ppblock = (1 << (this->phys_erase_shift - this->page_shift));
	u_char *oobbuf, *bufstart;
	if(debug_f)
		printk("%s : -->\n",__func__);
	/* Preset written len for early exit */
	*retlen = 0;

	/* Calculate total length of data */
	total_len = 0;
	for (i = 0; i < count; i++)
		total_len += (int) vecs[i].iov_len;

	DEBUG (MTD_DEBUG_LEVEL3,
	       "csnand_writev: to = 0x%08x, len = %i, count = %ld\n", (unsigned int) to, (unsigned int) total_len, count);

	/* Do not allow write past end of page */
	if ((to + total_len) > mtd->size) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_writev: Attempted write past end of device\n");
		return -EINVAL;
	}

	/* reject writes, which are not page aligned */
	if (NOTALIGNED (to) || NOTALIGNED(total_len)) {
		printk (KERN_NOTICE "csnand_write_ecc: Attempt to write not page aligned data\n");
		return -EINVAL;
	}

	/* Grab the lock and see if the device is available */
	csnand_get_device (this, mtd, FL_WRITING);

	/* Get the current chip-nr */
	chipnr = (int) (to >> this->chip_shift);
	/* Select the NAND device */
	this->select_chip(mtd, chipnr);

	/* Check, if it is write protected */
	if (csnand_check_wp(mtd))
		goto out;

	/* if oobsel is NULL, use chip defaults */
	if (oobsel == NULL)
		oobsel = &mtd->oobinfo;

	/* Autoplace of oob data ? Use the default placement scheme */
	if (oobsel->useecc == MTD_NANDECC_AUTOPLACE) {
		oobsel = this->autooob;
		autoplace = 1;
	}
	if (oobsel->useecc == MTD_NANDECC_AUTOPL_USR)
		autoplace = 1;

	/* Setup start page */
	page = (int) (to >> this->page_shift);
	/* Invalidate the page cache, if we write to the cached page */
	if (page <= this->pagebuf && this->pagebuf < ((to + total_len) >> this->page_shift))
		this->pagebuf = -1;

	startpage = page & this->pagemask;

	/* Loop until all kvec' data has been written */
	len = 0;
	while (count) {
		/* If the given tuple is >= pagesize then
		 * write it out from the iov
		 */
		if ((vecs->iov_len - len) >= mtd->oobblock) {
			/* Calc number of pages we can write
			 * out of this iov in one go */
			numpages = (vecs->iov_len - len) >> this->page_shift;
			/* Do not cross block boundaries */
			numpages = min (ppblock - (startpage & (ppblock - 1)), numpages);
			oobbuf = csnand_prepare_oobbuf (mtd, NULL, oobsel, autoplace, numpages);
			bufstart = (u_char *)vecs->iov_base;
			bufstart += len;
			this->data_poi = bufstart;
			oob = 0;
			for (i = 1; i <= numpages; i++) {
				/* Write one page. If this is the last page to write
				 * then use the real pageprogram command, else select
				 * cached programming if supported by the chip.
				 */
				ret = csnand_write_page (mtd, this, page & this->pagemask,
					&oobbuf[oob], oobsel, i != numpages);
				if (ret)
					goto out;
				this->data_poi += mtd->oobblock;
				len += mtd->oobblock;
				oob += mtd->oobsize;
				page++;
				nand_page = page;
			}
			/* Check, if we have to switch to the next tuple */
			if (len >= (int) vecs->iov_len) {
				vecs++;
				len = 0;
				count--;
			}
		} else {
			/* We must use the internal buffer, read data out of each
			 * tuple until we have a full page to write
			 */
			int cnt = 0;
			while (cnt < mtd->oobblock) {
				if (vecs->iov_base != NULL && vecs->iov_len)
					this->data_buf[cnt++] = ((u_char *) vecs->iov_base)[len++];
				/* Check, if we have to switch to the next tuple */
				if (len >= (int) vecs->iov_len) {
					vecs++;
					len = 0;
					count--;
				}
			}
			this->pagebuf = page;
			this->data_poi = this->data_buf;
			bufstart = this->data_poi;
			numpages = 1;
			oobbuf = csnand_prepare_oobbuf (mtd, NULL, oobsel, autoplace, numpages);
			ret = csnand_write_page (mtd, this, page & this->pagemask,
				oobbuf, oobsel, 0);
			if (ret)
				goto out;
			page++;
			nand_page = page;
		}

		this->data_poi = bufstart;
		ret = csnand_verify_pages (mtd, this, startpage, numpages, oobbuf, oobsel, chipnr, 0);
		if (ret)
			goto out;

		written += mtd->oobblock * numpages;
		/* All done ? */
		if (!count)
			break;

		startpage = page & this->pagemask;
		/* Check, if we cross a chip boundary */
		if (!startpage) {
			chipnr++;
			this->select_chip(mtd, -1);
			this->select_chip(mtd, chipnr);
		}
	}
	ret = 0;
out:
	/* Deselect and wake up anyone waiting on the device */
	csnand_release_device(mtd);

	*retlen = written;
	return ret;
}

/**
 * single_erease_cmd - [GENERIC] NAND standard block erase command function
 * @mtd:	MTD device structure
 * @page:	the page address of the block which will be erased
 *
 * Standard erase command for NAND chips
 */
//static void cssingle_erase_cmd (struct mtd_info *mtd, int page)
//{
//	struct nand_chip *this = mtd->priv;
//	/* Send commands to erase a block */
//	this->cmdfunc (mtd, NAND_CMD_ERASE1, -1, page);
//	this->cmdfunc (mtd, NAND_CMD_ERASE2, -1, -1);
//}

/**
 * multi_erease_cmd - [GENERIC] AND specific block erase command function
 * @mtd:	MTD device structure
 * @page:	the page address of the block which will be erased
 *
 * AND multi block erase command function
 * Erase 4 consecutive blocks
 */
//static void multi_erase_cmd (struct mtd_info *mtd, int page)
//{
//	struct nand_chip *this = mtd->priv;
//	/* Send commands to erase a block */
//	this->cmdfunc (mtd, NAND_CMD_ERASE1, -1, page++);
//	this->cmdfunc (mtd, NAND_CMD_ERASE1, -1, page++);
//	this->cmdfunc (mtd, NAND_CMD_ERASE1, -1, page++);
//	this->cmdfunc (mtd, NAND_CMD_ERASE1, -1, page);
//	this->cmdfunc (mtd, NAND_CMD_ERASE2, -1, -1);
//}

/*Add function*/
static void nand_read_id(int chip_no, unsigned char *id)
{
	unsigned int opcode, i, extid;
	
	if(chip_no==0)
		CHIP_EN = NFLASH_CHIP0_EN;
	else
		CHIP_EN = NFLASH_CHIP1_EN;
	  
	opcode = FLASH_READ_REG(NFLASH_TYPE);
	
	FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0); //set 31b = 0
	if((opcode&FLASH_SIZE_MASK) == FLASH_SIZE_32)
		FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_DATA_2|NCNT_ADDR_1|NCNT_CMD_1);//0x7f000100); 		//set only command & address and two data
	else if((opcode&FLASH_SIZE_MASK) == FLASH_SIZE_256)
	{
		FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_DATA_5|NCNT_ADDR_1|NCNT_CMD_1);//0x7f000400); 		//set only command & address and 4 data
		extid = 3;
	}
	else
	{
		FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_DATA_4|NCNT_ADDR_1|NCNT_CMD_1);//0x7f000300); 		//set only command & address and 4 data
		extid = 2;
	}
	
	FLASH_WRITE_REG(NFLASH_CMD_ADDR, NAND_CMD_READID); //write read id command
	FLASH_WRITE_REG(NFLASH_ADDRESS, 0x0); //write address 0x00
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif	
	/* read maker code */
	opcode = FLASH_START_BIT|FLASH_RD|DWIDTH|CHIP_EN;//|chip0_en; //set start bit & 8bits read command
	FLASH_WRITE_REG(NFLASH_ACCESS, opcode); 
	opcode=FLASH_READ_REG(NFLASH_ACCESS);
		while(opcode&FLASH_START_BIT) //polling flash access 31b
      	{
           opcode=FLASH_READ_REG(NFLASH_ACCESS);
           //sl2312_flash_delay();
           schedule();
      	}
      	
    opcode = FLASH_READ_REG(NFLASH_DATA);
    if(DWIDTH==NFLASH_WiDTH16)
    {
      		id[0] = opcode&0xff;
      		id[1] = (opcode&0xff00)>>8;
    }
    else
    {
    	    id[0] = opcode&0xff;
    	    opcode = FLASH_START_BIT|FLASH_RD|DWIDTH|CHIP_EN;//|chip0_en; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, opcode); 
			opcode=FLASH_READ_REG(NFLASH_ACCESS);
			while(opcode&FLASH_START_BIT) //polling flash access 31b
    	  	{
    	       opcode=FLASH_READ_REG(NFLASH_ACCESS);
    	       //sl2312_flash_delay();
    	       schedule();
    	  	}
    		opcode = FLASH_READ_REG(NFLASH_DATA);
      		id[1] = (opcode&0xff00)>>8;
      		
      		opcode=FLASH_READ_REG(NFLASH_TYPE);
      		if((opcode&FLASH_SIZE_MASK)>0)
      		{
      		    for(i=0;i<extid;i++)
      		    {
      				//data cycle 3 & 4 ->not use
      				opcode = FLASH_START_BIT|FLASH_RD|DWIDTH|CHIP_EN;//set start bit & 8bits read command
					FLASH_WRITE_REG(NFLASH_ACCESS, opcode); 
					opcode=FLASH_READ_REG(NFLASH_ACCESS);
      				while(opcode&FLASH_START_BIT) //polling flash access 31b
      				{
        			   opcode=FLASH_READ_REG(NFLASH_ACCESS);
        			   //sl2312_flash_delay();
        			   schedule();
      				}
      				
      				opcode=FLASH_READ_REG(NFLASH_DATA);
      				id[2+i] = (opcode>>(8*((2+i)%4))) & 0xff;
      		    }
      		}
    }
#ifndef CONFIG_GEMINI_NAND_INDIRECT				
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_DIRECT);
#else
			FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
#endif	
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif    
}

/**
 * csnand_erase - [MTD Interface] erase block(s)
 * @mtd:	MTD device structure
 * @instr:	erase instruction
 *
 * Erase one ore more blocks
 */
static int csnand_erase (struct mtd_info *mtd, struct erase_info *instr)
{
	return csnand_erase_nand (mtd, instr, 0);
}

#define BBT_PAGE_MASK	0xffffff3f
/**
 * nand_erase_intern - [NAND Interface] erase block(s)
 * @mtd:	MTD device structure
 * @instr:	erase instruction
 * @allowbbt:	allow erasing the bbt area
 *
 * Erase one ore more blocks
 */
int csnand_erase_nand (struct mtd_info *mtd, struct erase_info *instr, int allowbbt)
{
	int page, len, status, pages_per_block, ret, chipnr;
	struct nand_chip *this = mtd->priv;
	int rewrite_bbt[NAND_MAX_CHIPS]={0};	/* flags to indicate the page, if bbt needs to be rewritten. */
	unsigned int bbt_masked_page;		/* bbt mask to compare to page being erased. */
						/* It is used to see if the current page is in the same */
						/*   256 block group and the same bank as the bbt. */

	DEBUG (MTD_DEBUG_LEVEL3,
	       "csnand_erase: start = 0x%08x, len = %i\n", (unsigned int) instr->addr, (unsigned int) instr->len);
	if(debug_f)
		printk("%s : -->\n",__func__);
	/* Start address must align on block boundary */
	if (instr->addr & ((1 << this->phys_erase_shift) - 1)) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_erase: Unaligned address\n");
		return -EINVAL;
	}

	/* Length must align on block boundary */
	if (instr->len & ((1 << this->phys_erase_shift) - 1)) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_erase: Length not block aligned\n");
		return -EINVAL;
	}

	/* Do not allow erase past end of device */
	if ((instr->len + instr->addr) > mtd->size) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_erase: Erase past end of device\n");
		return -EINVAL;
	}

	instr->fail_addr = 0xffffffff;

	/* Grab the lock and see if the device is available */
	csnand_get_device (this, mtd, FL_ERASING);

	/* Shift to get first page */
	page = (int) (instr->addr >> this->page_shift);
	chipnr = (int) (instr->addr >> this->chip_shift);

	/* Calculate pages in each block */
	pages_per_block = 1 << (this->phys_erase_shift - this->page_shift);

	/* Select the NAND device */
	this->select_chip(mtd, chipnr);
	//this->select_chip(mtd, 0);

	/* Check the WP bit */
	/* Check, if it is write protected */
	if (csnand_check_wp(mtd)) {
		DEBUG (MTD_DEBUG_LEVEL0, "csnand_erase: Device is write protected!!!\n");
		instr->state = MTD_ERASE_FAILED;
		goto erase_exit;
	}

	/* if BBT requires refresh, set the BBT page mask to see if the BBT should be rewritten */
	if (this->options & BBT_AUTO_REFRESH) {
		bbt_masked_page = this->bbt_td->pages[chipnr] & BBT_PAGE_MASK;
	} else {
		bbt_masked_page = 0xffffffff;	/* should not match anything */
	}

	/* Loop through the pages */
	len = instr->len;

	instr->state = MTD_ERASING;

	while (len) {
		/* Check if we have a bad block, we do not erase bad blocks ! */
		if (csnand_block_checkbad(mtd, ((loff_t) page) << this->page_shift, 0, allowbbt)) {
			printk (KERN_WARNING "csnand_erase: attempt to erase a bad block at page 0x%08x\n", page);
			instr->state = MTD_ERASE_FAILED;
			goto erase_exit;
		}

		/* Invalidate the page cache, if we erase the block which contains
		   the current cached page */
		if (page <= this->pagebuf && this->pagebuf < (page + pages_per_block))
			this->pagebuf = -1;

		//this->erase_cmd (mtd, page & this->pagemask);
		csnand_erase_block(mtd, page);

		status = this->waitfunc (mtd, this, FL_ERASING);

		/* See if operation failed and additional status checks are available */
		if ((status & NAND_STATUS_FAIL) && (this->errstat)) {
			status = this->errstat(mtd, this, FL_ERASING, status, page);
		}

		/* See if block erase succeeded */
		if (status & NAND_STATUS_FAIL) {
			DEBUG (MTD_DEBUG_LEVEL0, "csnand_erase: " "Failed erase, page 0x%08x\n", page);
			instr->state = MTD_ERASE_FAILED;
			instr->fail_addr = (page << this->page_shift);
			goto erase_exit;
		}

		/* if BBT requires refresh, set the BBT rewrite flag to the page being erased */
		if (this->options & BBT_AUTO_REFRESH) {
			if (((page & BBT_PAGE_MASK) == bbt_masked_page) &&
			     (page != this->bbt_td->pages[chipnr])) {
				rewrite_bbt[chipnr] = (page << this->page_shift);
			}
		}

		/* Increment page address and decrement length */
		len -= (1 << this->phys_erase_shift);
		page += pages_per_block;

		/* Check, if we cross a chip boundary */
		if (len && !(page & this->pagemask)) {
			chipnr++;
			this->select_chip(mtd, -1);
			this->select_chip(mtd, chipnr);

			/* if BBT requires refresh and BBT-PERCHIP,
			 *   set the BBT page mask to see if this BBT should be rewritten */
			if ((this->options & BBT_AUTO_REFRESH) && (this->bbt_td->options & NAND_BBT_PERCHIP)) {
				bbt_masked_page = this->bbt_td->pages[chipnr] & BBT_PAGE_MASK;
			}

		}
	}
	instr->state = MTD_ERASE_DONE;

erase_exit:

	ret = instr->state == MTD_ERASE_DONE ? 0 : -EIO;
	/* Do call back function */
	if (!ret)
		mtd_erase_callback(instr);

	/* Deselect and wake up anyone waiting on the device */
	csnand_release_device(mtd);

	/* if BBT requires refresh and erase was successful, rewrite any selected bad block tables */
	if ((this->options & BBT_AUTO_REFRESH) && (!ret)) {
		for (chipnr = 0; chipnr < this->numchips; chipnr++) {
			if (rewrite_bbt[chipnr]) {
				/* update the BBT for chip */
				DEBUG (MTD_DEBUG_LEVEL0, "csnand_erase_nand: nand_update_bbt (%d:0x%0x 0x%0x)\n",
					chipnr, rewrite_bbt[chipnr], this->bbt_td->pages[chipnr]);
				nand_update_bbt (mtd, rewrite_bbt[chipnr]);
			}
		}
	}

	/* Return more or less happy */
	return ret;
}

/**
 * csnand_sync - [MTD Interface] sync
 * @mtd:	MTD device structure
 *
 * Sync is actually a wait for chip ready function
 */
static void csnand_sync (struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;

	DEBUG (MTD_DEBUG_LEVEL3, "csnand_sync: called\n");
	if(debug_f)
		printk("%s : -->\n",__func__);
	/* Grab the lock and see if the device is available */
	csnand_get_device (this, mtd, FL_SYNCING);
	/* Release it and go back */
	csnand_release_device (mtd);
}


/**
 * csnand_block_isbad - [MTD Interface] Check whether the block at the given offset is bad
 * @mtd:	MTD device structure
 * @ofs:	offset relative to mtd start
 */
static int csnand_block_isbad (struct mtd_info *mtd, loff_t ofs)
{
	if(debug_f)
		printk("%s : -->\n",__func__);	
	/* Check for invalid offset */
	if (ofs > mtd->size)
		return -EINVAL;

	return csnand_block_checkbad (mtd, ofs, 1, 0);
}

/**
 * csnand_block_markbad - [MTD Interface] Mark the block at the given offset as bad
 * @mtd:	MTD device structure
 * @ofs:	offset relative to mtd start
 */
static int csnand_block_markbad (struct mtd_info *mtd, loff_t ofs)
{
	struct nand_chip *this = mtd->priv;
	int ret;
	if(debug_f)
		printk("%s : -->\n",__func__);
        if ((ret = csnand_block_isbad(mtd, ofs))) {
        	/* If it was bad already, return success and do nothing. */
		if (ret > 0)
			return 0;
        	return ret;
        }

	return this->block_markbad(mtd, ofs);
}

/**
 * csnand_suspend - [MTD Interface] Suspend the NAND flash
 * @mtd:	MTD device structure
 */
//static int csnand_suspend(struct mtd_info *mtd)
//{
//	struct nand_chip *this = mtd->priv;
//
//	return csnand_get_device (this, mtd, FL_PM_SUSPENDED);
//}

/**
 * csnand_resume - [MTD Interface] Resume the NAND flash
 * @mtd:	MTD device structure
 */
//static void csnand_resume(struct mtd_info *mtd)
//{
//	struct nand_chip *this = mtd->priv;
//
//	if (this->state == FL_PM_SUSPENDED)
//		csnand_release_device(mtd);
//	else
//		printk(KERN_ERR "resume() called for the chip which is not "
//				"in suspended state\n");
//
//}


/**
 * csnand_scan - [NAND Interface] Scan for the NAND device
 * @mtd:	MTD device structure
 * @maxchips:	Number of chips to scan for
 *
 * This fills out all the not initialized function pointers
 * with the defaults.
 * The flash ID is read and the mtd/chip structures are
 * filled with the appropriate values. Buffers are allocated if
 * they are not provided by the board driver
 *
 */
int csnand_scan (struct mtd_info *mtd, int maxchips)
{
	int i, j, nand_maf_id, nand_dev_id, busw, maf_id;
	struct nand_chip *this = mtd->priv;
	unsigned char id[5];
	

	/* Get buswidth to select the correct functions*/
	busw = this->options & NAND_BUSWIDTH_16;

	/* check for proper chip_delay setup, set 20us if not */
	if (!this->chip_delay)
		this->chip_delay = 20;

	/* check, if a user supplied command function given */
	if (this->cmdfunc == NULL)
		this->cmdfunc = csnand_command;

	/* check, if a user supplied wait function given */
	if (this->waitfunc == NULL)
		this->waitfunc = csnand_wait;

	if (!this->select_chip)
		this->select_chip = csnand_select_chip;
	if (!this->write_byte)
		this->write_byte = csnand_write_byte;//busw ? csnand_write_byte16 : csnand_write_byte;
	if (!this->read_byte)
		this->read_byte = csnand_read_byte;//busw ? csnand_read_byte16 : csnand_read_byte;
	//if (!this->write_word)
	//	this->write_word = csnand_write_word;
	//if (!this->read_word)
	//	this->read_word = csnand_read_word;
	if (!this->block_bad)
		this->block_bad = csnand_block_bad;
	if (!this->block_markbad)
		this->block_markbad = csnand_default_block_markbad;
	if (!this->write_buf)
		this->write_buf = csnand_write_buf;//busw ? csnand_write_buf16 : csnand_write_buf;
	if (!this->read_buf)
		this->read_buf = csnand_read_buf;//busw ? csnand_read_buf16 : csnand_read_buf;
	if (!this->verify_buf)
		this->verify_buf = csnand_verify_buf;//busw ? csnand_verify_buf16 : csnand_verify_buf;
	if (!this->scan_bbt)
		this->scan_bbt = nand_default_bbt;

	/* Select the device */
	this->select_chip(mtd, 0);

	/* Send the command for reading device ID */
	this->cmdfunc (mtd, NAND_CMD_READID, 0x00, -1);

	/* Read manufacturer and device IDs */
	nand_read_id(0,id);
	
	nand_maf_id = id[0];
	nand_dev_id = id[1];

	/* Print and store flash device information */
	for (i = 0; nand_flash_ids[i].name != NULL; i++) {

		if (nand_dev_id != nand_flash_ids[i].id)
			continue;

		if (!mtd->name) mtd->name = nand_flash_ids[i].name;
		this->chipsize = nand_flash_ids[i].chipsize << 20;

		/* New devices have all the information in additional id bytes */
		if (!nand_flash_ids[i].pagesize) {
			int extid;
			///* The 3rd id byte contains non relevant data ATM */
			///extid = this->read_byte(mtd);
			/* The 4th id byte is the important one */
			extid = id[3];
			/* Calc pagesize */
			mtd->oobblock = 1024 << (extid & 0x3);
			extid >>= 2;
			/* Calc oobsize */
			mtd->oobsize = (8 << (extid & 0x01)) * (mtd->oobblock >> 9);
			extid >>= 2;
			/* Calc blocksize. Blocksize is multiples of 64KiB */
			mtd->erasesize = (64 * 1024)  << (extid & 0x03);
			extid >>= 2;
			/* Get buswidth information */
			busw = (extid & 0x01) ? NAND_BUSWIDTH_16 : 0;

		} else {
			/* Old devices have this data hardcoded in the
			 * device id table */
			mtd->erasesize = nand_flash_ids[i].erasesize;
			mtd->oobblock = nand_flash_ids[i].pagesize;
			mtd->oobsize = mtd->oobblock / 32;
			busw = nand_flash_ids[i].options & NAND_BUSWIDTH_16;
		}

		/* Try to identify manufacturer */
		for (maf_id = 0; nand_manuf_ids[maf_id].id != 0x0; maf_id++) {
			if (nand_manuf_ids[maf_id].id == nand_maf_id)
				break;
		}

		/* Check, if buswidth is correct. Hardware drivers should set
		 * this correct ! */
		if (busw != (this->options & NAND_BUSWIDTH_16)) {
			printk (KERN_INFO "NAND device: Manufacturer ID:"
				" 0x%02x, Chip ID: 0x%02x (%s %s)\n", nand_maf_id, nand_dev_id,
				nand_manuf_ids[maf_id].name , mtd->name);
			printk (KERN_WARNING
				"NAND bus width %d instead %d bit\n",
					(this->options & NAND_BUSWIDTH_16) ? 16 : 8,
					busw ? 16 : 8);
			this->select_chip(mtd, -1);
			return 1;
		}

		/* Calculate the address shift from the page size */
		this->page_shift = ffs(mtd->oobblock) - 1;
		this->bbt_erase_shift = this->phys_erase_shift = ffs(mtd->erasesize) - 1;
		this->chip_shift = ffs(this->chipsize) - 1;

		/* Set the bad block position */
		this->badblockpos = mtd->oobblock > 512 ?
			NAND_LARGE_BADBLOCK_POS : NAND_SMALL_BADBLOCK_POS;

		/* Get chip options, preserve non chip based options */
		this->options &= ~NAND_CHIPOPTIONS_MSK;
		this->options |= nand_flash_ids[i].options & NAND_CHIPOPTIONS_MSK;
		/* Set this as a default. Board drivers can override it, if neccecary */
		this->options |= NAND_NO_AUTOINCR;
		/* Check if this is a not a samsung device. Do not clear the options
		 * for chips which are not having an extended id.
		 */
		if (nand_maf_id != NAND_MFR_SAMSUNG && !nand_flash_ids[i].pagesize)
			this->options &= ~NAND_SAMSUNG_LP_OPTIONS;

	//	/* Check for AND chips with 4 page planes */
	//	if (this->options & NAND_4PAGE_ARRAY)
	//		this->erase_cmd = multi_erase_cmd;
	//	else
	//		this->erase_cmd = cssingle_erase_cmd;

	//	/* Do not replace user supplied command function ! */
	//	if (mtd->oobblock > 512 && this->cmdfunc == csnand_command)
	//		this->cmdfunc = csnand_command_lp;

		/* Try to identify manufacturer */
		for (j = 0; nand_manuf_ids[j].id != 0x0; j++) {
			if (nand_manuf_ids[j].id == nand_maf_id)
				break;
		}
		
		printk (KERN_INFO "NAND device: Manufacturer ID:"
			" 0x%02x, Chip ID: 0x%02x (%s %s)\n", nand_maf_id, nand_dev_id,
			nand_manuf_ids[maf_id].name , nand_flash_ids[i].name);
		break;
	}

	if (!nand_flash_ids[i].name) {
		printk (KERN_WARNING "No NAND device found!!!\n");
		this->select_chip(mtd, -1);
		return 1;
	}

	for (i=1; i < maxchips; i++) {
		this->select_chip(mtd, i);

		/* Send the command for reading device ID */
		nand_read_id(1,id);

		/* Read manufacturer and device IDs */
		if (nand_maf_id != id[0] ||
		    nand_dev_id != id[1])
			break;
	}
	
	if (i > 1)
		printk(KERN_INFO "%d NAND chips detected\n", i);

	/* Allocate buffers, if neccecary */
	tmpbuf = kmalloc (mtd->oobblock,GFP_KERNEL);
	tmpoobbuf = kmalloc (mtd->oobsize,GFP_KERNEL);
	
	if ((!tmpbuf)||(!tmpoobbuf)) {
		printk ("Unable to allocate SL2312 NAND MTD device structure.\n");
		
	}
	if (!this->oob_buf) {
		size_t len;
		len = mtd->oobsize << (this->phys_erase_shift - this->page_shift);
		this->oob_buf = kmalloc (len, GFP_KERNEL);
		if (!this->oob_buf) {
			printk (KERN_ERR "csnand_scan(): Cannot allocate oob_buf\n");
			return -ENOMEM;
		}
		this->options |= NAND_OOBBUF_ALLOC;
	}

	if (!this->data_buf) {
		size_t len;
		len = mtd->oobblock + mtd->oobsize;
		this->data_buf = kmalloc (len, GFP_KERNEL);
		if (!this->data_buf) {
			if (this->options & NAND_OOBBUF_ALLOC)
				kfree (this->oob_buf);
			printk (KERN_ERR "csnand_scan(): Cannot allocate data_buf\n");
			return -ENOMEM;
		}
		this->options |= NAND_DATABUF_ALLOC;
	}

	/* Store the number of chips and calc total size for mtd */
	this->numchips = i;
	mtd->size = i * this->chipsize;
	/* Convert chipsize to number of pages per chip -1. */
	this->pagemask = (this->chipsize >> this->page_shift) - 1;
	/* Preset the internal oob buffer */
	memset(this->oob_buf, 0xff, mtd->oobsize << (this->phys_erase_shift - this->page_shift));

	/* If no default placement scheme is given, select an
	 * appropriate one */
	if (!this->autooob) {
		/* Select the appropriate default oob placement scheme for
		 * placement agnostic filesystems */
		switch (mtd->oobsize) {
		case 8:
			this->autooob = &nand_oob_8;
			break;
		case 16:
			this->autooob = &nand_oob_16;
			break;
		case 64:
			this->autooob = &nand_oob_64;
			break;
		default:
			printk (KERN_WARNING "No oob scheme defined for oobsize %d\n",
				mtd->oobsize);
			BUG();
		}
	}

#if FORCE_DMA_ACCESS	
	// set dma fifo port
	FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
	//kmalloc(TBUF_SIZE, GFP_ATOMIC|GFP_DMA);
	//write_data = kmalloc ((mtd->oobblock + mtd->oobsize), GFP_ATOMIC|GFP_DMA);
	//read_data = kmalloc ((mtd->oobblock + mtd->oobsize), GFP_ATOMIC|GFP_DMA);
	//read_dma, write_dma;
	write_data = (unsigned char *)pci_alloc_consistent(NULL,(mtd->oobblock + mtd->oobsize),(dma_addr_t *)&write_dma);
	read_data = (unsigned char *)pci_alloc_consistent(NULL,(mtd->oobblock + mtd->oobsize),(dma_addr_t *)&read_dma);
		
	if (!write_data||!read_data) {
		if (write_data)
			kfree (write_data); 
		if (read_data)
			kfree (read_data);
		printk (KERN_ERR "csnand_scan(): Cannot allocate write_data or read_data\n");
		return -ENOMEM;
	}

#endif	
	/* The number of bytes available for the filesystem to place fs dependend
	 * oob data */
	mtd->oobavail = 0;
	for (i = 0; this->autooob->oobfree[i][1]; i++)
		mtd->oobavail += this->autooob->oobfree[i][1];

	/*
	 * check ECC mode, default to software
	 * if 3byte/512byte hardware ECC is selected and we have 256 byte pagesize
	 * fallback to software ECC
	*/
	this->eccsize = 256;	/* set default eccsize */
	this->eccbytes = 3;

	switch (this->eccmode) {
	case NAND_ECC_HW12_2048:
		if (mtd->oobblock < 2048) {
			printk(KERN_WARNING "2048 byte HW ECC not possible on %d byte page size, fallback to SW ECC\n",
			       mtd->oobblock);
			this->eccmode = NAND_ECC_SOFT;
			this->calculate_ecc = nand_calculate_ecc;
			this->correct_data = nand_correct_data;
		} else
			this->eccsize = 2048;
		break;

	case NAND_ECC_HW3_512:
	case NAND_ECC_HW6_512:
	case NAND_ECC_HW8_512:
		if (mtd->oobblock == 256) {
			printk (KERN_WARNING "512 byte HW ECC not possible on 256 Byte pagesize, fallback to SW ECC \n");
			this->eccmode = NAND_ECC_SOFT;
			this->calculate_ecc = nand_calculate_ecc;
			this->correct_data = nand_correct_data;
		} else
			this->eccsize = 512; /* set eccsize to 512 */
		break;

	case NAND_ECC_HW3_256:
		break;

	case NAND_ECC_NONE:
		printk (KERN_WARNING "NAND_ECC_NONE selected by board driver. This is not recommended !!\n");
		this->eccmode = NAND_ECC_NONE;
		break;

	case NAND_ECC_SOFT:
		this->calculate_ecc = nand_calculate_ecc;
		this->correct_data = nand_correct_data;
		break;

	default:
		printk (KERN_WARNING "Invalid NAND_ECC_MODE %d\n", this->eccmode);
		BUG();
	}

	/* Check hardware ecc function availability and adjust number of ecc bytes per
	 * calculation step
	*/
	switch (this->eccmode) {
	case NAND_ECC_HW12_2048:
		this->eccbytes += 4;
	case NAND_ECC_HW8_512:
		this->eccbytes += 2;
	case NAND_ECC_HW6_512:
		this->eccbytes += 3;
	case NAND_ECC_HW3_512:
	case NAND_ECC_HW3_256:
		if (this->calculate_ecc && this->correct_data && this->enable_hwecc)
			break;
		printk (KERN_WARNING "No ECC functions supplied, Hardware ECC not possible\n");
		BUG();
	}

	mtd->eccsize = this->eccsize;

	/* Set the number of read / write steps for one page to ensure ECC generation */
	switch (this->eccmode) {
	case NAND_ECC_HW12_2048:
		this->eccsteps = mtd->oobblock / 2048;
		break;
	case NAND_ECC_HW3_512:
	case NAND_ECC_HW6_512:
	case NAND_ECC_HW8_512:
		this->eccsteps = mtd->oobblock / 512;
		break;
	case NAND_ECC_HW3_256:
	case NAND_ECC_SOFT:
		this->eccsteps = mtd->oobblock / 256;
		break;

	case NAND_ECC_NONE:
		this->eccsteps = 1;
		break;
	}

	/* Initialize state, waitqueue and spinlock */
	this->state = FL_READY;
	init_waitqueue_head (&this->wq);
	spin_lock_init (&this->chip_lock);

	/* De-select the device */
	this->select_chip(mtd, -1);

	/* Invalidate the pagebuffer reference */
	this->pagebuf = -1;

	/* Fill in remaining MTD driver data */
	mtd->type = MTD_NANDFLASH;
	mtd->flags = MTD_CAP_NANDFLASH | MTD_ECC;
	mtd->ecctype = MTD_ECC_SW;
	mtd->erase = csnand_erase;
	mtd->point = NULL;
	mtd->unpoint = NULL;
	mtd->read = csnand_read;
	mtd->write = csnand_write;
	mtd->read_ecc = csnand_read_ecc;
	mtd->write_ecc = csnand_write_ecc;
	mtd->read_oob = csnand_read_oob;
	mtd->write_oob = csnand_write_oob;
	mtd->readv = NULL;
	mtd->writev = csnand_writev;
	mtd->writev_ecc = csnand_writev_ecc;
	mtd->sync = csnand_sync;
	mtd->lock = NULL;
	mtd->unlock = NULL;
	mtd->suspend = NULL;//csnand_suspend;
	mtd->resume = NULL;//csnand_resume;
	mtd->block_isbad = csnand_block_isbad;
	mtd->block_markbad = csnand_block_markbad;

	/* and make the autooob the default one */
	memcpy(&mtd->oobinfo, this->autooob, sizeof(mtd->oobinfo));

	mtd->owner = THIS_MODULE;

	/* Check, if we should skip the bad block table scan */
	if (this->options & NAND_SKIP_BBTSCAN)
		return 0;

	/* Build bad block table */
	return this->scan_bbt (mtd);
}

/* 
 *	hardware specific access to control-lines
*/
static void csnand_hwcontrol(struct mtd_info *mtd, int cmd)
{

	return ;	 
}

void csenable_hwecc(struct mtd_info *mtd, int mode)
{
	/* reset first */
	FLASH_WRITE_REG(NFLASH_ECC_CONTROL, FLASH_START_BIT|ECC_CLR); //set 31b = 0
	
}



static int csnand_waitfunc(struct mtd_info *mtd, struct nand_chip *this, int state)
{
	unsigned long	timeo = jiffies;
	int	status;

	if (state == FL_ERASING)
		 timeo += (HZ * 400) / 100;
	else
		 timeo += (HZ * 20) / 100;

	/* Apply this short delay always to ensure that we do wait tWB in
	 * any case on any machine. */
	ndelay (100);

	while (time_before(jiffies, timeo)) {
		/* Check, if we were interrupted */
		if (this->state != state)
			return 0;

		if (this->dev_ready) {
			if (this->dev_ready(mtd))
				break;
			else
			{
				if ((FLASH_READ_REG(NFLASH_DATA)&0xff) & NAND_STATUS_READY)
					break;
			}
		} else {
			//if (this->read_byte(mtd) & NAND_STATUS_READY)
			if ((FLASH_READ_REG(NFLASH_DATA)&0xff) & NAND_STATUS_READY)
				break;
		}
		cond_resched();
	}
	status = FLASH_READ_REG(NFLASH_DATA)&0xff;
	return status;
}

/**
 * nand_block_checkbad - [GENERIC] Check if a block is marked bad
 * @mtd:	MTD device structure
 * @ofs:	offset from device start
 * @getchip:	0, if the chip is already selected
 * @allowbbt:	1, if its allowed to access the bbt area
 *
 * Check, if the block is bad. Either by reading the bad block table or
 * calling of the scan function.
 */
 
static int csnand_erase_block(struct mtd_info *mtd, int page)
{
	int opcode;
	if(debug_f)
		printk("%s : -->\n",__func__);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif		
	/* Send commands to erase a page */
		FLASH_WRITE_REG(NFLASH_ECC_CONTROL, 0x0); //set 31b = 0
	
		if(((*(mtd)).size / (*(mtd)).oobblock) > 0x10000)
		    FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_EMPTY_DATA|NCNT_ADDR_3|NCNT_CMD_2);//0x7f0fff21);  // 3 address & 2 command
		else
		    FLASH_WRITE_REG(NFLASH_COUNT, NCNT_EMPTY_OOB|NCNT_EMPTY_DATA|NCNT_DATA_2|NCNT_CMD_2);//0x7f0fff11);  // 2 address & 2 command
		
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, ((NAND_CMD_ERASE2<<8)|NAND_CMD_ERASE1)); // write read id command
		FLASH_WRITE_REG(NFLASH_ADDRESS, page); //write address 0x00
		
		
		    
		/* read maker code */
		opcode = FLASH_START_BIT|FLASH_WT|DWIDTH|CHIP_EN; //set start bit & 8bits write command
		FLASH_WRITE_REG(NFLASH_ACCESS, opcode); 
		
		while(opcode&FLASH_START_BIT) //polling flash access 31b
      	{
           opcode=FLASH_READ_REG(NFLASH_ACCESS);
           //sl2312_flash_delay();
           schedule();
           //cond_resched();
      	}
      	if(debug_f)
			printk("%s : <--\n",__func__);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif			
		//return 0;
		
}

/*
 * Main initialization routine
 */
extern int nand_correct_data(struct mtd_info *mtd, u_char *dat, u_char *read_ecc, u_char *calc_ecc);

/**
 * csnand_verify_pages - [GENERIC] verify the chip contents after a write
 * @mtd:	MTD device structure
 * @this:	NAND chip structure
 * @page: 	startpage inside the chip, must be called with (page & this->pagemask)
 * @numpages:	number of pages to verify
 * @oob_buf:	out of band data buffer
 * @oobsel:	out of band selecttion structre
 * @chipnr:	number of the current chip
 * @oobmode:	1 = full buffer verify, 0 = ecc only
 *
 * The NAND device assumes that it is always writing to a cleanly erased page.
 * Hence, it performs its internal write verification only on bits that
 * transitioned from 1 to 0. The device does NOT verify the whole page on a
 * byte by byte basis. It is possible that the page was not completely erased
 * or the page is becoming unusable due to wear. The read with ECC would catch
 * the error later when the ECC page check fails, but we would rather catch
 * it early in the page write stage. Better to write no data than invalid data.
 */
#ifdef CONFIG_MTD_NAND_VERIFY_WRITE
static int csnand_verify_pages (struct mtd_info *mtd, struct nand_chip *this, int page, int numpages,
	u_char *oob_buf, struct nand_oobinfo *oobsel, int chipnr, int oobmode)
{
	int 	i, j, datidx = 0, oobofs = 0, res = -EIO;
	int	eccsteps = this->eccsteps;
	int	hweccbytes;
	u_char 	oobdata[64];
	if(debug_f)
		printk("%s : -->\n",__func__);
	hweccbytes = (this->options & NAND_HWECC_SYNDROME) ? (oobsel->eccbytes / eccsteps) : 0;

	/* Send command to read back the first page */
	this->cmdfunc (mtd, NAND_CMD_READ0, 0, page);

	for(;;) {
		
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif	
#ifdef CONFIG_GEMINI_NAND_INDIRECT
	unsigned int nopcode,dent_bit,tt, *prddata,*prdoob;
	
		FLASH_WRITE_REG(NFLASH_ACCESS, NFLASH_INDIRECT);
		
			ADD5=ADD4=ADD3=ADD2=0;
			
			if(mtd->oobblock < PAGE512_RAW_SIZE)
				ADD5 = (page>>24)&0xff;
				
    		ADD5=(page>>16)&0xff; 
			ADD4=(page>>8)&0xff;
			ADD3=(page)&0xff;
#if FORCE_DMA_ACCESS	
		pread = (unsigned int *) read_data; 
		//memset(read_data, 0xff, (mtd->oobblock+mtd->oobsize));
		WRITE_DMA_REG(DMA_SYNC, DMA_CH0_SYNC);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_CLR_FIFO); //clear fifo
		WRITE_DMA_REG(DMA_MAIN_CFG, DMA_ENABLE); //enable DMA
		WRITE_DMA_REG(DMA_CH0_SRC_ADDR, (NFLASH_DMA_FIFO+SL2312_FLASH_CTRL_BASE)); //src_address
		WRITE_DMA_REG(DMA_CH0_DST_ADDR, read_dma); //dest_address
		WRITE_DMA_REG(DMA_CH0_LLP, 0x0); //LLP
		WRITE_DMA_REG(DMA_CH0_SIZE, ((mtd->oobblock+mtd->oobsize)/4)); //size
		WRITE_DMA_REG(DMA_CH0_CFG, DMA_ABORT_INT); //CFG
		WRITE_DMA_REG(DMA_CH0_CSR, 0x112c3); //CSR
#endif	    
    	dent_bit=FLASH_READ_REG(NFLASH_TYPE);
		switch(dent_bit&FLASH_SIZE_MASK)
		{
			case FLASH_SIZE_32:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_3|NCNT_CMD_1);//0x0f01ff20);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_64:
			case FLASH_SIZE_128:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_512P_OOB|NCNT_512P_DATA|NCNT_ADDR_4|NCNT_CMD_1);//0x0f01ff30);
			    nopcode = NAND_CMD_READ0;
			break;
			
			case FLASH_SIZE_256:
				FLASH_WRITE_REG(NFLASH_COUNT, NCNT_2kP_OOB|NCNT_2kP_DATA|NCNT_ADDR_5|NCNT_CMD_2);//0x3f07ff41);
			    nopcode = (NAND_CMD_READSTART<<8)|NAND_CMD_READ0;//0x00003000;
			break;
		}
		nopcode |= (ADD5<<24);
		FLASH_WRITE_REG(NFLASH_CMD_ADDR, nopcode); //write address 0x00
		
		nopcode = 0x0|(ADD4<<24)|(ADD3<<16)|(ADD2<<8);
		FLASH_WRITE_REG(NFLASH_ADDRESS, nopcode); //write address 0x00
		
		pread = (unsigned int *) read_data; 
#if FORCE_DMA_ACCESS	
		
		// set dma fifo port
		FLASH_WRITE_REG(NFLASH_FIFO_ADDRESS, NFLASH_DMA_FIFO);
		FLASH_WRITE_REG(NFLASH_FIFO_CONTROL, FLASH_START_BIT|FLASH_RD);
		nopcode=READ_DMA_REG(DMA_TC);
		while(!(nopcode&DMA_CH0_TC)) //polling flash access 31b
      	{
          nopcode=READ_DMA_REG(DMA_TC); 
          udelay(2);
      	}
	    nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL); 		
		while(nopcode&FLASH_START_BIT) //polling flash access 31b
      	{
          nopcode=FLASH_READ_REG(NFLASH_FIFO_CONTROL);
          udelay(2);
      	}
      	
      	//Disable channel 0 DMA
      	WRITE_DMA_REG(DMA_CH0_CSR, DMA_CH0_DISABLE);
      	//DMA TC int status Rg
      	//write clear int
      	WRITE_DMA_REG(DMA_INT_TC_CLR, DMA_CH0_TC);
      	//Flash status Reg
      	//write clear fifo_int
      	FLASH_WRITE_REG(NFLASH_STATUS, 0x20000);
		
		
#else		
		for(i=0;i<((mtd->oobblock+mtd->oobsize)/4);i++)
        {	
        	nopcode = FLASH_START_BIT | FLASH_RD|NFLASH_CHIP0_EN|NFLASH_WiDTH32|NFLASH_INDIRECT; //set start bit & 8bits read command
			FLASH_WRITE_REG(NFLASH_ACCESS, nopcode); 
			while(nopcode&FLASH_START_BIT) //polling flash access 31b
      		{
        	   nopcode=FLASH_READ_REG(NFLASH_ACCESS);
        	   udelay(2);
        	   schedule();
      		}
      		    
      		dent_bit = FLASH_READ_REG(NFLASH_DATA);    
      			pread[i] = dent_bit; 

		}

#endif
#else  //direct		
	//printk("%s (%x): oobtmp",__func__,page);
	int j;
	for(i=0,j=0;i<(mtd->oobblock+mtd->oobsize);i++)
	{
		//if(i<mtd->oobblock)
			read_data[i] = (unsigned char)FLASH_READ_DATA(page*mtd->oobblock +i);
	}
	//printk("\n");
	///* read oobdata */
	//for (i = 0; i <  mtd->oobsize; i++) 
	//	oobtmp[i] =(unsigned char) FLASH_READ_DATA(page*mtd->oobblock + mtd->oobblock + i);
#endif		
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif		
		for (i=0; i<mtd->oobblock; i++)
		{
			if (this->data_poi[datidx+i] != read_data[i])
			{
				DEBUG (MTD_DEBUG_LEVEL0, "%s: " "Failed write verify, page 0x%08x ", __FUNCTION__, page);
				goto out;
			}
		}
		for (i=0; i<mtd->oobsize; i++)
		{
			if (oob_buf[oobofs+i] != read_data[mtd->oobblock+i])
			{
				DEBUG (MTD_DEBUG_LEVEL0, "%s: " "Failed write verify, page 0x%08x ", __FUNCTION__, page);
				goto out;
			}
		}
				
		oobofs += mtd->oobsize - hweccbytes * eccsteps;
		datidx += mtd->oobblock;
		page++;
		nand_page = page;
		numpages--;

		/* Apply delay or wait for ready/busy pin
		 * Do this before the AUTOINCR check, so no problems
		 * arise if a chip which does auto increment
		 * is marked as NOAUTOINCR by the board driver.
		 * Do this also before returning, so the chip is
		 * ready for the next command.
		*/
		if (!this->dev_ready)
			udelay (this->chip_delay);
		else
			csnand_wait_ready(mtd);

		/* All done, return happy */
		if (!numpages)
			return 0;


		/* Check, if the chip supports auto page increment */
		if (!NAND_CANAUTOINCR(this))
			this->cmdfunc (mtd, NAND_CMD_READ0, 0x00, page);
	}
	/*
	 * Terminate the read command. We come here in case of an error
	 * So we must issue a reset command.
	 */
out:
	this->cmdfunc (mtd, NAND_CMD_RESET, -1, -1);
	return res;
}
#endif

int __init csmtd_init (void)
{
	struct nand_chip *this;
	int err = 0;
	struct mtd_partition *parts;
	int nr_parts = 0;
	int ret, data, *base;
	struct mtd_info *mymtd=NULL;
	int i;
	
	printk("NAND MTD Driver Start Init ......\n");
	
    	//base = (unsigned int *)(IO_ADDRESS(csGLOBAL_BASE) + GLOBAL_MISC_CTRL);
    	//data = *base;
    	//data&=0xffffffeb;
    	//data|=0x3; //disable p & s flash
        //*base = data;
        
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif
    
	/* Allocate memory for MTD device structure and private data */
	csmtd = kmalloc(sizeof(struct mtd_info) + sizeof(struct nand_chip), GFP_KERNEL);
	if (!csmtd) {
		printk ("Unable to allocate CS35xx NAND MTD device structure.\n");
		err = -ENOMEM;
		goto out;
	}
	//printk("sizeof(struct mtd_info) :%x sizeof(struct nand_chip):%x\n",sizeof(struct mtd_info) ,sizeof(struct nand_chip));
      //  csdevice_setup();

	/* io is indirect via a register so don't need to ioremap address */

	/* Get pointer to private data */
	this = (struct nand_chip *) (&csmtd[1]);

	/* Initialize structures */
	memset((char *) csmtd, 0, sizeof(struct mtd_info));
	memset((char *) this, 0, sizeof(struct nand_chip));

	/* Link the private data with the MTD structure */
	csmtd->priv = this;
	csmtd->name = "cs35xx-nand";

	/* Set address of NAND IO lines */
	this->IO_ADDR_R = (void __iomem *)IO_ADDRESS((SL2312_FLASH_CTRL_BASE+NFLASH_DATA)); //(unsigned long)&(sl2312_ndfmcptr->dtr);
	this->IO_ADDR_W = (void __iomem *)IO_ADDRESS((SL2312_FLASH_CTRL_BASE+NFLASH_DATA)); //(unsigned long)&(sl2312_ndfmcptr->dtr);
	this->read_byte = csnand_read_byte;
    this->write_byte = csnand_write_byte;
    this->write_buf = csnand_write_buf;
	this->read_buf = csnand_read_buf;
	this->verify_buf = csnand_verify_buf;
	this->select_chip = csnand_select_chip;
	this->block_bad = csnand_block_bad;
	this->hwcontrol = csnand_hwcontrol;
	this->dev_ready = csnand_device_ready;
	this->cmdfunc = csnand_command;
	this->waitfunc = csnand_waitfunc;
	//this->calculate_ecc = csreadecc;
	this->enable_hwecc = csenable_hwecc;
#ifdef CONFIG_YAFFS_FS	
#if 0
	this->eccmode = NAND_ECC_NONE;
#else	
	this->eccmode = NAND_ECC_SOFT;//NAND_ECC_NONE;
	this->calculate_ecc = nand_calculate_ecc;
	this->correct_data = nand_correct_data;
#endif	
#else	
	this->eccmode = NAND_ECC_HW3_512;	
#endif	
	/*this->eccsize = 512;	*/ 
	/* 20 us command delay time */
	this->chip_delay = 20;	
	
	this->correct_data = nand_correct_data;
	//this->scan_bbt = csnand_scan_bbt;//nand_default_bbt;//csnand_scan_bbt;
	
	/* set the bad block tables to support debugging */
	this->bbt_td = &cs_bbt_main_descr;
	this->bbt_md = &cs_bbt_mirror_descr;
	///* Allocate memory for internal data buffer */
	//this->data_buf = kmalloc (sizeof(u_char) * (csmtd->oobblock + csmtd->oobsize), GFP_KERNEL);
	//if (!this->data_buf) {
	//	printk ("Unable to allocate NAND data buffer.\n");
	//	err = -ENOMEM;
	//	goto out_ior;
	//}
	
	/* Scan to find existance of the device */
	if (csnand_scan(csmtd, 1)) {
		err = -ENXIO;
		goto out_ior;
	}
	
	/* Register the partitions */
	parts = sl2312_partitions;
	nr_parts = sizeof(sl2312_partitions)/sizeof(*parts);

	ret = add_mtd_partitions(csmtd, sl2312_partitions, nr_parts); 
	/*If we got an error, free all resources.*/
	if (ret < 0) {
		del_mtd_partitions(csmtd);
		map_destroy(csmtd);
	}
	goto out;

//out_buf:
//	kfree (this->data_buf);    
out_ior:
out:

#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
	printk("NAND MTD Driver Init Success ......\n");
	
	return err;
}

module_init(csmtd_init);


char chrtohex(char c)
{
  char val;
  if ((c >= '0') && (c <= '9'))
  {
    val = c - '0';
    return val;
  }
  else if ((c >= 'a') && (c <= 'f'))
  {
    val = 10 + (c - 'a');
    return val;
  }
  else if ((c >= 'A') && (c <= 'F'))
  {
    val = 10 + (c - 'A');
    return val;
  }
  printk("<1>Error number\n");
  return 0;
}


int get_vlaninfo(vlaninfo* vlan)
{
	if(debug_f)
		printk("%s : -->\n",__func__);
	vctl_mheader head;
	vctl_entry entry;
	struct mtd_info *mymtd=NULL;
	int i, j, loc = 0;
	char *payload=0, *tmp1, *tmp2, tmp3[9];
	size_t retlen;

#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif
	for(i=0;i<MAX_MTD_DEVICES;i++)
	{
		mymtd=get_mtd_device(NULL,i);
		//    printk("mymtd->name: %s\n", mymtd->name);
		if(mymtd && !strcmp(mymtd->name,"VCTL"))
		{
			//      printk("%s\n", mymtd->name);
			break;
		}
	}
	if( i >= MAX_MTD_DEVICES)
	{
		printk("Can't find version control\n");
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
		if(debug_f)
		printk("%s : <-- 1 \n",__func__);
		return 0;
	}

	if (!mymtd | !mymtd->read)
	{
		printk("<1>Can't read Version Configuration\n");
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
		if(debug_f)
		printk("%s : <-- 2 \n",__func__);
		return 0;
	}
	
	for(i=0; i<mymtd->size; i += mymtd->erasesize,loc += mymtd->erasesize)
	{
		if(mymtd->block_isbad(mymtd, loc))
			continue;
		else
			break;
	}
	if(loc>=mymtd->size)
	{
		printk("No good block in VCTL\n");
		return 1;
	}

	mymtd->read(mymtd, loc, VCTL_HEAD_SIZE, &retlen, (u_char*)&head);
	//  printk("entry header: %c%c%c%c\n", head.header[0], head.header[1], head.header[2], head.header[3]);
	//  printk("entry number: %x\n", head.entry_num);
	if ( strncmp(head.header, "FLFM", 4) )
	{
		printk("VCTL is a erase block\n");
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
	if(debug_f)
		printk("%s : <-- 3 \n",__func__);
		return 0;
	}
	loc += retlen;
	for (i = 0; i < head.entry_num; i++)
	{
		mymtd->read(mymtd, loc, VCTL_ENTRY_LEN, &retlen, (u_char*)&entry);
		//    printk("type: %x\n", entry.type);
		//    printk("size: %x\n", entry.size);
		strncpy(tmp3, entry.header, 4);
		if (entry.type == VCT_VLAN)
		{
			for (j = 0; j < 6 ; j++)
			{
				vlan[0].mac[j] = 0;
				vlan[1].mac[j] = 0;
			}
			vlan[0].vlanid = 1;
			vlan[1].vlanid = 2;
			vlan[0].vlanmap = 0x7F;
			vlan[1].vlanmap = 0x80;

			payload = (char *)kmalloc(entry.size - VCTL_ENTRY_LEN, GFP_KERNEL);
			loc += VCTL_ENTRY_LEN;
			mymtd->read(mymtd, loc, entry.size - VCTL_ENTRY_LEN, &retlen, payload);
			//      printk("%s\n", payload);
			tmp1 = strstr(payload, "MAC1:");
			tmp2 = strstr(payload, "MAC2:");
			if(!tmp1||!tmp2){
				kfree(payload);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
				printk("Error VCTL format!!\n");
				if(debug_f)
						printk("%s : <-- 3 \n",__func__);
				return;
			}
			tmp1 += 7;
			tmp2 += 7;


			for (j = 0; j < 6; j++)
			{
				vlan[0].mac[j] = chrtohex(tmp1[2*j])*16 + chrtohex(tmp1[(2*j)+1]);
				vlan[1].mac[j] = chrtohex(tmp2[2*j])*16 + chrtohex(tmp2[(2*j)+1]);
			}
			tmp1 = strstr(payload, "ID1:");
			tmp2 = strstr(payload, "ID2:");
			tmp1 += 4;
			tmp2 += 4;
			vlan[0].vlanid = tmp1[0] - '0';
			vlan[1].vlanid = tmp2[0] - '0';
			tmp1 = strstr(payload, "MAP1:");
			tmp2 = strstr(payload, "MAP2:");
			tmp1 += 7;
			tmp2 += 7;
			vlan[0].vlanmap = chrtohex(tmp1[0]) * 16 + chrtohex(tmp1[1]);
			vlan[1].vlanmap = chrtohex(tmp2[0]) * 16 + chrtohex(tmp2[1]);
			//  printk("Vlan1 id:%x map:%02x mac:%x%x%x%x%x%x\n", vlan[0].vlanid, vlan[0].vlanmap, vlan[0].mac[0], vlan[0].mac[1], vlan[0].mac[2], vlan[0].mac[3], vlan[0].mac[4], vlan[0].mac[5]);
			//  printk("Vlan2 id:%x map:%02x mac:%x%x%x%x%x%x\n", vlan[1].vlanid, vlan[1].vlanmap, vlan[1].mac[0], vlan[1].mac[1], vlan[1].mac[2], vlan[1].mac[3], vlan[1].mac[4], vlan[1].mac[5]);
			break;
		}
		loc += entry.size;
	}
	if ( entry.type == VCT_VLAN )
	{
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
		if(debug_f)
		printk("%s : <-- 5 \n",__func__);
		kfree(payload);
		return 1;
	}
	if (i >= head.entry_num)
	printk("Can't find vlan information\n");
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
	if(debug_f) 
		printk("%s : <--\n",__func__);
	return 0;
}

EXPORT_SYMBOL(get_vlaninfo);
#if 0
int copy_vctl_to_shared_mem(void)
{
	vctl_mheader head;
	vctl_entry entry;
	struct mtd_info *mymtd = NULL;
	int i, j, loc = 0;
	char *payload=NULL, *tmp=NULL;
	size_t retlen, copied=0;

	char *shared_mem = (char*)IO_ADDRESS(IPC_VCTL_BASE);
	if(debug_f)
		printk("%s : -->\n",__func__);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_lock();				// sl2312 share pin lock
#endif

	for (i=0; i<MAX_MTD_DEVICES; i++) {
		mymtd = get_mtd_device(NULL, i);
		if (mymtd && !strcmp(mymtd->name, "VCTL")) {
			break;
		}
	}

	if (i >= MAX_MTD_DEVICES || !mymtd || !mymtd->read) {
		printk("Can't find or access version control!\n");
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
		return 0;
	}

	mymtd->read(mymtd, 0, IPC_VCTL_SIZE, &retlen, (u_char*)shared_mem);

#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
	return 1;

#if 0
	// we cannot use the following code due to incorrect entry.size value in vctl_entry.
	mymtd->read(mymtd, 0, VCTL_HEAD_SIZE, &retlen, (u_char*)&head);
	loc += retlen;

	memcpy(shared_mem, &head, retlen);
	printk("%s::copied head %d to shared mem %x, entries %d\n",
		__func__, retlen, shared_mem, head.entry_num);
	shared_mem += retlen;
	copied += retlen;

	for (i=0; i<head.entry_num; i++) {
		// copy vctl_entry to shared memory
		mymtd->read(mymtd, loc, VCTL_ENTRY_LEN, &retlen, (u_char*)&entry);
		loc += retlen;
		//loc += VCTL_ENTRY_LEN;
		if ((copied+retlen) > IPC_VCTL_SIZE) {
			printk("%s::exceeds shared memory boundary! %x\n",
				__func__, shared_mem+VCTL_ENTRY_LEN);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
			return 0;
		}
		memcpy(shared_mem, &entry, retlen);
		printk("%s::copied %d to shared mem %x, retlen %d, ENTRY LEN %d, payload size %d, type %d, v1 %s, v2 %s\n",
			__func__, VCTL_ENTRY_LEN, shared_mem, retlen, VCTL_ENTRY_LEN, entry.size, entry.type, entry.majorver, entry.minorver);
		shared_mem += retlen;
		copied += retlen;

		if (entry.size > VCTL_ENTRY_LEN) {
			payload = (char*)kmalloc(entry.size-VCTL_ENTRY_LEN, GFP_KERNEL);
			if (!payload) {
				printk("%s::cannot allocate memory %d\n", __func__, entry.size-VCTL_ENTRY_LEN);
				break;
			}
			mymtd->read(mymtd, loc, entry.size-VCTL_ENTRY_LEN, &retlen, payload);
			loc += VCTL_ENTRY_LEN;

			if ((copied + entry.size-VCTL_ENTRY_LEN) > IPC_VCTL_SIZE) {
				printk("%s::exceeds shared memory boundary! %x\n",
					__func__, shared_mem+entry.size-VCTL_ENTRY_LEN);
				kfree(payload);
#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
				return 0;
			}
			memcpy(shared_mem, payload, entry.size-VCTL_ENTRY_LEN);
			printk("%s::copied entry payload %d to shared mem %x\n",
				__func__, entry.size-VCTL_ENTRY_LEN, shared_mem);
			shared_mem += (entry.size-VCTL_ENTRY_LEN);
			copied += (entry.size-VCTL_ENTRY_LEN);

			kfree(payload);
		}
	}
#endif

#ifdef CONFIG_SL2312_SHARE_PIN	
	mtd_unlock();				// sl2312 share pin lock
#endif
	if(debug_f)
		printk("%s : <--\n",__func__);
	return 1;
}
EXPORT_SYMBOL(copy_vctl_to_shared_mem);
#endif
/*
 * Clean up routine
 */
#ifdef MODULE
static void __exit cscleanup (void)
{
	struct nand_chip *this = (struct nand_chip *) &csmtd[1];

	if (tmpbuf) {
		free(tmpbuf);
		
	}
	if (tmpoobbuf) {
		free(tmpoobbuf);
		
	}
	/* Unregister partitions */
	del_mtd_partitions(csmtd); 
	
	/* Unregister the device */
	del_mtd_device (csmtd);

	/* Free internal data buffers */
	kfree (this->data_buf);

	/* Free the MTD device structure */
	kfree (csmtd); 
}
module_exit(cscleanup);
#endif

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("Middle Huang");
MODULE_DESCRIPTION ("Cortina NAND flash driver code");
