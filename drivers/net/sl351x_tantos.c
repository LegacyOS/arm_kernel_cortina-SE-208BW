/*
 * 	Copyright (c) 2008 Cortina Systems, Inc.
 * 	All Rights Reserved.
 *
 *	Description: 
 * 	Driver for Tantos-0G 5 Port 10/100Mbit/s Plus 2xMII 
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

#include <asm/io.h>
#include <asm/arch/sl2312.h>
#include <asm/hardware.h>
#include <asm/arch/sl351x_tantos.h>
#include <linux/delay.h>
 
void ifx_gpio_init(void);
void ifx_mdc_hi(void);
void ifx_mdc_lo(void);
void ifx_mdcs_hi(void);
void ifx_mdcs_lo(void);
void ifx_mdio_hi(void);
void ifx_mdc_lo(void);
void ifx_mdio_mode(int mode);
static void ifx_sw_mdc_pulse(void);
static void ifx_sw_mdc_toggle(void);
int ifx_sw_mdio_readbit(void);
uint32_t ifx_sw_read(uint32_t addr, uint32_t *dat);
int ifx_sw_write(uint32_t addr, uint32_t dat);
void ifx_tantos_check_busy(void);
int tantos_chk_linked(int port);
void tantos_clr_rmon(void);
void tantos_clr_rmon_by_port(int port);

int tantos_get_portsts(int port, int state);
unsigned long tantos_get_rmon_by_off(int port, int off);

void tantos_reset(void);
int tantos_vlan_add(int port_base, int port, int fid);
int tantos_vlan_del(int port_base, int port);
int tantos_vlan_init(void);

int ifx_sw_max_port_num; 

/* command codes */
#define IFX_SW_SMI_READ		0x02
#define IFX_SW_SMI_WRITE	0x01
#define IFX_SW_SMI_START	0x01

#define IFX_SW_BIT_MASK_1	0x00000001
#define IFX_SW_BIT_MASK_2	0x00000002
#define IFX_SW_BIT_MASK_4	0x00000008
#define IFX_SW_BIT_MASK_10	0x00000200
#define IFX_SW_BIT_MASK_16	0x00008000
#define IFX_SW_BIT_MASK_32	0x80000000

/* delay timers */
#define IFX_SW_MDC_DOWN_DELAY	5
#define IFX_SW_MDC_UP_DELAY		5
#define IFX_SW_CS_DELAY			5

/* MDIO modes */
#define IFX_SW_MDIO_OUTPUT	1
#define IFX_SW_MDIO_INPUT	0

/*
 * define ADM8668 GPIO port to ADM6996 EEPROM interface
 * MDIO -> EEDI (GPIO 2, bi-direction)
 * MDCS -> EECS (GPIO 0, output only)
 * MDC -> EESK (GPIO 1, output only)
 *        EEDO (do not need this one!)
 */
#define MDIO_BIT	4
#define MDC_BIT		5
#define MDCS_BIT	31

#define GPIO_MDIO   BIT(MDIO_BIT)		
#define GPIO_MDC    BIT(MDC_BIT)		
#define GPIO_MDCS   BIT(MDCS_BIT)		

#define MDIO_INPUT		0x00000001	/* no use in ADM8668 */
#define MDIO_OUTPUT_EN	0x0004000

#define GPIO_SET_HI(x)		WRITE32(GPIO_BASE_ADD + GPIO_DATA_SET, x)
#define GPIO_SET_LOW(x)		WRITE32(GPIO_BASE_ADD + GPIO_DATA_CLEAR, x)
#define GPIO_READ_MDIO(x)	READ32(GPIO_BASE_ADD + GPIO_DATA_IN, x)

/*
 * initialize GPIO pins.
 * output mode, low
 */
void ifx_gpio_init(void)
{
  	GPIO_SET_HI(GPIO_MDC);
  	WRITE32(GPIO_BASE_ADD1 + GPIO_DATA_CLEAR, GPIO_MDCS);
	REG32(GPIO_BASE_ADD + GPIO_PIN_DIR) |= BIT(MDC_BIT);
	REG32(GPIO_BASE_ADD + GPIO_PIN_DIR) |= BIT(MDIO_BIT);
	REG32(GPIO_BASE_ADD1 + GPIO_PIN_DIR) |= BIT(MDCS_BIT);
  	return;
}

/* read one bit from mdio port */
int ifx_sw_mdio_readbit(void)
{
  	int val;
  	
  	//val = (ADM8668_WLAN_REG(GPIO_REG) & 0x4) >> 2;
  	GPIO_READ_MDIO(val);
  	val = val & BIT(MDIO_BIT);
  	
  	return val;
}

/*
 * MDIO mode selection
 * 1 -> output
 * 0 -> input
 * switch input/output mode of GPIO 0
 */
void ifx_mdio_mode(int mode)
{
  	if (mode)	/* output */
  		REG32(GPIO_BASE_ADD + GPIO_PIN_DIR) |= BIT(MDIO_BIT);
  	else
  		REG32(GPIO_BASE_ADD + GPIO_PIN_DIR) &= ~BIT(MDIO_BIT);
}

void ifx_mdc_hi(void)
{
  	GPIO_SET_HI(GPIO_MDC);
}

void ifx_mdio_hi(void)
{
  	GPIO_SET_HI(GPIO_MDIO);
}

void ifx_mdcs_hi(void)
{
  	WRITE32(GPIO_BASE_ADD1 + GPIO_DATA_SET, GPIO_MDCS);
}

void ifx_mdc_lo(void)
{
  	GPIO_SET_LOW(GPIO_MDC);
}

void ifx_mdio_lo(void)
{
  	GPIO_SET_LOW(GPIO_MDIO);
}

void ifx_mdcs_lo(void)
{
	WRITE32(GPIO_BASE_ADD1 + GPIO_DATA_CLEAR, GPIO_MDCS);
}

static void ifx_sw_mdc_pulse(void)
{
  	ifx_mdc_lo();
  	udelay(IFX_SW_MDC_DOWN_DELAY);
  	ifx_mdc_hi();
  	udelay(IFX_SW_MDC_UP_DELAY);
  	ifx_mdc_lo();
}

static void ifx_sw_mdc_toggle(void)
{
  	ifx_mdc_hi();
  	udelay(IFX_SW_MDC_UP_DELAY);
  	ifx_mdc_lo();
  	udelay(IFX_SW_MDC_DOWN_DELAY);
}

uint32_t ifx_sw_read(uint32_t addr, uint32_t *dat)
{
  	uint32_t op;
  	*dat = 0;
  	
  	ifx_gpio_init();
  	
  	ifx_mdcs_hi();
  	udelay(IFX_SW_CS_DELAY);
  	
  	ifx_mdcs_lo();
  	ifx_mdc_lo();
  	ifx_mdio_lo();
  	
  	udelay(IFX_SW_CS_DELAY);
  	
  	/* preamble, 32 bit 1 */
  	ifx_mdio_hi();
  	op = IFX_SW_BIT_MASK_32;
  	while (op)
  	{
  	  ifx_sw_mdc_pulse();
  	  op >>= 1;
  	}
  	
  	/* command start (01b) */
  	op = IFX_SW_BIT_MASK_2;
  	while (op)
  	{
  	  if (op & IFX_SW_SMI_START)
  	    ifx_mdio_hi();
  	  else
  	    ifx_mdio_lo();
  	
  	  ifx_sw_mdc_pulse();
  	  op >>= 1;
  	}
  	
  	/* read command (10b) */
  	op = IFX_SW_BIT_MASK_2;
  	while (op)
  	{
  	  if (op & IFX_SW_SMI_READ)
  	    ifx_mdio_hi();
  	  else
  	    ifx_mdio_lo();
  	
  	  ifx_sw_mdc_pulse();
  	  op >>= 1;
  	}
  	
  	
  	/* send address A9 ~ A0 */
  	op = IFX_SW_BIT_MASK_10;
  	while (op)
  	{
  	  if (op & addr)
  	    ifx_mdio_hi();
  	  else
  	    ifx_mdio_lo();
  	
  	  ifx_sw_mdc_pulse();
  	  op >>= 1;
  	}
  	
  	/* turnaround bits */
  	op = IFX_SW_BIT_MASK_2;
  	ifx_mdio_hi();
  	while (op)
  	{
  	  ifx_sw_mdc_pulse();
  	  op >>= 1;
  	}
  	
 	udelay(IFX_SW_MDC_DOWN_DELAY);
  	
  	/* set MDIO pin to input mode */
  	ifx_mdio_mode(IFX_SW_MDIO_INPUT);
  	
  	/* start read data */
  	*dat = 0;
//  op = IFX_SW_BIT_MASK_32;	/* currently SMI interface is 16bit in GAN board */
  	op = IFX_SW_BIT_MASK_16;
  	while (op)
  	{
  	  *dat <<= 1;
  	  if (ifx_sw_mdio_readbit()) *dat |= 1;
  	  ifx_sw_mdc_toggle();
  	
  	  op >>= 1;
  	}
  	
  	/* set MDIO to output mode */
  	ifx_mdio_mode(IFX_SW_MDIO_OUTPUT);
  	
  	/* dummy clock */
  	op = IFX_SW_BIT_MASK_4;
  	ifx_mdio_lo();
  	while(op)
  	{
  	  ifx_sw_mdc_pulse();
  	  op >>= 1;
  	}
  	
  	ifx_mdc_lo();
  	ifx_mdio_lo();
  	ifx_mdcs_hi();

  	return *dat;
}

/*
 *  write register to ADM6996 eeprom registers
 */
int ifx_sw_write(uint32_t addr, uint32_t dat)
{
  	uint32_t op;
  	
  	ifx_gpio_init();
  	
  	ifx_mdcs_hi();
  	udelay(IFX_SW_CS_DELAY);
  	
  	ifx_mdcs_lo();
  	ifx_mdc_lo();
  	ifx_mdio_lo();
  	
  	udelay(IFX_SW_CS_DELAY);
  	
  	/* preamble, 32 bit 1 */
  	ifx_mdio_hi();
  	op = IFX_SW_BIT_MASK_32;
  	while (op) {
  	  	ifx_sw_mdc_pulse();
  	  	op >>= 1;
  	}
  	
  	/* command start (01b) */
  	op = IFX_SW_BIT_MASK_2;
  	while (op) {
  		if (op & IFX_SW_SMI_START) {
  	   		ifx_mdio_hi();
  	   	} else {
  	    	ifx_mdio_lo();
  	    }
  	
  	  	ifx_sw_mdc_pulse();
  	  	op >>= 1;
  	}
  	
  	/* write command (10b) */
  	op = IFX_SW_BIT_MASK_2;
  	while (op) {
  	  	if (op & IFX_SW_SMI_WRITE) {
  	    	ifx_mdio_hi();
  		} else {
  	    	ifx_mdio_lo();
  		}
  	
  	  	ifx_sw_mdc_pulse();
  	  	op >>= 1;
  	}
  	
  	/* send address A9 ~ A0 */
  	op = IFX_SW_BIT_MASK_10;
  	while (op) {
  	  if (op & addr) {
  	 	   ifx_mdio_hi();
  		} else {
  	    	ifx_mdio_lo();
  	    }
  	
  	  	ifx_sw_mdc_pulse();
  	  	op >>= 1;
  	}
  	
  	/* turnaround bits */
  	op = IFX_SW_BIT_MASK_2;
  	ifx_mdio_hi();
  	while (op) {
  	  	ifx_sw_mdc_pulse();
  	  	op >>= 1;
  	}
  	
  	udelay(IFX_SW_MDC_DOWN_DELAY);
  	
  	/* set MDIO pin to output mode */
  	ifx_mdio_mode(IFX_SW_MDIO_OUTPUT);
  	
  	/* start write data */
  	op = IFX_SW_BIT_MASK_16;
  	while (op) {
  		if (op & dat) {
  	    	ifx_mdio_hi();
  	    } else {
  			ifx_mdio_lo();
  		}
  	    
  	    ifx_sw_mdc_pulse();
  	    op >>= 1;
  	}
  	
  	/* set MDIO to output mode */
  	ifx_mdio_mode(IFX_SW_MDIO_OUTPUT);
  	
  	/* dummy clock */
  	op = IFX_SW_BIT_MASK_4;
  	ifx_mdio_lo();
  	while(op) {
  	  	ifx_sw_mdc_pulse();
  	  	op >>= 1;
  	}
  	
  	ifx_mdc_lo();
  	ifx_mdio_lo();
  	ifx_mdcs_hi();
  	
  	return 0;
}

/* 
 * check the link status
 */
int tantos_chk_linked(int port)
{
    uint32_t val;
	return (ifx_sw_read(port * 0x20, &val) & 0x1); 
}

int get_port_status(void)
{
	int i, P0, P1, P2;
	int link;
	
	for(i = 0; i < ifx_sw_max_port_num; i++) {
		P0 = tantos_get_portsts(i, 0);
		P1 = tantos_get_portsts(i, 1);
		P2 = tantos_get_portsts(i, 2);
		if (P0) {
			link = 1;
		}
	}
	return link;
}

/* 
 * Get port state
 * state: 0 -> link, 1 -> 10/100, 2 -> Half/Full, 3 -> Flow control
 */
int tantos_get_portsts(int port, int state)
{
    int reg, ret;

    reg = TANTOS_REG_P0STS + port*0x20;

    switch (state)
	{
        case 0:
            ret = (ifx_sw_read(reg, &ret) & BIT_0) >> 0;
            break;
        case 1:
		    if (ifx_sw_read(reg, &ret) & BIT_2) /* 1000Mbps */
		        ret = 2;
		    else /* 10Mbps or 100Mbps */
		        ret = (ifx_sw_read(reg, &ret) & BIT_1) >> 1;
            break;
        case 2:
            ret = (ifx_sw_read(reg, &ret) & BIT_3) >> 3;
            break;
        case 3:
            ret = (ifx_sw_read(reg, &ret) & BIT_4) >> 4;
            break;
        default:
		    /* should not be here. */
		    ret = 0;
            break;
    }
	
    return ret; 
}

/* 
 * check the RMONCTL register if it's busy or not
 */
void ifx_tantos_check_busy(void)
{
	int val; 
    uint32_t rtval;
	
	/* wait for the busy bit */
	val = ifx_sw_read(TANTOS_REG_RMONCTL, &rtval); 
	while (val & BIT_11) {
		val = ifx_sw_read(TANTOS_REG_RMONCTL, &rtval); 
	}
}

/* 
 * get a RMON counter by offset and port
 */
unsigned long tantos_get_rmon_by_off(int port, int off)
{
	uint32_t val = 0; 
	unsigned long counter;
	
	if (port >= IFX_TANTOS_MAX_PORT) return 0; 

	ifx_tantos_check_busy();
	/* read the specific port+offset counter from RMON counter */
	val = (port<<6) | BIT_11 | (off);
	ifx_sw_write(TANTOS_REG_RMONCTL, val);
	
	ifx_tantos_check_busy();
	
	/* get counters (Low)! */
	val = ifx_sw_read(TANTOS_REG_RMONLOW, &val) & 0xff;
	
	counter = val; 
	
	/* get counters (High)! */
	val = ifx_sw_read(TANTOS_REG_RMONHIGH, &val) & 0xff;
	
	counter += (val << 16);
		
	return counter;
}

/* 
 * clear ALL RMON counters
 */
void tantos_clr_rmon(void)
{
	int val; 
	
	ifx_tantos_check_busy();
	/* renew ALL RMON counters */
	val = BIT_11 | (IFX_TANTOS_CLRRMON_ALL << 9);
	ifx_sw_write(TANTOS_REG_RMONCTL, val);	
	ifx_tantos_check_busy();	
}

/* 
 * clear a RMON counter by port
 */
void tantos_clr_rmon_by_port(int port)
{
	int val; 
	
	ifx_tantos_check_busy();
	/* renew the specific port RMON counter */
	val = (port << 6) | BIT_11 | (IFX_TANTOS_CLRRMON << 9);
	ifx_sw_write(TANTOS_REG_RMONCTL, val);	
	ifx_tantos_check_busy();	
}

/* 
 * Get port packet counter (RX/TX/Collision/CRC Error)
 */
unsigned long long tantos_get_RXCNT(int port)
{
	unsigned long long val = 0;

	val = (long) tantos_get_rmon_by_off(port, 0x22);
	val <<= 32;
	val += (long) tantos_get_rmon_by_off(port, 0x23);

	return (val);
}

unsigned long long tantos_get_TXCNT(int port)
{
	unsigned long long val;

	val = (long) tantos_get_rmon_by_off(port, 0x26);
	val <<= 32;
	val += (long) tantos_get_rmon_by_off(port, 0x27);

	return (val);
}

unsigned long long tantos_get_COLCNT(int port)
{
	unsigned long long val;

	val = (long) tantos_get_rmon_by_off(port, 0x18);

	return (val);
}

unsigned long long tantos_get_ERRCNT(int port)
{
	unsigned long long val;
	
	val = (long) tantos_get_rmon_by_off(port, 0x24);
	val <<= 32;
	val += (long) tantos_get_rmon_by_off(port, 0x25);

	return (val);
}

/*
 *  add a port to certain vlan
 */
int tantos_vlan_add(int port_base, int port, int fid)
{
    int reg = 0;
    
    switch(port_base)
    {
        case 0:
            ifx_sw_read(TANTOS_REG_P0PBVM, &reg);
            reg = (fid << 14)|( 1 << port)|(reg & 0x3fff);
            ifx_sw_write(TANTOS_REG_P0PBVM, reg);
            break;
        case 1:
            ifx_sw_read(TANTOS_REG_P1PBVM, &reg);
            reg = (fid << 14)|( 1 << port)|(reg & 0x3fff);
            ifx_sw_write(TANTOS_REG_P1PBVM, reg);
            break;
        case 2:
            ifx_sw_read(TANTOS_REG_P2PBVM, &reg);
            reg = (fid << 14)|( 1 << port)|(reg & 0x3fff);
            ifx_sw_write(TANTOS_REG_P2PBVM, reg);
            break;
        case 3:
            ifx_sw_read(TANTOS_REG_P3PBVM, &reg);
            reg = (fid << 14)|( 1 << port)|(reg & 0x3fff);
            ifx_sw_write(TANTOS_REG_P3PBVM, reg);
            break;
        case 4:
            ifx_sw_read(TANTOS_REG_P4PBVM, &reg);
            reg = (fid << 14)|( 1 << port)|(reg & 0x3fff);
            ifx_sw_write(TANTOS_REG_P4PBVM, reg);
            break;
        case 5:
            ifx_sw_read(TANTOS_REG_P5PBVM, &reg);
            reg = (fid << 14)|( 1 << port)|(reg & 0x3fff);
            ifx_sw_write(TANTOS_REG_P5PBVM, reg);
            break;
        case 6:
            ifx_sw_read(TANTOS_REG_P6PBVM, &reg);
            reg = (fid << 14)|( 1 << port)|(reg & 0x3fff);
            ifx_sw_write(TANTOS_REG_P6PBVM, reg);
            break;
        default:
            /* Should not be here. */
            break;
    }

    return 0;
}

/* 
 *  delete a given port from certain vlan
 */
int tantos_vlan_del(int port_base, int port)
{
    uint32_t reg = 0;

    switch(port_base)
    {
        case 0:
            ifx_sw_read(TANTOS_REG_P0PBVM, &reg);
            reg &= ~( 1 << port);
            reg &= 0x3fff; /* Clean FID. */
            ifx_sw_write(TANTOS_REG_P0PBVM, reg);
            break;
        case 1:
            ifx_sw_read(TANTOS_REG_P1PBVM, &reg);
            reg &= ~( 1 << port);
            reg &= 0x3fff;	/* Clean FID. */
            ifx_sw_write(TANTOS_REG_P1PBVM, reg);
            break;
        case 2:
            ifx_sw_read(TANTOS_REG_P2PBVM, &reg);
            reg &= ~( 1 << port);
            reg &= 0x3fff; /* Clean FID. */
            ifx_sw_write(TANTOS_REG_P2PBVM, reg);
            break;
        case 3:
            ifx_sw_read(TANTOS_REG_P3PBVM, &reg);
            reg &= ~( 1 << port);
            reg &= 0x3fff; /* Clean FID. */
            ifx_sw_write(TANTOS_REG_P3PBVM, reg);
            break;
        case 4:
            ifx_sw_read(TANTOS_REG_P4PBVM, &reg);
            reg &= ~( 1 << port);
            reg &= 0x3fff; /* Clean FID. */
            ifx_sw_write(TANTOS_REG_P4PBVM, reg);
            break;
        case 5:
            ifx_sw_read(TANTOS_REG_P5PBVM, &reg);
            reg &= ~( 1 << port);
            reg &= 0x3fff; /* Clean FID. */
            ifx_sw_write(TANTOS_REG_P5PBVM, reg);
            break;
        case 6:
            ifx_sw_read(TANTOS_REG_P6PBVM, &reg);
            reg &= ~( 1 << port);
            reg &= 0x3fff; /* Clean FID. */
            ifx_sw_write(TANTOS_REG_P6PBVM, reg);
            break;
        default:
            /* Should not be here. */
            break;
    }

    return 0;
}

/*
 * initialize a VLAN
 * clear all VLAN bits
 */
int tantos_vlan_init(void)
{
    int i,j;
    uint32_t val;
    
    /* remove vlan_id */
    for(i = 0; i< IFX_TANTOS_MAX_PORT; i++)
        for(j = 0; j<IFX_TANTOS_MAX_PORT; j++)
            tantos_vlan_del(i, j);

    /* bypass VLAN tag */
    for(i=0;i<IFX_TANTOS_MAX_PORT;i++)
    {
        ifx_sw_read(TANTOS_REG_P0PBVM + i * 0x20, &val);
        ifx_sw_write(TANTOS_REG_P0PBVM + i * 0x20, val | BIT_7);
    }
    
    return 1;
}

/*
 * PHY reset.
 */
void tantos_reset(void)
{
    int wbusy;

    /* PHY reset from P0 to P4. */
    ifx_sw_write(TANTOS_REG_MIIWD, 0x8000);	/* MII Indirect Write Data */
    /* P0 */
    ifx_sw_write(TANTOS_REG_MIIAC, 0x0400);	/* MII Indirect Access Control, Port 0, phy addr 0 */
    while(ifx_sw_read(TANTOS_REG_MIIAC, &wbusy) & 0x8000);
    mdelay(1);
    /* P1 */
    ifx_sw_write(TANTOS_REG_MIIAC, 0x0420);/* MII Indirect Access Control, Port 1, phy addr 1 */
    while(ifx_sw_read(TANTOS_REG_MIIAC, &wbusy) & 0x8000);
    mdelay(1);
    /* P2 */
    ifx_sw_write(TANTOS_REG_MIIAC, 0x0440);/* MII Indirect Access Control, Port 2, phy addr 2 */
    while(ifx_sw_read(TANTOS_REG_MIIAC, &wbusy) & 0x8000);
    mdelay(1);
    /* P3 */
    ifx_sw_write(TANTOS_REG_MIIAC, 0x0460);
    while(ifx_sw_read(TANTOS_REG_MIIAC, &wbusy) & 0x8000);
    mdelay(1);
    /* p4 */
    ifx_sw_write(TANTOS_REG_MIIAC, 0x0480);
    while(ifx_sw_read(TANTOS_REG_MIIAC, &wbusy) & 0x8000);
    mdelay(1);
}


int ifx_sw_init(void)
{
	uint32_t val, i, a0, a1, a2;

	ifx_sw_read(TANTOS_REG_CI1, &val);
	printk("Tantos Switch ID %x\n",val);
	
	if((val & 0xFFFF) == 0x2599) {
		val = REG32(GLOBAL_BASE_ADD + 0x1c);
   		REG32(GLOBAL_BASE_ADD + 0x1c) = (val & 0xffff00ff) | 0x2900; 
    
        ifx_sw_read(0xDC,&val);  /* Broadcast to all ports ,P.131 */   
        ifx_sw_write(0xDC,0x0400);          
        
		ifx_sw_read(TANTOS_REG_SGC2, &val);
		ifx_sw_write(TANTOS_REG_SGC2, 0x8000);	/* Enable Switch */
        ifx_sw_read(TANTOS_REG_CHM, &val);
		val &= ~0xE0;
		val |= 0xa0;  /* set cpu port */
		ifx_sw_read(TANTOS_REG_CHM, &val);
		ifx_sw_write(TANTOS_REG_CHM, val);	
		ifx_sw_write(TANTOS_REG_P0BCTL, 0x0004);	/* Force Port 0 link 100-Full */
		ifx_sw_write(TANTOS_REG_P1BCTL, 0x0004);	/* Force Port 1 link 100-Full */
		ifx_sw_write(TANTOS_REG_P2BCTL, 0x0004);	/* Force Port 2 link 100-Full */
		ifx_sw_write(TANTOS_REG_P3BCTL, 0x0004);	/* Force Port 3 link 100-Full */
		
		ifx_sw_write(TANTOS_REG_P5BC, 0x0004);		/* Force Port 5 link 100-Full */
		ifx_sw_write(TANTOS_REG_P6BCTL, 0x0004);	/* Force Port 6 link 100-Full */
		ifx_sw_write(TANTOS_REG_P4BCTL, 0x0004);	/* Force Port 4 link 100-Full */
		
	    /* P4SPD = 100MPS and P5SPD = P6SPD = 1 --> 100MPS */
	    ifx_sw_write(TANTOS_REG_RGMIICR, 0x777);
	    
		ifx_sw_max_port_num = 6;	
		for(i = 0; i < ifx_sw_max_port_num; i++) {
           /* state: 0 -> link, 1 -> 10/100, 2 -> Half/Full, 3 -> Flow control*/
           a0 = tantos_get_portsts(i,0);
           a1 = tantos_get_portsts(i,1); 
           a2 = tantos_get_portsts(i,2);
        }
		tantos_reset();
		
		return 1;
	}
	
	return 0;
}






