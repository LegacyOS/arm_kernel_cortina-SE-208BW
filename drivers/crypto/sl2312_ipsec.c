/*-------------------------------------------------------------
 * sl2312_ipsec.c
 * Description: the new sl2312_ipsec.c with flags that set to use 
 *				1 of the following 4 modes: Default, Interrupt, 
 *				Tasklet, and NAPI.
 *				1) Default mode is aka polling, which is tested working, 
 *				but performance is not good.  It is also included in 
 *				Tasklet and NAPI mode.
 *				2) Interrupt mode is not maintained.
 *				*3) Tasklet mode is the most used, the best performed, and 
 *				the standard one.  The methodology for this one is 
 *				when RX interrupt is seen, it will mask out the RX 
 *				interrupt, schedule a RX event with tasklet. Once RX event 
 *				is done, it will re-enable the RX interrupt.
 *				4) NAPI mode is similar to Tasklet mode.  However, instead 
 *				of using tasklet, it creates a virtual network device and 
 *				runs on RX event on a net device's NAPI poll function.
 *
 *				*CONFIG_CRYPTO_BATCH will enable batch implementation
 *				which will send a batch of packet to the crypto engine
 *				at once and read a batch from crypto engine at once.
 *				This is also recommended to turn it on.
 * Modified: Wen Hsu, September 2008.
 *-----------------------------------------------------------*/
//#define CONFIG_SL2312_IPSEC_INTERRUPT
#define CONFIG_SL2312_IPSEC_TASKLET		// recommend
//#define CONFIG_SL2312_IPSEC_NAPI
#define CONFIG_CRYPTO_BATCH		// recommend, to enable the batch implementation

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/compiler.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/completion.h>
#include <asm/hardware.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/arch/irqs.h>
#include <asm/arch/sl2312.h>
#include <asm/arch/sl2312_ipsec.h>
#include <linux/dma-mapping.h>
#include <linux/sysctl_storlink.h>
#ifdef CONFIG_SL2312_IPSEC_TASKLET
#include <asm/irq.h>
#endif
#ifdef CONFIG_SL2312_IPSEC_NAPI
#include <asm/irq.h>
#include <linux/netdevice.h>
#endif

#ifdef CONFIG_SL351X_IPSEC
#include <asm/arch/sl351x_ipsec.h>
#endif

/*****************************
 *      const definition     *
 *****************************/
 
/* define TX/RX descriptor parameter */
#define     TX_BUF_TOT_LEN		(TX_BUF_SIZE * IPSEC_TX_DESC_NUM)
#define     RX_BUF_TOT_LEN		(RX_BUF_SIZE * IPSEC_RX_DESC_NUM)

/* define EMAC base address */
#define     IPSEC_PHYSICAL_BASE_ADDR	(SL2312_SECURITY_BASE)  //0x51000000
#define     IPSEC_BASE_ADDR			    (IO_ADDRESS(IPSEC_PHYSICAL_BASE_ADDR))
#define     IPSEC_GLOBAL_BASE_ADDR      (IO_ADDRESS(SL2312_GLOBAL_BASE)) 

//#define     IPSEC_IRQ		        0x04

#define     IPSEC_MAX_PACKET_LEN    32768//2048 + 256

#define     APPEND_MODE             0 
#define     CHECK_MODE              1

#define		DEFAULT_MODE			0
#define		BATCH_MODE				1

#define     MIN_HW_CHECKSUM_LEN     60

/* memory management utility */
#define DMA_MALLOC(size,handle)		pci_alloc_consistent(NULL,size,handle)	
#define DMA_MFREE(mem,size,handle)	pci_free_consistent(NULL,size,mem,handle)

#define ipsec_read_reg(offset)              (readl(IPSEC_BASE_ADDR + offset))
//#define ipsec_write_reg(offset,data,mask)    writel( (ipsec_read_reg(offset)&(~mask)) |(data&mask),(IPSEC_BASE_ADDR+offset))
#define ipsec_write_reg2(offset,data)       writel(data,(unsigned int *)(IPSEC_BASE_ADDR + offset))

/* define owner bit */
enum OWN_BIT {
	CPU = 0,
	DMA	= 1
};   

typedef struct IPSEC_PACKET_S qhead;

/*****************************
 * Global Variable Declare   *
 *****************************/
struct IPSEC_TEST_RESULT_S
{
	unsigned int auth_cmp_result;
	unsigned int sw_pkt_len;
	unsigned char sw_cipher[IPSEC_MAX_PACKET_LEN];
	unsigned int hw_pkt_len;
	unsigned char hw_cipher[IPSEC_MAX_PACKET_LEN];
} ipsec_result;

static IPSEC_CIPHER_CBC_T cbc;
static IPSEC_CIPHER_ECB_T ecb;
static IPSEC_AUTH_T auth;
static IPSEC_AUTH_T fcs_auth;
static IPSEC_HMAC_AUTH_T auth_hmac;
static IPSEC_CBC_AUTH_T cbc_auth;
static IPSEC_ECB_AUTH_T ecb_auth;
static IPSEC_CBC_AUTH_HMAC_T cbc_auth_hmac;
static IPSEC_ECB_AUTH_HMAC_T ecb_auth_hmac;

static IPSEC_DESCRIPTOR_T *rx_desc_index[IPSEC_RX_DESC_NUM];
static unsigned int rx_index = 0;
static unsigned int pid = 0;
static unsigned int last_rx_pid = 255;

static struct IPSEC_PACKET_S fcs_op; /* for tcp/ip checksum */
//static unsigned char out_packet2[2048];  /* for tcp/ip checksum */

volatile static IPSEC_T *tp = NULL;
static unsigned int tx_desc_virtual_base = 0;
static unsigned int rx_desc_virtual_base = 0;
static qhead *ipsec_queue,dummy[3];
static spinlock_t ipsec_irq_lock;
static spinlock_t ipsec_q_lock;
static spinlock_t ipsec_polling_lock;
static spinlock_t ipsec_tx_lock;
static spinlock_t ipsec_pid_lock;

//static unsigned int fcs_data_len = 0;
static unsigned int wep_crc_ok = 0;
static unsigned int tkip_mic_ok = 0;
static unsigned int ccmp_mic_ok = 0;

#ifdef CONFIG_SL2312_IPSEC_TASKLET
static IPSEC_TASKLET_INFO_T ipsec_tasklet_data;
static unsigned int flag_tasklet_scheduled = 0;
static unsigned int rx_poll_num = 10;
#endif

#ifdef CONFIG_SL2312_IPSEC_NAPI
static struct net_device *crypto_rx_dev = NULL;
static unsigned int flag_tasklet_scheduled = 0;
static unsigned int rx_poll_num = 10;
#endif

#if defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_INTERRUPT) || defined(CONFIG_SL2312_IPSEC_NAPI)
static unsigned int polling_flag = 0;
static int polling_process_id = -1;
static int polling_loop = 0;
#endif

#ifdef CONFIG_CRYPTO_BATCH
static IPSEC_DESCRIPTOR_T *first_batch_tx_desc;
extern struct IPSEC_PACKET_S CRYPTO_QUEUE[CRYPTO_QUEUE_SIZE];
static unsigned int tx_desc_count = 0;

typedef IPSEC_CBC_AUTH_HMAC_T IPSEC_SUPER_T;
static IPSEC_SUPER_T IPSEC_SUPER_T_list[CRYPTO_QUEUE_SIZE];
#endif

/*************************************
 *     Function Prototype            *
 *************************************/
static void ipsec_sw_reset(void);
static void ipsec_put_queue(qhead *q, struct IPSEC_PACKET_S *item);
static struct IPSEC_PACKET_S *ipsec_get_queue(qhead *q);
static void start_dma(void);
static int ipsec_hw_handle(unsigned char *ctrl_pkt, int ctrl_len, 
			struct scatterlist *data_pkt, int data_len, unsigned int tqflag);
static void ipsec_hw_start(void);
static void ipsec_complete_tx_packet(void);
static int ipsec_tx_packet(struct scatterlist *packet, 
			int len, unsigned int tqflag);
static int ipsec_rx_packet(unsigned int mode);
static int ipsec_interrupt_polling(void);
static void ipsec_byte_change(unsigned char *in_key, unsigned int in_len, 
			unsigned char *out_key, unsigned int *out_len);
static void ipsec_fcs_init(void);
static int ipsec_auth_and_cipher(struct IPSEC_PACKET_S *op, int mode, 
			int count, int cur_loc);
static int desc_free_space(void);
static void crypto_enable_interrupt(void);
static void crypto_disable_interrupt(void);
static void crypto_hw_stop(void);
static void crypto_release_buffers(void);
static int reset_crypto_engine(void);
static int __init ipsec_initial(void);
static void __exit ipsec_cleanup (void);

#ifdef CONFIG_SL2312_IPSEC_INTERRUPT
static irqreturn_t ipsec_interrupt(int irq, void *dev_id, struct pt_regs *regs);
#endif

#ifdef CONFIG_SL2312_IPSEC_TASKLET
static irqreturn_t ipsec_interrupt(int irq, void *dev_id, struct pt_regs *regs);
static int ipsec_tasklet_func(unsigned long data);
#endif

#ifdef CONFIG_SL2312_IPSEC_NAPI
static irqreturn_t ipsec_interrupt(int irq, void *dev_id, struct pt_regs *regs);
static inline int ipsec_rx_poll(struct net_device *dev, int *budget);
#endif

#ifdef CONFIG_CRYPTO_BATCH
static void process_ipsec_recursive(struct IPSEC_PACKET_S *crypto_queue, 
			int count, int current_count, int loc, int queue_size);
//static int ipsec_hw_handle_vpn(volatile unsigned char *ctrl_pkt, int ctrl_len, 
//			volatile unsigned char *data_pkt, int data_len, unsigned int tqflag, 
//			int count);
static int ipsec_hw_handle_vpn(unsigned char *ctrl_pkt, int ctrl_len, 
			unsigned char *data_pkt, int data_len, unsigned int tqflag, int count);
static int ipsec_fill_desc(IPSEC_DESCRIPTOR_T *desc, unsigned char * data, 
			int len, unsigned int flag, int ownership);
#endif

#ifdef CONFIG_SL2312_HW_CHECKSUM
unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum);
unsigned int csum_partial_copy_nocheck(const char *src, char *dst, 
			int len, int sum);
int ipsec_checksum_test(void);
#endif

/************************************************/
/*                 function body                */
/************************************************/
__inline__ unsigned int ipsec_get_time(void)
{
	return (readl(0xf2300000));
}

static void ipsec_write_reg(unsigned int offset, unsigned int data, unsigned int bit_mask)
{
	volatile unsigned int reg_val;
	unsigned int *addr;

	reg_val = ( ipsec_read_reg(offset) & (~bit_mask) ) | (data & bit_mask);
	addr = (unsigned int *)(IPSEC_BASE_ADDR + offset);
	writel(reg_val,addr);
	return;
}	

static void ipsec_sw_reset(void)
{
	unsigned int reg_val;

	reg_val = readl(IPSEC_GLOBAL_BASE_ADDR + GLOBAL_RESET_REG) | 0x00000010;
	writel(reg_val,IPSEC_GLOBAL_BASE_ADDR + GLOBAL_RESET_REG);
	udelay(100);
	return;
}

static void ipsec_put_queue(qhead *q, struct IPSEC_PACKET_S *i)
{
	unsigned long flags;

	spin_lock_irqsave(&ipsec_q_lock, flags);

	i->next = q->next;
	i->prev = q;
	q->next->prev = i;
	q->next = i;

	spin_unlock_irqrestore(&ipsec_q_lock, flags);
	return;
}

static struct IPSEC_PACKET_S * ipsec_get_queue(qhead *q)
{
	struct IPSEC_PACKET_S *i;
	unsigned long flags;

	if (q->prev == q) {
		return NULL;
	}

	spin_lock_irqsave(&ipsec_q_lock, flags);
	i = q->prev;
	q->prev = i->prev;
	i->prev->next = i->next;

	spin_unlock_irqrestore(&ipsec_q_lock, flags);

	i->next = i->prev = NULL;
	return i;
}

static void start_dma(void)
{
	IPSEC_TXDMA_FIRST_DESC_T txdma_busy;
	unsigned int reg_val;

	/* if TX DMA process is stop->ed , restart it */
	txdma_busy.bits32 = ipsec_read_reg(IPSEC_TXDMA_FIRST_DESC);
	if (txdma_busy.bits.td_busy == 0) {
		/* restart Rx DMA process */
		reg_val = ipsec_read_reg(IPSEC_RXDMA_CTRL);
		reg_val |= (0x03<<30);
		ipsec_write_reg2(IPSEC_RXDMA_CTRL, reg_val);

		/* restart Tx DMA process */
		reg_val = ipsec_read_reg(IPSEC_TXDMA_CTRL);
		reg_val |= (0x03<<30);
		ipsec_write_reg2(IPSEC_TXDMA_CTRL, reg_val);
	}
}

/*****************************************************************************
 * Function    : ipsec_crypto_hw_process
 * Description : This function processes H/W authentication and cipher.
 *       Input : op_info - the authentication and cipher information for IPSec 
 *       		 module.
 *      Output : none.
 *      Return : 0 - success, others - failure.
 *****************************************************************************/
int ipsec_crypto_hw_process(struct IPSEC_PACKET_S *op_info)
{
	volatile IPSEC_DESCRIPTOR_T *rx_desc;
	unsigned long flags, flags2, flags3;
	volatile IPSEC_RXDMA_CTRL_T	rxdma_ctrl;
	unsigned int rxdma_desc;
	int available_space = desc_free_space();
	int result = 0;

	if (op_info == NULL) {
		//printk("%s::op_info is null\n", __func__);
		return -1;
	}

	/* check if there is an available space for this crypto packet */
	if (available_space < 1) {
		//printk("%s::tx queue is full a\n", __func__);
		return -1;
	}

	/* threshold test.. should we have it? */
//	if (available_space < ((IPSEC_RX_DESC_NUM >> 2) + (IPSEC_RX_DESC_NUM >> 1))) {
//	if (available_space < (IPSEC_RX_DESC_NUM >> 1)) {
	if (available_space < (IPSEC_RX_DESC_NUM)) {
		//printk("%s::crypto engine hits threshold\n",__func__);
		return -1;
	}

	if (op_info->pkt_len >= 65500) {
		printk("%s::input pkt is bigger than 65500\n", __func__);
		return -1;
	}

	spin_lock_irqsave(&ipsec_pid_lock, flags3);
	op_info->process_id = (pid++) % 256;
	spin_unlock_irqrestore(&ipsec_pid_lock, flags3);

#if defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_INTERRUPT) || defined(CONFIG_SL2312_IPSEC_NAPI)
	/* first turn off the interrupt, such that there won't be conflict */
	spin_lock_irqsave(&ipsec_irq_lock, flags2);
	rxdma_ctrl.bits32 = ipsec_read_reg(IPSEC_RXDMA_CTRL);
	rxdma_ctrl.bits.rd_eof_en = 0;
	ipsec_write_reg2(IPSEC_RXDMA_CTRL, rxdma_ctrl.bits32);
	spin_unlock_irqrestore(&ipsec_irq_lock, flags2);

	/* 2nd, turn on the polling flag. */
	spin_lock_irqsave(&ipsec_polling_lock, flags);
	polling_flag = 1;
	polling_loop = 0;
//	if (polling_process_id != -1)
//		printk("current polling_process_id %d will be updated to %d, last_rx_pid = %d\n",
//			polling_process_id, op_info->process_id, last_rx_pid);
	polling_process_id = (int)(op_info->process_id);
	spin_unlock_irqrestore(&ipsec_polling_lock, flags);
#endif

#if (ZERO_COPY==1)
	if (op_info->out_packet2 != NULL) {
		/* get rx descriptor for this operation */
		rx_desc = rx_desc_index[rx_index%IPSEC_RX_DESC_NUM];
		/* set receive buffer address for this operation */
//		consistent_sync(op_info->out_packet2,op_info->pkt_len,PCI_DMA_TODEVICE);
		rx_desc->buf_adr = __pa(op_info->out_packet2); //virt_to_phys(op_info->out_packet2);
//		ipsec_write_reg(IPSEC_RXDMA_BUF_ADDR,rx_desc->buf_adr,0xffffffff);
		rxdma_desc = (ipsec_read_reg(IPSEC_RXDMA_CURR_DESC) & 0xfffffff0) 
						+ rx_desc_virtual_base;
		if ((unsigned int)rx_desc == (unsigned int)rxdma_desc) {
			ipsec_write_reg2(IPSEC_RXDMA_BUF_ADDR, rx_desc->buf_adr);
			consistent_sync((void *)rx_desc,sizeof(IPSEC_DESCRIPTOR_T), PCI_DMA_TODEVICE);
		}

		if (op_info->out_buffer_len != 0)
			rx_desc->frame_ctrl.bits.buffer_size = op_info->out_buffer_len;
		else
			rx_desc->frame_ctrl.bits.buffer_size = RX_BUF_SIZE;

		rx_index++;
	}

	if (op_info->out_packet != NULL) {
		int len = 0;
		int i = 0;
		unsigned char* pkt_ptr;

		while (len < op_info->out_buffer_len) {
			rx_desc = rx_desc_index[rx_index%IPSEC_RX_DESC_NUM];
			pkt_ptr = kmap(op_info->out_packet[i].page) + op_info->out_packet[i].offset;
			consistent_sync(pkt_ptr, op_info->out_packet[i].length, PCI_DMA_TODEVICE);
			rx_desc->buf_adr = __pa(pkt_ptr);
			rxdma_desc = (ipsec_read_reg(IPSEC_RXDMA_CURR_DESC) & 0xfffffff0) 
					+ rx_desc_virtual_base;
			if ((unsigned int)rx_desc == (unsigned int)rxdma_desc) {
				ipsec_write_reg2(IPSEC_RXDMA_BUF_ADDR, rx_desc->buf_adr);
				consistent_sync((void *)rx_desc, sizeof(IPSEC_DESCRIPTOR_T), PCI_DMA_TODEVICE);
			}

//			if (op_info->out_packet[i].length != 0)
//				rx_desc->frame_ctrl.bits.buffer_size = op_info->out_packet[i].length;
//			else
//				rx_desc->frame_ctrl.bits.buffer_size = RX_BUF_SIZE;

			len += op_info->out_packet[i].length;
			rx_index++;
			i++;
		}
	}
#endif

	ipsec_put_queue(ipsec_queue, op_info);
	result = ipsec_auth_and_cipher(op_info, 0, 0, 0);

	return result;
}

/*===========================================================================*/
/*    Hardware authentication & encrypt & decrypt function    */ 
/*===========================================================================*/
static int ipsec_hw_handle(unsigned char *ctrl_pkt, int ctrl_len, 
				struct scatterlist *data_pkt, int data_len, unsigned int tqflag)
{
	struct scatterlist sg[1];
	unsigned long flags;
	unsigned int ipsec_status;
	unsigned int i;
	int result = 0;

//	disable_irq(IRQ_IPSEC);
	sg[0].page = virt_to_page(ctrl_pkt);
	sg[0].offset = offset_in_page(ctrl_pkt);
	sg[0].length = ctrl_len;
//	ipsec_tx_packet(ctrl_pkt,ctrl_len,tqflag);
	spin_lock_irqsave(&ipsec_tx_lock, flags);
	ipsec_tx_packet(sg,ctrl_len, tqflag);
	ipsec_tx_packet(data_pkt, data_len, 0);
	start_dma();
	spin_unlock_irqrestore(&ipsec_tx_lock, flags);
#if 1
#if defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_NAPI)
	if (flag_tasklet_scheduled == 0)
#endif
	{
		for (i=0; i<5000; i++)
		{
			ipsec_status = ipsec_read_reg(IPSEC_STATUS_REG);
			/* check IPSec status register */
			if ((ipsec_status & 0x00000fff)==0) {
				break;
			}
		}

		if ((ipsec_status & 0x00000fff) != 0) {
			printk("\n%s:IPSEC Control Packet Error !!!(%08x)\n", __func__, 
					ipsec_status);
			ipsec_write_reg2(IPSEC_STATUS_REG,ipsec_status);

			/* reset the crypto engine to erase the error. */
			reset_crypto_engine();
			return -1;
		}
	}
#endif
//	enable_irq(IRQ_IPSEC);

#if !defined(CONFIG_SL2312_IPSEC_INTERRUPT) && !defined(CONFIG_SL2312_IPSEC_TASKLET) && !defined(CONFIG_SL2312_IPSEC_NAPI)
	result = ipsec_interrupt_polling();
//	if (result == 0) {
//		printk("ipsec_interrupt_polling: ok\n");
//	}
//	else
//		printk("%s : polling\n",__func__);
#else
	if (polling_flag == 1) {
		result = ipsec_interrupt_polling();
//		if(result == 0)
//		{
//			printk("ipsec_interrupt_polling: ok\n");
//		}
//		else
//			printk("%s::polling\n",__func__);
	}
#endif
	return result;
}

static int ipsec_buf_init(void)
{
	dma_addr_t tx_first_desc_dma=0;
	dma_addr_t rx_first_desc_dma=0;
//	dma_addr_t tx_first_buf_dma=0;
//	dma_addr_t rx_first_buf_dma=0;
	int i;

	if (tp == NULL) {
		tp = kmalloc(sizeof(IPSEC_T), GFP_ATOMIC);
		if (tp == NULL)
		{
			printk("memory allocation fail !\n");
		}
	}
	
#if (ZERO_COPY == 0)
	/* allocates TX/RX DMA packet buffer */
	/* tx_buf_virtual:virtual address  tp.tx_bufs_dma:physical address */
	tp->tx_bufs = DMA_MALLOC(TX_BUF_TOT_LEN, (dma_addr_t *)&tp->tx_bufs_dma);
	tx_buf_virtual_base = (unsigned int)tp->tx_bufs - (unsigned int)tp->tx_bufs_dma;
	memset(tp->tx_bufs, 0x00, TX_BUF_TOT_LEN);
	tx_first_buf_dma = tp->tx_bufs_dma;		/* physical address of tx buffer */
	tp->rx_bufs = DMA_MALLOC(RX_BUF_TOT_LEN, (dma_addr_t *)&tp->rx_bufs_dma);
	rx_buf_virtual_base = (unsigned int)tp->rx_bufs - (unsigned int)tp->rx_bufs_dma;
	memset(tp->rx_bufs, 0x00, RX_BUF_TOT_LEN);
	rx_first_buf_dma = tp->rx_bufs_dma;		/* physical address of rx buffer */
	printk("ipsec tx_buf = %08x\n", (unsigned int)tp->tx_bufs);
	printk("ipsec rx_buf = %08x\n", (unsigned int)tp->rx_bufs);
	printk("ipsec tx_buf_dma = %08x\n", tp->tx_bufs_dma);
	printk("ipsec rx_buf_dma = %08x\n", tp->rx_bufs_dma);
#endif

	/* allocates TX/RX descriptors */
	tp->tx_desc = DMA_MALLOC(IPSEC_TX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
					(dma_addr_t *)&tp->tx_desc_dma);
	tx_desc_virtual_base = (unsigned int)tp->tx_desc - (unsigned int)tp->tx_desc_dma;
	memset(tp->tx_desc, 0x00, IPSEC_TX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T));
	tp->rx_desc = DMA_MALLOC(IPSEC_RX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
					(dma_addr_t *)&tp->rx_desc_dma);
	rx_desc_virtual_base = (unsigned int)tp->rx_desc - (unsigned int)tp->rx_desc_dma;
	memset(tp->rx_desc, 0x00, IPSEC_RX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T));

#if (ZERO_COPY == 0)
	if (tp->tx_bufs==0x00 || tp->rx_bufs==0x00 || tp->tx_desc==0x00 || tp->rx_desc==0x00) 
#else
	if (tp->tx_desc==0x00 || tp->rx_desc==0x00) 
#endif
	{
#if (ZERO_COPY == 0)
		if (tp->tx_bufs)
			DMA_MFREE(tp->tx_bufs, TX_BUF_TOT_LEN, (unsigned int)tp->tx_bufs_dma);
		if (tp->rx_bufs)
			DMA_MFREE(tp->rx_bufs, RX_BUF_TOT_LEN, (unsigned int)tp->rx_bufs_dma);
#endif
		if (tp->tx_desc)
			DMA_MFREE(tp->tx_desc, IPSEC_TX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
							(unsigned int)tp->tx_desc_dma);
		if (tp->rx_desc)
			DMA_MFREE(tp->rx_desc, IPSEC_RX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
							(unsigned int)tp->rx_desc_dma);
		return -ENOMEM;
	}
	
	/* TX descriptors initial */
	tp->tx_cur_desc = tp->tx_desc;          /* virtual address */
	tp->tx_finished_desc = tp->tx_desc;     /* virtual address */
	tx_first_desc_dma = tp->tx_desc_dma;    /* physical address */
	for (i = 1; i < IPSEC_TX_DESC_NUM; i++) {
		tp->tx_desc->frame_ctrl.bits.own = CPU; /* set owner to CPU */
		/* set tx buffer size for descriptor */
		tp->tx_desc->frame_ctrl.bits.buffer_size = TX_BUF_SIZE; 
#if (ZERO_COPY == 0)
		tp->tx_desc->buf_adr = tp->tx_bufs_dma; /* set data buffer address */
		/* point to next buffer address */
		tp->tx_bufs_dma = tp->tx_bufs_dma + TX_BUF_SIZE;
#endif
		/* next tx descriptor DMA address */
		tp->tx_desc_dma = tp->tx_desc_dma + sizeof(IPSEC_DESCRIPTOR_T);
		tp->tx_desc->next_desc.next_descriptor = tp->tx_desc_dma | 0x0000000b;
		tp->tx_desc = &tp->tx_desc[1] ; /* next tx descriptor virtual address */
	}
	/* the last descriptor will point back to first descriptor */
	tp->tx_desc->frame_ctrl.bits.own = CPU;
	tp->tx_desc->frame_ctrl.bits.buffer_size = TX_BUF_SIZE;
#if (ZERO_COPY == 0)
	tp->tx_desc->buf_adr = (unsigned int)tp->tx_bufs_dma;
#endif
	tp->tx_desc->next_desc.next_descriptor = tx_first_desc_dma | 0x0000000b;
	tp->tx_desc = tp->tx_cur_desc;
	tp->tx_desc_dma = tx_first_desc_dma;
#if (ZERO_COPY == 0)
	tp->tx_bufs_dma = tx_first_buf_dma;
#endif
	
	/* RX descriptors initial */
	tp->rx_cur_desc = tp->rx_desc;
	rx_first_desc_dma = tp->rx_desc_dma;
	rx_desc_index[0] = tp->rx_desc;
	for (i = 1; i < IPSEC_RX_DESC_NUM; i++) {
		tp->rx_desc->frame_ctrl.bits.own = DMA;  /* set owner bit to DMA */
		/* set rx buffer size for descriptor */
		tp->rx_desc->frame_ctrl.bits.buffer_size = RX_BUF_SIZE;
#if (ZERO_COPY == 0)
		tp->rx_desc->buf_adr = tp->rx_bufs_dma;   /* set data buffer address */
		/* point to next buffer address */
		tp->rx_bufs_dma = tp->rx_bufs_dma + RX_BUF_SIZE;
#endif
		/* next rx descriptor DMA address */
		tp->rx_desc_dma = tp->rx_desc_dma + sizeof(IPSEC_DESCRIPTOR_T);
		tp->rx_desc->next_desc.next_descriptor = tp->rx_desc_dma | 0x0000000b;
		tp->rx_desc = &tp->rx_desc[1]; /* next rx descriptor virtual address */
	    rx_desc_index[i] = tp->rx_desc;
	}
	/* the last descriptor will point back to first descriptor */
	tp->rx_desc->frame_ctrl.bits.own = DMA;
	tp->rx_desc->frame_ctrl.bits.buffer_size = RX_BUF_SIZE;
#if (ZERO_COPY == 0)
	tp->rx_desc->buf_adr = tp->rx_bufs_dma;
#endif
	tp->rx_desc->next_desc.next_descriptor = rx_first_desc_dma | 0x0000000b;
	tp->rx_desc = tp->rx_cur_desc;
	tp->rx_desc_dma = rx_first_desc_dma;
#if (ZERO_COPY == 0)
	tp->rx_bufs_dma = rx_first_buf_dma;
#endif
#ifdef CONFIG_CRYPTO_BATCH
	memset(IPSEC_SUPER_T_list,0x00,CRYPTO_QUEUE_SIZE*sizeof(IPSEC_SUPER_T));
#endif
	printk("ipsec tx_desc = %08x\n",(unsigned int)tp->tx_desc);
	printk("ipsec rx_desc = %08x\n",(unsigned int)tp->rx_desc);
	printk("ipsec tx_desc_dma = %08x\n",tp->tx_desc_dma);
	printk("ipsec rx_desc_dma = %08x\n",tp->rx_desc_dma);
	return (0);	
}

static void ipsec_hw_start(void)
{
	volatile IPSEC_TXDMA_CURR_DESC_T tx_desc;
	volatile IPSEC_RXDMA_CURR_DESC_T rx_desc;
	volatile IPSEC_TXDMA_CTRL_T txdma_ctrl, txdma_ctrl_mask;
	volatile IPSEC_RXDMA_CTRL_T rxdma_ctrl, rxdma_ctrl_mask;
	volatile IPSEC_DMA_STATUS_T dma_status, dma_status_mask;

	ipsec_sw_reset();
	ipsec_write_reg(0xff40,0x00000044,0xffffffff);

	/* program TxDMA Current Descriptor Address register for first descriptor */
	tx_desc.bits32 = (unsigned int)(tp->tx_desc_dma);
	tx_desc.bits.eofie = 0;			/* turn off by Wen */
	tx_desc.bits.dec = 0;
	tx_desc.bits.sof_eof = 0x03;
	ipsec_write_reg(IPSEC_TXDMA_CURR_DESC, tx_desc.bits32, 0xffffffff);
	
	/* program RxDMA Current Descriptor Address register for first descriptor */
	rx_desc.bits32 = (unsigned int)(tp->rx_desc_dma);
	rx_desc.bits.eofie = 1;			/* turn off by Wen */
	rx_desc.bits.dec = 0;
	rx_desc.bits.sof_eof = 0x03;
	ipsec_write_reg(IPSEC_RXDMA_CURR_DESC, rx_desc.bits32, 0xffffffff);
		
	/* enable IPSEC interrupt & disable loopback */
//	dma_status.bits32 = (unsigned int)(tp->tx_desc_dma) - 6;
	dma_status.bits32 = 0;
	dma_status.bits.loop_back = 0;
	dma_status_mask.bits32 = 0xffffffff;
	dma_status_mask.bits.loop_back = 1;
	ipsec_write_reg(IPSEC_DMA_STATUS, dma_status.bits32, dma_status_mask.bits32);
	
	txdma_ctrl.bits32 = 0;
	txdma_ctrl.bits.td_start = 0;    /* start DMA transfer */
	txdma_ctrl.bits.td_continue = 0; /* continue DMA operation */
	txdma_ctrl.bits.td_chain_mode = 1; /* chain mode */
	txdma_ctrl.bits.td_prot = 0;
	txdma_ctrl.bits.td_burst_size = 2;
	txdma_ctrl.bits.td_bus = 0;
	txdma_ctrl.bits.td_endian = 0;				/* turn off by Wen */
	txdma_ctrl.bits.td_finish_en = 0;			/* turn off by Wen */
	txdma_ctrl.bits.td_fail_en = 0;				/* turn off by Wen */
	txdma_ctrl.bits.td_perr_en = 0;				/* turn off by Wen */
	txdma_ctrl.bits.td_eod_en = 0;				/* turn off by Wen */
	txdma_ctrl.bits.td_eof_en = 0;				/* turn off by Wen */
	txdma_ctrl_mask.bits32 = 0;
	txdma_ctrl_mask.bits.td_start = 1;    
	txdma_ctrl_mask.bits.td_continue = 1; 
	txdma_ctrl_mask.bits.td_chain_mode = 1;
	txdma_ctrl_mask.bits.td_prot = 0xf;
	txdma_ctrl_mask.bits.td_burst_size = 3;
	txdma_ctrl_mask.bits.td_bus = 1;
	txdma_ctrl_mask.bits.td_endian = 1;
	txdma_ctrl_mask.bits.td_finish_en = 0;		/* turn off by Wen */
	txdma_ctrl_mask.bits.td_fail_en = 0;		/* turn off by Wen */
	txdma_ctrl_mask.bits.td_perr_en = 0;		/* turn off by Wen */
	txdma_ctrl_mask.bits.td_eod_en = 0;			/* turn off by Wen */
	txdma_ctrl_mask.bits.td_eof_en = 0;			/* turn off by Wen */
	ipsec_write_reg(IPSEC_TXDMA_CTRL, txdma_ctrl.bits32, txdma_ctrl_mask.bits32);

	rxdma_ctrl.bits32 = 0;
	rxdma_ctrl.bits.rd_start = 0;    /* start DMA transfer */
	rxdma_ctrl.bits.rd_continue = 0; /* continue DMA operation */
	rxdma_ctrl.bits.rd_chain_mode = 1;   /* chain mode */
	rxdma_ctrl.bits.rd_prot = 0;
	rxdma_ctrl.bits.rd_burst_size = 2;
	rxdma_ctrl.bits.rd_bus = 0;
	rxdma_ctrl.bits.rd_endian = 0;
	rxdma_ctrl.bits.rd_finish_en = 0;			/* turn off by Wen */
	rxdma_ctrl.bits.rd_fail_en = 0;				/* turn off by Wen */
	rxdma_ctrl.bits.rd_perr_en = 0;				/* turn off by Wen */
	rxdma_ctrl.bits.rd_eod_en = 0;				/* turn off by Wen */
	rxdma_ctrl.bits.rd_eof_en = 1;				/* turn off by Wen */
	rxdma_ctrl_mask.bits32 = 0;
	rxdma_ctrl_mask.bits.rd_start = 1;    
	rxdma_ctrl_mask.bits.rd_continue = 1; 
	rxdma_ctrl_mask.bits.rd_chain_mode = 1;
	rxdma_ctrl_mask.bits.rd_prot = 15;
	rxdma_ctrl_mask.bits.rd_burst_size = 3;
	rxdma_ctrl_mask.bits.rd_bus = 1;
	rxdma_ctrl_mask.bits.rd_endian = 1;
	rxdma_ctrl_mask.bits.rd_finish_en = 0;		/* turn off by Wen */
	rxdma_ctrl_mask.bits.rd_fail_en = 0;		/* turn off by Wen */
	rxdma_ctrl_mask.bits.rd_perr_en = 0;		/* turn off by Wen */
	rxdma_ctrl_mask.bits.rd_eod_en = 0;			/* turn off by Wen */
	rxdma_ctrl_mask.bits.rd_eof_en = 1;			/* turn off by Wen */
	ipsec_write_reg(IPSEC_RXDMA_CTRL, rxdma_ctrl.bits32, rxdma_ctrl_mask.bits32);
	
    return;	
}	

static void ipsec_complete_tx_packet(void)
{
	IPSEC_DESCRIPTOR_T *tx_complete_desc;
	IPSEC_DESCRIPTOR_T *tx_finished_desc = tp->tx_finished_desc;
	unsigned int desc_cnt;
	unsigned int i;

	tx_complete_desc = (IPSEC_DESCRIPTOR_T *)(
					(ipsec_read_reg(IPSEC_TXDMA_CURR_DESC) & 0xfffffff0)
					+tx_desc_virtual_base);

//	printk("%s::complete TX\n",__func__);
	/* check tx status and accumulate tx statistics */
	for (;;) {
		if (tx_finished_desc->frame_ctrl.bits.own == CPU) {
			if ( (tx_finished_desc->frame_ctrl.bits.derr) ||
					(tx_finished_desc->frame_ctrl.bits.perr) ) {
				printk("Descriptor Processing Error !!!\n");
			}

			desc_cnt = tx_finished_desc->frame_ctrl.bits.desc_count;

//			if (desc_cnt > 1)
//				printk("%s::%d descriptor counts\n",__func__,desc_cnt);
			for (i=1; i<desc_cnt; i++) { /* multi_descriptor */
				tx_finished_desc = (IPSEC_DESCRIPTOR_T *)(
								(tx_finished_desc->next_desc.next_descriptor 
								 	& 0xfffffff0)+tx_desc_virtual_base);
				tx_finished_desc->frame_ctrl.bits.own = CPU;
			}
			tx_finished_desc = (IPSEC_DESCRIPTOR_T *)(
							(tx_finished_desc->next_desc.next_descriptor 
							 	& 0xfffffff0)+tx_desc_virtual_base);
			if (tx_finished_desc == tx_complete_desc) {
				break;
			}
		} else {
			break;
		}
	}
	tp->tx_finished_desc = tx_finished_desc;
}

static int ipsec_tx_packet(struct scatterlist *packet, int len, unsigned int tqflag)
{
	IPSEC_DESCRIPTOR_T *tx_desc = tp->tx_cur_desc;
//	IPSEC_DESCRIPTOR_T *return_desc = tx_desc;
//	IPSEC_TXDMA_CTRL_T tx_ctrl,tx_ctrl_mask;
//	IPSEC_RXDMA_CTRL_T rx_ctrl,rx_ctrl_mask;
	unsigned int desc_cnt;
	unsigned int i, tmp_len;
	unsigned int sof;
	unsigned int last_desc_byte_cnt;
	unsigned char *pkt_ptr;

	if (tx_desc->frame_ctrl.bits.own != CPU) {
		printk("\nipsec_tx_packet : Current Tx Descriptor is in use!\n");
		ipsec_read_reg(0x0000);
	}
//#if (ZERO_COPY == 0)
//    pkt_ptr = packet;
//#else
//    pkt_ptr = kmap(packet[0].page) + packet[0].offset;
//		//consistent_sync(pkt_ptr,packet[0].length,PCI_DMA_TODEVICE);
//    pkt_ptr = (unsigned char *)virt_to_phys(pkt_ptr);  //__pa(packet);   
//	ipsec_write_reg2(IPSEC_TXDMA_BUF_ADDR,(unsigned int)pkt_ptr);
////	
////    consistent_sync(packet,len,PCI_DMA_TODEVICE);
////    pkt_ptr = (unsigned char *)virt_to_phys(packet);  //__pa(packet);
//////	ipsec_write_reg(IPSEC_TXDMA_BUF_ADDR,(unsigned int)pkt_ptr,0xffffffff);
////	ipsec_write_reg2(IPSEC_TXDMA_BUF_ADDR,(unsigned int)pkt_ptr);
//#endif
	sof = 0x02;		/* the first descriptor */
	desc_cnt = (len/TX_BUF_SIZE);
	last_desc_byte_cnt = len % TX_BUF_SIZE;
	//for (i=0; i<desc_cnt ;i++)
	tmp_len=0;i=0;
	while(tmp_len < len)
	{
//		printk("%s::filling in desc@%x\n",__func__,tx_desc);
		tx_desc->frame_ctrl.bits32 = 0;
		tx_desc->flag_status.bits32 = 0;
		
		/* descriptor byte count */
		tx_desc->frame_ctrl.bits.buffer_size = packet[i].length;
		/* set tqflag */
		tx_desc->flag_status.bits_tx_flag.tqflag = tqflag;

		pkt_ptr = kmap(packet[i].page) + packet[i].offset;
		consistent_sync(pkt_ptr,packet[i].length,PCI_DMA_TODEVICE);
		pkt_ptr = (unsigned char *)virt_to_phys(pkt_ptr);	// __pa(packet);

#if (ZERO_COPY == 0)
		/* copy packet to descriptor buffer address */
		memcpy((char *)(tx_desc->buf_adr+tx_buf_virtual_base), pkt_ptr, 
						packet[i].length);
		//pkt_ptr = &pkt_ptr[packet[i].length];
#else
		tx_desc->buf_adr = (unsigned int)pkt_ptr;
		//pkt_ptr = (unsigned char *)((unsigned int)pkt_ptr + packet[i].length);
#endif

		if ( (packet[i].length == len) && i==0 ) {
			sof = 0x03; /*only one descriptor*/
		}
		else if ( ((packet[i].length + tmp_len)== len) && (i != 0) ) {
			sof = 0x01;		/*the last descriptor*/
		}
		tx_desc->next_desc.bits.eofie = 1;
		tx_desc->next_desc.bits.dec = 0;
		tx_desc->next_desc.bits.sof_eof = sof;
		if (sof==0x02) {
			sof = 0x00;		/* the linking descriptor */
		}

		wmb();

		///middle
		tmp_len+=packet[i].length;
		i++;

//		printk("%s::tmp_len %d,len %d\n",__func__,tmp_len,len);
		/* set owner bit */
		tx_desc->frame_ctrl.bits.own = DMA;

		/* move to the next tx_desc */
		tx_desc = (IPSEC_DESCRIPTOR_T *)(
						(tx_desc->next_desc.next_descriptor & 0xfffffff0)
						+tx_desc_virtual_base);
		if (tx_desc->frame_ctrl.bits.own != CPU) {
			printk("\nipsec_tx_packet : Next Tx Descriptor is in use!\n");
		}
	};
	tp->tx_cur_desc = tx_desc;

//	consistent_sync(tx_desc,sizeof(IPSEC_DESCRIPTOR_T),DMA_BIDIRECTIONAL);

	return (0);
}

static int ipsec_rx_packet(unsigned int mode)
{
	IPSEC_DESCRIPTOR_T *rx_desc = tp->rx_cur_desc ;
	struct IPSEC_PACKET_S *op_info ;
//	unsigned char *pkt_ptr,*rx_buf_adr;
	unsigned int pkt_len;
//	unsigned int remain_pkt_len;
	unsigned int desc_count;
	unsigned int process_id=256;
	unsigned int auth_cmp_result;
	unsigned int checksum = 0;
//	unsigned int own; 
	unsigned int i;
	unsigned long flags;
	unsigned int count = 0;
	unsigned int failure = 0;

	while (((count < rx_poll_num) || (polling_flag == 1)) && (failure == 0)) {
		consistent_sync((void *)rx_desc,sizeof(IPSEC_DESCRIPTOR_T),PCI_DMA_FROMDEVICE);

		// debug message
		if (((unsigned int)rx_desc < 0xf0000000) 
				|| ((unsigned int)rx_desc > 0xffffffff)) {
			printk("%s::descriptor address is out of range? 0x%x\n",__func__,(unsigned int)rx_desc);
			failure = 1;
			goto rx_fail;
		}

		if (rx_desc == NULL) {
			printk("%s::WHAT IS GOING ON?!?! rx_desc == NULL?\n",__func__);
			failure = 1;
			goto rx_fail;
		}

//		spin_lock_irqsave(&ipsec_rx_lock, flags_a);
		if (rx_desc->frame_ctrl.bits.own == CPU) {
			if ((rx_desc->frame_ctrl.bits.derr == 1) 
					|| (rx_desc->frame_ctrl.bits.perr == 1)) {
				printk("%s::Descriptor Processing Error!!!\n",__func__);
				failure = 1;
				goto rx_fail;
			}
			/* total byte count in a frame*/
			pkt_len = rx_desc->flag_status.bits_rx_status.frame_count;
			/* get process ID from descriptor */
			process_id = rx_desc->flag_status.bits_rx_status.process_id;
			auth_cmp_result = rx_desc->flag_status.bits_rx_status.auth_result;
			wep_crc_ok = rx_desc->flag_status.bits_rx_status.wep_crc_ok;
			tkip_mic_ok = rx_desc->flag_status.bits_rx_status.tkip_mic_ok;
			ccmp_mic_ok = rx_desc->flag_status.bits_rx_status.ccmp_mic_ok;
			/* get descriptor count per frame */
			desc_count = rx_desc->frame_ctrl.bits.desc_count;
//			checksum = rx_desc->flag_status.bits_rx_status.checksum ;
//			checksum = checksum + rx_desc->frame_ctrl.bits.checksum * 256;
		} else {
			return count;
		}

		if (last_rx_pid == process_id) {
			printk("error!! last_rx_pid = %d, process_id = %d\n",last_rx_pid,process_id);
			failure = 1;
			goto rx_fail;
		}

		if (process_id != 256)
			last_rx_pid = process_id;

		/* get request information from queue */
		if ((op_info = ipsec_get_queue(ipsec_queue))!=NULL) {
			/* fill request result */
			op_info->out_pkt_len = pkt_len;
			op_info->auth_cmp_result = auth_cmp_result;
			op_info->checksum = checksum;
			op_info->status = CRYPTO_COMPLETE;

			/* problem might be caused by prefetch and cache. */
			mb();
			if (op_info->out_packet2 != NULL) {
				if (((unsigned int)op_info->out_packet2 < 0xc0000000) 
						|| ((unsigned int)op_info->out_packet2 >= 0xd0000000))
					printk("%s::op_info->out_packet2 address is out of range? 0x%x\n", 
								__func__, (unsigned int)op_info->out_packet2);
				consistent_sync((void *)op_info->out_packet2, pkt_len, 
							PCI_DMA_FROMDEVICE);

			}
			else if (op_info->out_packet != NULL) {
				unsigned char* pkt_ptr;
				unsigned int len = 0;
				i = 0;

				while (len < pkt_len) {
					pkt_ptr = kmap(op_info->out_packet[i].page) + op_info->out_packet[i].offset;
					consistent_sync((void *)pkt_ptr, op_info->out_packet[i].length, DMA_BIDIRECTIONAL);
					len += op_info->out_packet[i].length;
					i++;
				}
				if (i != desc_count) printk("%s::desc %d vs real count %d\n", 
											__func__, desc_count, i);
			}

			mb();

			if ((op_info->process_id != process_id)) {
				op_info->status = CRYPTO_MISMATCH;
				printk("%s::op_info->out_pkt_len =%d , op_info->pkt_len= %d\n", 
								__func__, op_info->out_pkt_len,op_info->pkt_len);
				printk("%s::Process ID: %d(queue) vs %d(rx desc) !\n", 
								__func__, op_info->process_id, process_id);
				failure = 1;
				goto rx_fail;
			}

#if defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_INTERRUPT) || defined(CONFIG_SL2312_IPSEC_NAPI)
			if ((polling_flag == 1 ) && ((int)process_id == polling_process_id)) {
				spin_lock_irqsave(&ipsec_polling_lock, flags);
				polling_flag = 0;
				polling_process_id = -1;
				spin_unlock_irqrestore(&ipsec_polling_lock, flags);
			}
#endif
		} else {
//			op_info->status = CRYPTO_QUEUE_EMPTY;
//			spin_unlock_irqrestore(&ipsec_rx_lock,flags_a);
			printk("ipsec_rx_packet:IPSec Queue Empty!\n");
			failure = 1;
			goto rx_fail;
		}
		count++;

#if (ZERO_COPY == 0)
		if (op_info > 0) {
			//pkt_ptr = &op_info->out_packet2[0];
			pkt_ptr = op_info->out_packet2;
		}

		remain_pkt_len = pkt_len;
#endif

		for (i=0; i<desc_count; i++) {
#if (ZERO_COPY == 0)
			if (op_info > 0) {
				rx_buf_adr = (char *)(rx_desc->buf_adr + rx_buf_virtual_base);
				if ( remain_pkt_len < RX_BUF_SIZE ) {
					memcpy(pkt_ptr,rx_buf_adr,remain_pkt_len);
					//hw_memcpy(pkt_ptr,rx_buf_adr,remain_pkt_len);
				} else {
					memcpy(pkt_ptr,rx_buf_adr,RX_BUF_SIZE);
					//hw_memcpy(pkt_ptr,rx_buf_adr,RX_BUF_SIZE);
//					pkt_ptr = &pkt_ptr[RX_BUF_SIZE];
					ptr_ptr = pkt_ptr + RX_BUF_SIZE;
					remain_pkt_len = remain_pkt_len - RX_BUF_SIZE;
				}
			}
#endif
			/* return RX descriptor to DMA */
			rx_desc->frame_ctrl.bits.own = DMA;
			rx_desc->frame_ctrl.bits.buffer_size = RX_BUF_SIZE;
			consistent_sync((void*)rx_desc, sizeof(IPSEC_DESCRIPTOR_T), 
							PCI_DMA_TODEVICE);
			tp->rx_finished_desc = rx_desc;
			/* get next RX descriptor pointer */
			rx_desc = (IPSEC_DESCRIPTOR_T *)(
					(rx_desc->next_desc.next_descriptor & 0xfffffff0) 
					+ rx_desc_virtual_base);
		}
		tp->rx_cur_desc = rx_desc;
//		spin_unlock_irqrestore(&ipsec_rx_lock,flags_a);

		/* to call callback function */
		if ((op_info > 0) && (failure != 1)) {
			if ((op_info->out_packet == NULL) && (op_info->out_packet2 == NULL)) {
				printk("%s::shouldn't happen!!!\n", __func__);
				failure = 1;
				goto rx_fail;
			}

			/* if callback exists, use callback function. 
			 * if not. just skip it. */
			if (op_info->callback != NULL) {
				op_info->flag_polling = polling_flag;
				op_info->callback(op_info);
			}
		}
	}

rx_fail:
	if (failure == 1) {
		printk("%s::something critical fails! Going to restart crypto engine\n", 
						__func__);
		reset_crypto_engine();
		return -1;
	}
	return count;
}

#ifdef CONFIG_SL2312_IPSEC_TASKLET
static int ipsec_tasklet_func(unsigned long data)
{
	IPSEC_TASKLET_INFO_T *ipsec_info = (IPSEC_TASKLET_INFO_T *)data;
	unsigned long flags;
	volatile IPSEC_RXDMA_CTRL_T	rxdma_ctrl;
	int rx_count;

//	if (down_trylock(&ipsec_info->sem)!=0) {
//		tasklet_hi_schedule(&ipsec_info->tasklet);
//		cond_resched();
//		return;
//	}

	rx_count = ipsec_rx_packet(0);
	ipsec_complete_tx_packet();

	if (rx_count == -1) {
//		printk("%s::interrupt and tasklet have been deleted/disabled\n", 
//						__func__);
		clear_bit(0, &ipsec_info->sched);
		return 0;
	}

	if (rx_count < 10) {
		flag_tasklet_scheduled = 0;
		spin_lock_irqsave(&ipsec_irq_lock, flags);
		rxdma_ctrl.bits32 = ipsec_read_reg(IPSEC_RXDMA_CTRL);
		rxdma_ctrl.bits.rd_eof_en = 1;
		ipsec_write_reg2(IPSEC_RXDMA_CTRL, rxdma_ctrl.bits32);
		spin_unlock_irqrestore(&ipsec_irq_lock, flags);
//		up(&ipsec_info->sem);
		clear_bit(0, &ipsec_info->sched);
		return 0;
	} else {
		tasklet_hi_schedule(&ipsec_info->tasklet);
//		tasklet_schedule(&ipsec_info->tasklet);
//		cond_resched();
		return 1;
	}
}
#endif

#ifdef CONFIG_SL2312_IPSEC_NAPI
static inline int ipsec_rx_poll(struct net_device *dev, int *budget) 
{
	unsigned long flags;
	volatile IPSEC_RXDMA_CTRL_T	rxdma_ctrl;
	int rx_count = 0;

	rx_count = ipsec_rx_packet(0);
	ipsec_complete_tx_packet();

	if (rx_count == -1) {
//		printk("%s::interrupt and NAPI have been deleted/disabled\n",__func__);
		return 0;
	}

	if (rx_count == 0) {
		flag_tasklet_scheduled = 0;
		netif_rx_complete(dev);
		spin_lock_irqsave(&ipsec_irq_lock, flags);
		rxdma_ctrl.bits32 = ipsec_read_reg(IPSEC_RXDMA_CTRL);
		rxdma_ctrl.bits.rd_eof_en = 1;
		ipsec_write_reg2(IPSEC_RXDMA_CTRL, rxdma_ctrl.bits32);
		spin_unlock_irqrestore(&ipsec_irq_lock, flags);
		return 0;
	} else
		return 1;
}
#endif

#if defined(CONFIG_SL2312_IPSEC_INTERRUPT) || defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_NAPI)
static irqreturn_t ipsec_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	IPSEC_DMA_STATUS_T status;
	int handled = 0;
	unsigned long flags;
	int failure = 0;
#ifdef CONFIG_SL2312_IPSEC_TASKLET
	IPSEC_TASKLET_INFO_T *ipsec_info;
	volatile IPSEC_RXDMA_CTRL_T rxdma_ctrl;
#endif
#ifdef CONFIG_SL2312_IPSEC_NAPI
	volatile IPSEC_RXDMA_CTRL_T rxdma_ctrl;
#endif

	handled = 1;
	disable_irq(IRQ_IPSEC);

	/* read DMA status */
	status.bits32 = ipsec_read_reg(IPSEC_DMA_STATUS);

	/* clear DMA status */
	ipsec_write_reg(IPSEC_DMA_STATUS, status.bits32, status.bits32);

	if ((status.bits32 & 0x63000000) > 0) {
		printk("Error :");
		if (status.bits.ts_derr == 1)
			printk("AHB bus Error While Tx !!!\n");

		if (status.bits.ts_perr == 1)
			printk("Tx Descriptor Protocol Error !!!\n");

		if (status.bits.rs_derr == 1)
			printk("AHB bus Error While Rx !!!\n");

		if (status.bits.rs_perr == 1)
			printk("Rx Descriptor Protocol Error !!!\n");

		failure = 1;
		goto interrupt_fail;
	}

#ifdef CONFIG_SL2312_IPSEC_INTERRUPT
	if (status.bits.ts_eofi == 1) {
		ipsec_complete_tx_packet();
	}

	if (status.bits.rs_eofi==1) {
		ipsec_rx_packet(0);
		if (status.bits.ts_eofi==0) { /* Tx interrupt losed */
			ipsec_complete_tx_packet();
		}
	}
#endif
#ifdef CONFIG_SL2312_IPSEC_TASKLET
	ipsec_info = (IPSEC_TASKLET_INFO_T *)&ipsec_tasklet_data;

	/* schedule the tasklet */
	if (status.bits.rs_eofi == 1) {
		spin_lock_irqsave(&ipsec_irq_lock, flags);
		if (!test_and_set_bit(0, &ipsec_info->sched)) {
			rxdma_ctrl.bits32 = ipsec_read_reg(IPSEC_RXDMA_CTRL);
			rxdma_ctrl.bits.rd_eof_en = 0;
			ipsec_write_reg2(IPSEC_RXDMA_CTRL, rxdma_ctrl.bits32);
			flag_tasklet_scheduled = 1;
			tasklet_hi_schedule(&ipsec_info->tasklet);
//			tasklet_schedule(&ipsec_info->tasklet);
			//cond_resched();
		}
		spin_unlock_irqrestore(&ipsec_irq_lock, flags);
	}
#endif
#ifdef CONFIG_SL2312_IPSEC_NAPI
	/* schedule the NAPI */
	if (status.bits.rs_eofi == 1) {
		spin_lock_irqsave(&ipsec_irq_lock, flags);
		if (likely(netif_rx_schedule_prep(crypto_rx_dev))) {
			rxdma_ctrl.bits32 = ipsec_read_reg(IPSEC_RXDMA_CTRL);
			rxdma_ctrl.bits.rd_eof_en = 0;
			ipsec_write_reg2(IPSEC_RXDMA_CTRL, rxdma_ctrl.bits32);
			flag_tasklet_scheduled = 1;
			__netif_rx_schedule(crypto_rx_dev);
		}
		spin_unlock_irqrestore(&ipsec_irq_lock, flags);
	}
#endif
	enable_irq(IRQ_IPSEC);

interrupt_fail:
	if (failure) {
		printk("%s::something critical fails! Going to restart crypto engine\n", 
						__func__);
		reset_crypto_engine();
		return -1;
	}
	return IRQ_RETVAL(handled);
}
#endif

static int ipsec_interrupt_polling(void)
{
	IPSEC_DMA_STATUS_T status;
	unsigned int i;
	int result = 0;
	unsigned long flags;
	int	do_tx_complete = 0;
	volatile IPSEC_RXDMA_CTRL_T	rxdma_ctrl;
	int failure = 0;

	if (polling_flag == 0) {
//		printk("%s::polling flag has been turned off\n",__func__);
		return 0;
	}

	/* increment polling_loop, for the case that some errors have 
	 * occured, and the crypto engine stucks on infinite loop. */
	polling_loop++;

	if (polling_loop >= (IPSEC_RX_DESC_NUM)) {
		printk("%s::crypto engine stucks.\n", __func__);
		failure = 1;
		goto polling_fail;
	}

//	disable_irq(IRQ_IPSEC);
	for (i=0; i<40001; i++) {
		/* read DMA status */
		status.bits32 = ipsec_read_reg(IPSEC_DMA_STATUS);

		if (status.bits.rs_eofi == 1) {
			/* clear DMA status */
			ipsec_write_reg(IPSEC_DMA_STATUS, status.bits32, status.bits32);
			break;
		}

		if (i > 40000) {
//			ipsec_read_reg(0x0000);
			printk("FCS fail.......\n");
			failure = 1;
			goto polling_fail;
		}
	}

	if (polling_flag == 0) {
//		printk("%s::polling flag has been turned off 2\n", __func__);
		return 0;
	}

	if (status.bits.rs_eofi == 1) {
		result = ipsec_rx_packet(1);
		if (result != -1) 
			do_tx_complete = 1;
		if (result == 0)
			polling_loop--;
	}
//	enable_irq(IRQ_IPSEC);

#if defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_INTERRUPT) || defined(CONFIG_SL2312_IPSEC_NAPI)
	if (polling_flag == 1) {
		do_tx_complete = 0;
//		printk("%s::gotta run polling more to get to the number we want !!\n",__func__);
//		printk("polling_process_id = %d, last_rx_pid = %d\n",polling_process_id,last_rx_pid);
		start_dma();
		result = ipsec_interrupt_polling();
//		if(result >= 0) {
//			printk("%s::more polling done!\n",__func__);
//		} else
//			printk("%s::polling\n",__func__);
	} else {
		if (flag_tasklet_scheduled != 1) {
			spin_lock_irqsave(&ipsec_irq_lock, flags);
			rxdma_ctrl.bits32 = ipsec_read_reg(IPSEC_RXDMA_CTRL);
			rxdma_ctrl.bits.rd_eof_en = 1;
			ipsec_write_reg2(IPSEC_RXDMA_CTRL, rxdma_ctrl.bits32);
			spin_unlock_irqrestore(&ipsec_irq_lock, flags);
		}
	}

	if (do_tx_complete == 1)
		ipsec_complete_tx_packet();
#endif

#if 0		// original	
	if ((status.bits32 & 0x63000000) > 0) {
		printk("Error :");       
		if (status.bits.ts_derr == 1) {
			printk("AHB bus Error While Tx !!!\n");
			return -2;
		}
		if (status.bits.ts_perr == 1) {
			printk("Tx Descriptor Protocol Error !!!\n");
			return -3;
		}
		if (status.bits.rs_derr == 1) {
			printk("AHB bus Error While Rx !!!\n");
			return -4;
		}
		if (status.bits.rs_perr == 1) {
			printk("Rx Descriptor Protocol Error !!!\n");
			return -5;
		}
	}

	if (status.bits.ts_eofi == 1) {
		//printk("ipsec_interrupt_polling: going ipsec_complete_tx_packet\n");
		ipsec_complete_tx_packet();
	}

	//if ((status.bits.rs_eodi == 1) || (status.bits.rs_eofi == 1))
	if (status.bits.rs_eofi == 1) {
		//printk("do i get here to check ipsec queue #2?\n");
		ipsec_rx_packet(1);
		if (status.bits.ts_eofi == 0) /* Tx interrupt losed */ {
			ipsec_complete_tx_packet();
		}
	}
#endif
polling_fail:
	if (failure == 1) {
		printk("%s::something critical fails! Going to restart crypto engine\n", 
						__func__);
		reset_crypto_engine();
		return -1;
	}
	return (result < 0) ? result : 0;
}

static void ipsec_byte_change(unsigned char *in_key, unsigned int in_len, 
				unsigned char *out_key, unsigned int *out_len)
{
	unsigned int i, j;
    
	memset(out_key, 0x00, sizeof(out_key));
	*out_len = ((in_len + 3)/4) * 4;
	for (i=0; i<(*out_len/4); i++) {
		for (j=0; j<4; j++) {
			out_key[i*4+(3-j)] = in_key[i*4+j];
		}
	}
}

static void ipsec_fcs_init(void)
{
    memset(&fcs_op, 0x00, sizeof(fcs_op));
    fcs_op.op_mode = AUTH;
    fcs_op.auth_algorithm = FCS;
    fcs_op.auth_result_mode = CHECK_MODE; 
    fcs_op.callback = NULL;
    fcs_op.auth_header_len = 0;
#if 1    
    memset(&fcs_auth, 0x00, sizeof(IPSEC_AUTH_T));
    fcs_auth.var.control.bits.op_mode = fcs_op.op_mode;	/* authentication */
	/* append/check authentication result */
    fcs_auth.var.control.bits.auth_mode = fcs_op.auth_result_mode;
    fcs_auth.var.control.bits.auth_algorithm = fcs_op.auth_algorithm; /* FCS */
	/* 4-word to be checked or appended */
    fcs_auth.var.control.bits.auth_check_len = 4;
#endif
}

#ifdef CONFIG_SL2312_HW_CHECKSUM
unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum)
{
	static unsigned int pid = 0;
	unsigned int checksum=0;
    
	if (len < MIN_HW_CHECKSUM_LEN) {
		checksum = csum_partial_sw(buff, len, sum);
	} else {
//		fcs_op.process_id = (pid++) % 256;
		fcs_op.in_packet = (unsigned char *)buff;
		fcs_op.pkt_len = len;
		fcs_op.out_packet2 = (unsigned char *)&out_packet2[0];
		fcs_op.auth_algorithm_len = len;
		ipsec_crypto_hw_process(&fcs_op);
//		interruptible_sleep_on(&ipsec_wait_q);
		checksum = fcs_op.checksum + sum;
	}
	return (checksum);
}
unsigned int csum_partial_copy_nocheck(const char *src, char *dst, int len, 
				int sum)
{
	unsigned int checksum;

	if (len < MIN_HW_CHECKSUM_LEN) {
		checksum = csum_partial_copy_nocheck_sw(src, dst, len, sum);
	} else {
		fcs_op.in_packet = (unsigned char *)src;
		fcs_op.pkt_len = len;
		fcs_op.out_packet2 = (unsigned char *)dst;
		fcs_op.auth_algorithm_len = len;
		ipsec_crypto_hw_process(&fcs_op);
		checksum = fcs_op.checksum + sum;
#if (ZERO_COPY==1)
		memcpy(dst,src,len);		
#endif
	}
	return (checksum);
}

int ipsec_checksum_test(void)
{
	unsigned int i, j;
	unsigned int t1, t2;
	unsigned int sum1, sum2;
	unsigned char *src;
	unsigned char *dst;

	src = kmalloc(IPSEC_MAX_PACKET_LEN,GFP_ATOMIC);
	dst = kmalloc(IPSEC_MAX_PACKET_LEN,GFP_ATOMIC);

	for(i=0; i<IPSEC_MAX_PACKET_LEN; i++) {
		src[i] = i % 256;
	}

	for (i=64; i<=2048; i=i+64) {
		t1 = jiffies;
		for (j=0; j<100000; j++) {
			sum1=csum_partial_copy_nocheck_sw(src, dst, i, 0);
		}
		t2 = jiffies;
		sum1 = (sum1 >> 16) + (sum1 & 0x0000ffff);
		if (sum1 > 0xffff)  sum1 = (sum1 & 0x0000ffff) + 1;
		printk("S/W len=%04d sum=%04x time=%04d<===>", i, sum1,t2-t1);

		t1 = jiffies;
		for (j=0; j<100000; j++) {
			sum2=csum_partial_copy_nocheck(src, dst, i, 0);
		}
		t2 = jiffies;
		printk("H/W(A) len=%04d sum=%04x time=%04d", i, sum2, t2-t1);
		if (sum1 == sum2) {
			printk ("---OK!\n");
		} else {
			printk("---FAIL!\n");
		}
	}

	return (0);        
}
#endif

int ipsec_get_cipher_algorithm(unsigned char *alg_name, unsigned int alg_mode)
{
	static unsigned char name[3][8]={"des", "des3_ede", "aes"};
	static unsigned int  algorithm[2][3]={{ECB_DES, ECB_3DES, ECB_AES}, 
											{CBC_DES, CBC_3DES, CBC_AES}};
	unsigned int i;

	if ((alg_mode != ECB) && (alg_mode != CBC)) return -1;
        
    for (i=0; i<3; i++) {
		if (strncmp(alg_name,&name[i][0], 8) == 0) {
			return (algorithm[alg_mode][i]);
		}
	}
	return -1;
}
EXPORT_SYMBOL(ipsec_get_cipher_algorithm);

int ipsec_get_auth_algorithm(unsigned char *alg_name, unsigned int alg_mode)
{
	static unsigned char name[2][8]={"md5", "sha1"};
	static unsigned int algorithm[2][2]={{MD5, HMAC_MD5}, {SHA1, HMAC_SHA1}};
	unsigned int i;

	//if ((alg_mode != 0) && (alg_mode != 1))
	//    return -1;

//	printk("%s::alg_name=%s,alg_mode=%d\n",__func__,alg_name,alg_mode);
	for (i=0; i<2; i++) {
		if (strncmp(alg_name,&name[i][0],8) == 0) {
			return (algorithm[i][alg_mode]);
		}
	}
	return -1;
}
EXPORT_SYMBOL(ipsec_get_auth_algorithm);

/**************************************************************
 * Name: ipsec_auth_and_cipher
 * Description: for each given IPSEC_PACKET_S, it completes the control packet,
 *				and fill control + data packet backwards from 
 *				(count * 2 + current tx_desc location)
 *************************************************************/
static int ipsec_auth_and_cipher(struct IPSEC_PACKET_S  *op, int mode, 
				int count, int cur_loc)
{
	unsigned char iv[16];
	unsigned int iv_size;
	unsigned int tdflag=0;
	unsigned char cipher_key[32];
	unsigned int cipher_key_size;
	unsigned char auth_key[64];
	unsigned int auth_key_size;
	unsigned int control_packet_len;
	unsigned char auth_result[20];
	unsigned int auth_result_len;
	unsigned int current_auth_check_len;
	IPSEC_CIPHER_CBC_T *cbc_ptr;
	IPSEC_CIPHER_ECB_T *ecb_ptr;
	IPSEC_AUTH_T *auth_ptr;
	IPSEC_HMAC_AUTH_T *auth_hmac_ptr;
	IPSEC_CBC_AUTH_T *cbc_auth_ptr;
	IPSEC_ECB_AUTH_T *ecb_auth_ptr;
	IPSEC_CBC_AUTH_HMAC_T *cbc_auth_hmac_ptr;
	IPSEC_ECB_AUTH_HMAC_T *ecb_auth_hmac_ptr;
	int result = 0;

	if ((op->auth_algorithm == MD5) || (op->auth_algorithm == HMAC_MD5))
		current_auth_check_len = 4;
	else	/* SHA1 or HMAC_SHA1 */
		current_auth_check_len = 5;

	switch (op->op_mode) {
		case ENC_AUTH:
		case AUTH_DEC:
			if ((op->cipher_algorithm == CBC_DES) 
					|| (op->cipher_algorithm == CBC_3DES) 
					|| (op->cipher_algorithm == CBC_AES)) {
				/* (CBC_DES,CBC_3DES,CBC_AES) + (MD5,SHA1) */
				if ((op->auth_algorithm == MD5) 
						|| (op->auth_algorithm == SHA1)) {
					/* Authentication and Cipher CBC mode */
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						cbc_auth_ptr = (IPSEC_CBC_AUTH_T*)&(IPSEC_SUPER_T_list[cur_loc]);
						memset(cbc_auth_ptr, 0x00, sizeof(IPSEC_SUPER_T));
					} else
#endif
					{
						cbc_auth_ptr = &cbc_auth;
						memset(cbc_auth_ptr, 0x00, sizeof(IPSEC_CBC_AUTH_T));
					}
					/* cipher encryption */
					cbc_auth_ptr->control.bits.op_mode = op->op_mode;
					/* cipher algorithm */
					cbc_auth_ptr->control.bits.cipher_algorithm = op->cipher_algorithm;
					/* set frame process id */
					cbc_auth_ptr->control.bits.process_id = op->process_id;
					/* the header length to be skipped by the cipher */
					cbc_auth_ptr->cipher.bits.cipher_header_len = op->cipher_header_len;
					/* the length of message body to be encrypted */
					cbc_auth_ptr->cipher.bits.cipher_algorithm_len = op->cipher_algorithm_len;
					ipsec_byte_change(op->cipher_key,op->cipher_key_size, 
							cipher_key, &cipher_key_size);
					memcpy(cbc_auth_ptr->cipher_key,cipher_key,cipher_key_size);
					/* authentication algorithm */
					cbc_auth_ptr->control.bits.auth_algorithm = op->auth_algorithm;
					/* append/check mode */
					cbc_auth_ptr->control.bits.auth_mode = op->auth_result_mode;
					/* the header length to be skipped by the cipher */
					cbc_auth_ptr->auth.bits.auth_header_len = op->auth_header_len;
					/* the length of message body to be encrypted */
					cbc_auth_ptr->auth.bits.auth_algorithm_len = op->auth_algorithm_len;
					cbc_auth_ptr->control.bits.auth_check_len = op->auth_check_len ? op->auth_check_len : current_auth_check_len;

					//control_packet_len = 4 + 4 + 4 + 16 + 32;
					//tdflag = 0x01 + 0x02 + 0x04 + 0x08 + 0x10;
					control_packet_len = 60;
					tdflag = 0x7f;  /* 1+2+4+8+10+20+40 */

					if (op->cipher_algorithm == CBC_AES) {
						/* IPSec Control Register */
						cbc_auth_ptr->control.bits.aesnk = op->cipher_key_size/4;
						/* Cipher IV */
						ipsec_byte_change(op->iv, 16, iv, &iv_size);
					} else {
						/* IPSec Control Register */
						cbc_auth_ptr->control.bits.aesnk = 0;
						/* Cipher IV */
						ipsec_byte_change(op->iv, 8, iv, &iv_size);
					}
					memcpy(cbc_auth_ptr->cipher_iv, iv, iv_size);

					if (op->auth_result_mode == CHECK_MODE) {
						if (op->auth_checkval) {
							ipsec_byte_change(op->auth_checkval, 
									cbc_auth_ptr->control.bits.auth_check_len*4, 
									cbc_auth_ptr->auth_check_val, 
									&auth_result_len);
						} else {
							ipsec_byte_change(&ipsec_result.sw_cipher[op->pkt_len], 
									current_auth_check_len*4, 
									auth_result, &auth_result_len);
							memcpy(cbc_auth_ptr->auth_check_val, auth_result, 
									auth_result_len);
						}
						control_packet_len = control_packet_len + 20;
						tdflag = tdflag + 0x200;
					}
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						result = ipsec_hw_handle_vpn(
										(unsigned char *)cbc_auth_ptr, 
										control_packet_len, op->in_packet2, 
										op->pkt_len, tdflag, count);
					} else
#endif
					{
						result = ipsec_hw_handle(
										(unsigned char *)cbc_auth_ptr,
										control_packet_len, op->in_packet, 
										op->pkt_len, tdflag);
					}
				} else { /* (CBC_DES,CBC_3DES,CBC_AES) + (HMAC_MD5,HMAC_SHA1) */
					/* Authentication HMAC mode and Cipher CBC mode */
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						cbc_auth_hmac_ptr = (IPSEC_CBC_AUTH_HMAC_T*)&(IPSEC_SUPER_T_list[cur_loc]);
						memset(cbc_auth_hmac_ptr, 0x00, sizeof(IPSEC_SUPER_T));
					}
					else
#endif
					{
						cbc_auth_hmac_ptr = &cbc_auth_hmac;
						memset(cbc_auth_hmac_ptr, 0x00, sizeof(IPSEC_CBC_AUTH_HMAC_T));
					}
					/* cipher encryption */
					cbc_auth_hmac_ptr->control.bits.op_mode = op->op_mode;
					/* cipher algorithm */
					cbc_auth_hmac_ptr->control.bits.cipher_algorithm = op->cipher_algorithm;
					/* set frame process id */
					cbc_auth_hmac_ptr->control.bits.process_id = op->process_id;
					/* the header length to be skipped by the cipher */
					cbc_auth_hmac_ptr->cipher.bits.cipher_header_len = op->cipher_header_len;
					/* the length of message body to be encrypted */
					cbc_auth_hmac_ptr->cipher.bits.cipher_algorithm_len = op->cipher_algorithm_len;
					ipsec_byte_change(op->cipher_key, op->cipher_key_size, 
							cipher_key, &cipher_key_size);
					memcpy(cbc_auth_hmac_ptr->cipher_key, cipher_key, cipher_key_size);
					/* authentication algorithm */
					cbc_auth_hmac_ptr->control.bits.auth_algorithm = op->auth_algorithm;
					/* append/check mode */
					cbc_auth_hmac_ptr->control.bits.auth_mode = op->auth_result_mode;
					/* the header length to be skipped by the cipher */
					cbc_auth_hmac_ptr->auth.bits.auth_header_len = op->auth_header_len;
					/* the length of message body to be encrypted */
					cbc_auth_hmac_ptr->auth.bits.auth_algorithm_len = op->auth_algorithm_len;
					ipsec_byte_change(op->auth_key,op->auth_key_size,auth_key,&auth_key_size);
					memcpy(cbc_auth_hmac_ptr->auth_key,auth_key,auth_key_size);
					cbc_auth_hmac_ptr->control.bits.auth_check_len = op->auth_check_len ? op->auth_check_len : current_auth_check_len;

					//control_packet_len = 4 + 4 + 4 + 16 + 32 + 64;
					//tdflag = 0x01 + 0x02 + 0x04 + 0x08 + 0x10 + 0x20;
					control_packet_len = 124;
					tdflag = 0x1ff;  /* 1+2+4+8+10+20+40+80+100 */

					if (op->cipher_algorithm == CBC_AES) {
						/* IPSec Control Register */
						cbc_auth_hmac_ptr->control.bits.aesnk = op->cipher_key_size/4;
						/* Cipher IV */
						ipsec_byte_change(op->iv, 16, iv, &iv_size);
					} else {	/* CBC_DES || CBC_3DESC */
						/* IPSec Control Register */
						cbc_auth_hmac_ptr->control.bits.aesnk = 0;
						/* Cipher IV */
						ipsec_byte_change(op->iv, 8, iv, &iv_size);
					}
					memcpy(cbc_auth_hmac_ptr->cipher_iv, iv, iv_size);
	
					if (op->auth_result_mode == CHECK_MODE) {
						if (op->auth_checkval) {
							ipsec_byte_change(op->auth_checkval, 
									cbc_auth_hmac_ptr->control.bits.auth_check_len*4, 
									cbc_auth_hmac_ptr->auth_check_val, 
									&auth_result_len);
						} else {
							ipsec_byte_change(&ipsec_result.sw_cipher[op->pkt_len], 
									current_auth_check_len*4, auth_result, 
									&auth_result_len);
							memcpy(cbc_auth_hmac_ptr->auth_check_val, 
									auth_result, auth_result_len);
						}
						control_packet_len = control_packet_len + 20;
						tdflag = tdflag + 0x200;
					}
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						result = ipsec_hw_handle_vpn(
										(unsigned char *)cbc_auth_hmac_ptr, 
										control_packet_len, op->in_packet2, 
										op->pkt_len, tdflag,count);
					} else
#endif
					{
						result = ipsec_hw_handle(
										(unsigned char *)cbc_auth_hmac_ptr, 
										control_packet_len, op->in_packet, 
										op->pkt_len, tdflag);
					}
				}
			} else { /* ECB_DES || ECB_3DES || ECB_AES */
				/* (ECB_DES,ECB_3DES,ECB_AES) + (MD5,SHA1) */
				if ((op->auth_algorithm == MD5) || (op->auth_algorithm == SHA1)) {
					/* Authentication and Cipher ECB mode */
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						ecb_auth_ptr = (IPSEC_ECB_AUTH_T*)&(IPSEC_SUPER_T_list[cur_loc]);
						memset(ecb_auth_ptr, 0x00, sizeof(IPSEC_SUPER_T));
					} else
#endif
					{
						ecb_auth_ptr = &ecb_auth;
						memset(ecb_auth_ptr, 0x00, sizeof(IPSEC_ECB_AUTH_T));
					}
					/* cipher encryption */
					ecb_auth_ptr->control.bits.op_mode = op->op_mode;
					/* cipher algorithm */
					ecb_auth_ptr->control.bits.cipher_algorithm = op->cipher_algorithm;
					/* set frame process id */
					ecb_auth_ptr->control.bits.process_id = op->process_id;
					/* the header length to be skipped by the cipher */
					ecb_auth_ptr->cipher.bits.cipher_header_len = op->cipher_header_len;
					/* the length of message body to be encrypted */
					ecb_auth_ptr->cipher.bits.cipher_algorithm_len = op->cipher_algorithm_len;
					ipsec_byte_change(op->cipher_key,op->cipher_key_size, 
							cipher_key, &cipher_key_size);
					memcpy(ecb_auth_ptr->cipher_key, cipher_key, cipher_key_size);
					/* authentication algorithm */
					ecb_auth_ptr->control.bits.auth_algorithm = op->auth_algorithm;
					/* append/check mode */
					ecb_auth_ptr->control.bits.auth_mode = op->auth_result_mode;
					/* the header length to be skipped by the cipher */
					ecb_auth_ptr->auth.bits.auth_header_len = op->auth_header_len;
					/* the length of message body to be encrypted */
					ecb_auth_ptr->auth.bits.auth_algorithm_len = op->auth_algorithm_len;
					ecb_auth_ptr->control.bits.auth_check_len = op->auth_check_len ? op->auth_check_len : current_auth_check_len;

					//control_packet_len = 4 + 4 + 4 + 32;
					//tdflag = 0x01 + 0x02 + 0x04 + 0x10;
					control_packet_len = 44;
					tdflag = 0x77;  /* 1+2+4+10+20+40 */
				
					/* IPSec Control Register */
					if (op->cipher_algorithm == ECB_AES)
						ecb_auth_ptr->control.bits.aesnk = op->cipher_key_size/4;
					else /* ECB_DES || ECB_3DES */
						ecb_auth_ptr->control.bits.aesnk = 0;

					if (op->auth_result_mode == CHECK_MODE) {
						if (op->auth_checkval) {
							ipsec_byte_change(op->auth_checkval, 
									ecb_auth_ptr->control.bits.auth_check_len*4, 
									ecb_auth_ptr->auth_check_val, 
									&auth_result_len);
						} else {
							ipsec_byte_change(&ipsec_result.sw_cipher[op->pkt_len], 
									current_auth_check_len*4, auth_result, 
									&auth_result_len);
							memcpy(ecb_auth_ptr->auth_check_val, auth_result, 
									auth_result_len);
						}
						control_packet_len = control_packet_len + 20;
						tdflag = tdflag + 0x200;
					}
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						result = ipsec_hw_handle_vpn(
										(unsigned char *)ecb_auth_ptr, 
										control_packet_len, op->in_packet2, 
										op->pkt_len, tdflag,count);
					} else
#endif
					{
						result = ipsec_hw_handle((unsigned char *)ecb_auth_ptr, 
										control_packet_len, op->in_packet, 
										op->pkt_len, tdflag);
					}
				} else { /* (ECB_DES,ECB_3DES,ECB_AES) + (HMAC_MD5,HMAC_SHA1) */
					/* Authentication HMAC mode and Cipher ECB mode */
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						ecb_auth_hmac_ptr = (IPSEC_ECB_AUTH_HMAC_T*)&(IPSEC_SUPER_T_list[cur_loc]);
						memset(ecb_auth_hmac_ptr ,0x00, sizeof(IPSEC_SUPER_T));
					} else
#endif
					{
						ecb_auth_hmac_ptr = &ecb_auth_hmac;
						memset(ecb_auth_hmac_ptr, 0x00, sizeof(IPSEC_ECB_AUTH_HMAC_T));
					}
					/* cipher encryption */
					ecb_auth_hmac_ptr->control.bits.op_mode = op->op_mode;
					/* cipher algorithm */
					ecb_auth_hmac_ptr->control.bits.cipher_algorithm = op->cipher_algorithm;
					/* set frame process id */
					ecb_auth_hmac_ptr->control.bits.process_id = op->process_id;
					/* the header length to be skipped by the cipher */
					ecb_auth_hmac_ptr->cipher.bits.cipher_header_len = op->cipher_header_len;
					/* the length of message body to be encrypted */
					ecb_auth_hmac_ptr->cipher.bits.cipher_algorithm_len = op->cipher_algorithm_len;
					ipsec_byte_change(op->cipher_key, op->cipher_key_size,
							cipher_key, &cipher_key_size);
					memcpy(ecb_auth_hmac_ptr->cipher_key, cipher_key, 
							cipher_key_size);
					/* authentication algorithm */
					ecb_auth_hmac_ptr->control.bits.auth_algorithm = op->auth_algorithm;
					/* append/check mode */
					ecb_auth_hmac_ptr->control.bits.auth_mode = op->auth_result_mode;
					/* the header length to be skipped by the cipher */
					ecb_auth_hmac_ptr->auth.bits.auth_header_len = op->auth_header_len;
					/* the length of message body to be encrypted */
					ecb_auth_hmac_ptr->auth.bits.auth_algorithm_len = op->auth_algorithm_len;
					ipsec_byte_change(op->auth_key, op->auth_key_size, 
							auth_key, &auth_key_size);
					memcpy(ecb_auth_hmac_ptr->auth_key, auth_key, auth_key_size);
					ecb_auth_hmac_ptr->control.bits.auth_check_len = op->auth_check_len ? op->auth_check_len : current_auth_check_len;

					//control_packet_len = 4 + 4 + 4 + 32 + 64;
					//tdflag = 0x01 + 0x02 + 0x04 + 0x10 + 0x20;
					control_packet_len = 108;
					tdflag = 0x1f7;  /* 1+2+4+10+20+40+80+100 */

					/* IPSec Control Register */
					if (op->cipher_algorithm == ECB_AES)
						ecb_auth_hmac_ptr->control.bits.aesnk = op->cipher_key_size/4;
					else
						ecb_auth_hmac_ptr->control.bits.aesnk = 0;

					if (op->auth_result_mode == CHECK_MODE) {
						if (op->auth_checkval) {
							ipsec_byte_change(op->auth_checkval, 
									ecb_auth_hmac_ptr->control.bits.auth_check_len*4, 
									ecb_auth_hmac_ptr->auth_check_val, 
									&auth_result_len);
						} else {
							ipsec_byte_change(
									&ipsec_result.sw_cipher[op->pkt_len], 
									current_auth_check_len*4, auth_result, 
									&auth_result_len);
							memcpy(ecb_auth_hmac_ptr->auth_check_val, 
									auth_result, auth_result_len);
						}
						control_packet_len = control_packet_len + 20;
						tdflag = tdflag + 0x200;
					}
#ifdef CONFIG_CRYPTO_BATCH
					if (mode == BATCH_MODE) {
						result = ipsec_hw_handle_vpn(
										(unsigned char *)ecb_auth_hmac_ptr, 
										control_packet_len, op->in_packet2, 
										op->pkt_len, tdflag, count);
					} else
#endif
					{
						result = ipsec_hw_handle(
										(unsigned char *)ecb_auth_hmac_ptr, 
										control_packet_len, op->in_packet, 
										op->pkt_len, tdflag);
					}
				}
			}
			break;

		case CIPHER_ENC:
		case CIPHER_DEC:
			if ((op->cipher_algorithm == CBC_DES) 
					|| (op->cipher_algorithm == CBC_3DES) 
					|| (op->cipher_algorithm == CBC_AES)) {
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					cbc_ptr = (IPSEC_CIPHER_CBC_T*)&(IPSEC_SUPER_T_list[cur_loc]);
					memset(cbc_ptr, 0x00, sizeof(IPSEC_SUPER_T));
				} else
#endif
				{
					cbc_ptr = &cbc;
					memset(cbc_ptr, 0x00, sizeof(IPSEC_CIPHER_CBC_T));
				}
				/* cipher encryption */
				cbc_ptr->control.bits.op_mode = op->op_mode;
				/* DES-CBC mode */
				cbc_ptr->control.bits.cipher_algorithm = op->cipher_algorithm;
				/* set frame process id */
				cbc_ptr->control.bits.process_id = op->process_id;
				/* the header length to be skipped by the cipher */
				cbc_ptr->cipher.bits.cipher_header_len = op->cipher_header_len;
				/* the length of message body to be encrypted */
				cbc_ptr->cipher.bits.cipher_algorithm_len = op->cipher_algorithm_len;
				ipsec_byte_change(op->cipher_key, op->cipher_key_size, 
						cipher_key, &cipher_key_size);
				memcpy(cbc_ptr->cipher_key, cipher_key, cipher_key_size);

	  			if (op->cipher_algorithm == CBC_AES) {
					/* AES key size */
					cbc_ptr->control.bits.aesnk = op->cipher_key_size/4;
					op->iv_size = 16;
				} else {
					op->iv_size = 8;
				}
				ipsec_byte_change(op->iv, op->iv_size, iv, &iv_size);
				memcpy(cbc_ptr->cipher_iv, iv, iv_size);
				tdflag = 0x7b;  /* 1+2+8+10+20+40 */
				/* hardware encryption */
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					result = ipsec_hw_handle_vpn((unsigned char *)cbc_ptr, 
									sizeof(IPSEC_CIPHER_CBC_T),
									op->in_packet2, op->pkt_len, tdflag, count);
				} else
#endif
				{
					result = ipsec_hw_handle((unsigned char *)cbc_ptr, 
									sizeof(IPSEC_CIPHER_CBC_T), op->in_packet, 
									op->pkt_len, tdflag);
				}
			}
			else /* ECB_DES || ECB_3DES || ECB_AES */
			{
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					ecb_ptr = (IPSEC_CIPHER_ECB_T*)&(IPSEC_SUPER_T_list[cur_loc]);
					memset(ecb_ptr, 0x00, sizeof(IPSEC_SUPER_T));
				} else
#endif
				{
					ecb_ptr = &ecb;
					memset(ecb_ptr, 0x00, sizeof(IPSEC_CIPHER_ECB_T));
				}
				/* cipher encryption */
				ecb_ptr->control.bits.op_mode = op->op_mode;
				/* DES-CBC mode */
				ecb_ptr->control.bits.cipher_algorithm = op->cipher_algorithm;
				/* set frame process id */
				ecb_ptr->control.bits.process_id = op->process_id;
				/* the header length to be skipped by the cipher */
				ecb_ptr->cipher.bits.cipher_header_len = op->cipher_header_len;
				/* the length of message body to be encrypted */
				ecb_ptr->cipher.bits.cipher_algorithm_len = op->cipher_algorithm_len;
				ipsec_byte_change(op->cipher_key, op->cipher_key_size, 
						cipher_key, &cipher_key_size);
				memcpy(ecb_ptr->cipher_key, cipher_key, cipher_key_size);

	  			/* AES key size */
				if (op->cipher_algorithm == ECB_AES)
					ecb_ptr->control.bits.aesnk = op->cipher_key_size/4;

				tdflag = 0x73;  /* 1+2+10+20+40 */
				/* hardware encryption */
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					result = ipsec_hw_handle_vpn((unsigned char *)ecb_ptr, 
									sizeof(IPSEC_CIPHER_ECB_T), op->in_packet2, 
									op->pkt_len, tdflag, count);
				} else
#endif
				{
					result = ipsec_hw_handle((unsigned char *)ecb_ptr, 
									sizeof(IPSEC_CIPHER_ECB_T), op->in_packet, 
									op->pkt_len, tdflag);
				}
			}
			break;

		case AUTH:
			if ((op->auth_algorithm == MD5) || (op->auth_algorithm == SHA1)) {
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					auth_ptr = (IPSEC_AUTH_T*)&(IPSEC_SUPER_T_list[cur_loc]);
					memset(auth_ptr, 0x00, sizeof(IPSEC_SUPER_T));
				} else
#endif
				{
					auth_ptr = &auth;
					memset(auth_ptr, 0x00, sizeof(IPSEC_AUTH_T));
				}
				/* authentication */
				auth_ptr->var.control.bits.op_mode = op->op_mode;
				/* append/check authentication result  */
				auth_ptr->var.control.bits.auth_mode = op->auth_result_mode;
				auth_ptr->var.control.bits.auth_algorithm = op->auth_algorithm;
				/* set frame process id */
				auth_ptr->var.control.bits.process_id = op->process_id;
				auth_ptr->var.auth.bits.auth_header_len = op->auth_header_len;
				auth_ptr->var.auth.bits.auth_algorithm_len = op->auth_algorithm_len;
				auth_ptr->var.control.bits.auth_check_len = op->auth_check_len ? op->auth_check_len : current_auth_check_len;

				if (op->auth_result_mode == APPEND_MODE) {
					control_packet_len = sizeof(IPSEC_AUTH_T) - 20;
					tdflag = 0x05; 
				} else {
					if ((op->auth_check_len) && (op->auth_checkval)) {
						ipsec_byte_change(op->auth_checkval, 
								op->auth_check_len*4, 
								auth_ptr->var.auth_check_val, &auth_result_len);
					} else {
						ipsec_result.sw_pkt_len = current_auth_check_len*4;
						ipsec_byte_change(ipsec_result.sw_cipher, 
										ipsec_result.sw_pkt_len, auth_result, 
										&auth_result_len);
						memcpy(auth_ptr->var.auth_check_val, auth_result, 
										auth_result_len);
					}
					control_packet_len = sizeof(IPSEC_AUTH_T);
					tdflag = 0x205;
				}
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					result = ipsec_hw_handle_vpn((unsigned char *)auth_ptr, 
									control_packet_len, op->in_packet2, 
									op->pkt_len, tdflag, count);
				} else
#endif
				{
	  				result = ipsec_hw_handle((unsigned char *)auth_ptr, 
									control_packet_len, op->in_packet, 
									op->pkt_len, tdflag);
				}
			}
			else if ((op->auth_algorithm == HMAC_MD5) 
					|| (op->auth_algorithm == HMAC_SHA1)) {
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					auth_hmac_ptr = (IPSEC_HMAC_AUTH_T*)&(IPSEC_SUPER_T_list[cur_loc]);
					memset(auth_hmac_ptr, 0x00, sizeof(IPSEC_SUPER_T));
				} else
#endif
				{
					auth_hmac_ptr = &auth_hmac;
					memset(auth_hmac_ptr, 0x00, sizeof(IPSEC_HMAC_AUTH_T));
				}
				/* authentication */
				auth_hmac_ptr->control.bits.op_mode = op->op_mode;
				/* append/check authentication result  */
				auth_hmac_ptr->control.bits.auth_mode = op->auth_result_mode;
				auth_hmac_ptr->control.bits.auth_algorithm = op->auth_algorithm;
				/* set frame process id */
				auth_hmac_ptr->control.bits.process_id = op->process_id;
				auth_hmac_ptr->auth.bits.auth_header_len = op->auth_header_len;
				auth_hmac_ptr->auth.bits.auth_algorithm_len = op->auth_algorithm_len;
				ipsec_byte_change(op->auth_key, op->auth_key_size, auth_key, 
						&auth_key_size);
				memcpy(auth_hmac_ptr->auth_key, auth_key, auth_key_size);
				auth_hmac_ptr->control.bits.auth_check_len = op->auth_check_len ? op->auth_check_len : current_auth_check_len;

				if (op->auth_result_mode == APPEND_MODE) {
					control_packet_len = sizeof(IPSEC_HMAC_AUTH_T) - 20;
					tdflag = 0x185;  /* 1+4+80+100 */
				} else {
					if ((op->auth_check_len) && (op->auth_checkval)) {
						ipsec_byte_change(op->auth_checkval, 
								op->auth_check_len*4, 
								auth_hmac_ptr->auth_check_val, 
								&auth_result_len);
					} else {
						ipsec_result.sw_pkt_len = current_auth_check_len*4;
						ipsec_byte_change(ipsec_result.sw_cipher, 
								ipsec_result.sw_pkt_len, auth_result, 
								&auth_result_len);
						memcpy(auth_hmac_ptr->auth_check_val, auth_result, 
								auth_result_len);
					}
					control_packet_len = sizeof(IPSEC_HMAC_AUTH_T);
					tdflag = 0x385; /* 1+4+80+100+200 */
				}
#ifdef CONFIG_CRYPTO_BATCH
				if (mode == BATCH_MODE) {
					result = ipsec_hw_handle_vpn(
									(unsigned char *)auth_hmac_ptr, 
									control_packet_len, op->in_packet2, 
									op->pkt_len, tdflag, count);
				} else
#endif
				{
					result = ipsec_hw_handle((unsigned char *)auth_hmac_ptr, 
									control_packet_len, op->in_packet, 
									op->pkt_len, tdflag);
				}
			} else /* FCS */ {
				/* set frame process id */
				fcs_auth.var.control.bits.process_id = op->process_id;
				fcs_auth.var.auth.bits.auth_header_len = op->auth_header_len;
				fcs_auth.var.auth.bits.auth_algorithm_len = op->auth_algorithm_len;
				result = ipsec_hw_handle((unsigned char *)&fcs_auth, 28, 
							op->in_packet, op->pkt_len, 0x45);
			}
			break;

		default:
			break;
    }
    return result;
}

#ifdef CONFIG_CRYPTO_BATCH
#if 0	// nonrecursive version.. incomplete
int process_ipsec_batch(struct IPSEC_PACKET_S *crypto_queue, int count, 
				int start_loc, int queue_size)
{
	int available_space = desc_free_space();
	int result = 0;
	unsigned long flags;
	int i;

	if (count <= 0)
		return count;

	if (available_space <= 0) {
		printk("%s::available space (%d) is less or equal to 0\n", __func__, 
				available_space);
		return count;
	}

	if (count > available_space) {
		printk("%s::count(%d) vs space(%d)\n", __func__, count, available_space);
		result = count - available_space;
		count = available_space;
	}

	for (i=0; i<count; i++)
		ipsec_put_queue(ipsec_queue, &(crypto_queue[i]));
	for (i=count-1; i>=0; i--)
		ipsec_auth_and_cipher(&(crypto_queue[i]), i);
}
#endif

//#if 0	// recursive version
int process_ipsec_batch(struct IPSEC_PACKET_S *crypto_queue, int count, 
				int start_loc, int queue_size)
{
	int available_space = desc_free_space();
	int result = 0;
	unsigned long flags;
	
	if (count <= 0)
		return count;

	if (available_space <= 0) {
		return count;
	}

	if (count >= available_space) {
		result = count - available_space + 1;
		count = available_space - 1;
	}
//	printk("%s::count = %d, available space = %d\n",__func__, count, available_space);
	tx_desc_count = 0;

	spin_lock_irqsave(&ipsec_tx_lock, flags);
	process_ipsec_recursive(crypto_queue, count, 0, start_loc, queue_size);
	spin_unlock_irqrestore(&ipsec_tx_lock, flags);

#if defined(CONFIG_SL2312_IPSEC_INTERRUPT) || defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_NAPI)
	// restart dma here
	start_dma();
#else
	start_dma();
	ipsec_interrupt_polling();
//	if(ipsec_interrupt_polling()==0)
//	{
//		//printk("ipsec_interrupt_polling: ok\n");
//	}
//	else
//		printk("%s : polling\n",__func__);
#endif

	return result;
}

static void process_ipsec_recursive(struct IPSEC_PACKET_S *crypto_queue, 
				int count, int current_count, int loc, int queue_size)
{
	IPSEC_DESCRIPTOR_T *rx_desc;
	struct IPSEC_PACKET_S *packet_ptr;
	int cur_loc;
	unsigned int rxdma_desc;
	unsigned long flags;

	if (count > current_count) {
		cur_loc = current_count + loc;
		if (cur_loc >= queue_size)
			cur_loc -= queue_size;
		packet_ptr = (struct IPSEC_PACKET_S*)&(crypto_queue[cur_loc]);
		spin_lock_irqsave(&ipsec_pid_lock, flags);
		packet_ptr->process_id = (pid++) % 256;
		spin_unlock_irqrestore(&ipsec_pid_lock, flags);
		ipsec_put_queue(ipsec_queue, packet_ptr);
		process_ipsec_recursive(crypto_queue, count, current_count+1, loc, 
				queue_size);
		rx_desc = rx_desc_index[(rx_index + 
						(unsigned int)current_count)%IPSEC_RX_DESC_NUM];
//		consistent_sync(packet_ptr->output_skb,SW_RX_BUF_SIZE,DMA_BIDIRECTIONAL);
		rx_desc->buf_adr = __pa(packet_ptr->out_packet2);
		if (packet_ptr->out_buffer_len != 0)
			rx_desc->frame_ctrl.bits.buffer_size = packet_ptr->out_buffer_len;
		else
			rx_desc->frame_ctrl.bits.buffer_size = RX_BUF_SIZE;
//		consistent_sync(rx_desc,sizeof(IPSEC_DESCRIPTOR_T),DMA_BIDIRECTIONAL);

		if (current_count == 0) {
			rx_index = rx_index + (unsigned int)count;
			rxdma_desc = (ipsec_read_reg(IPSEC_RXDMA_CURR_DESC) 
								&0xfffffff0) + rx_desc_virtual_base;
			if ((unsigned int)rx_desc == (unsigned int)rxdma_desc) {
				ipsec_write_reg2(IPSEC_RXDMA_BUF_ADDR, rx_desc->buf_adr);
				if (((unsigned int)rx_desc < 0xf0000000) 
						|| ((unsigned int)rx_desc > 0xffffffff))
					printk("%s::descriptor address is out of range? 0x%x\n", 
							__func__, (unsigned int)rx_desc);
				consistent_sync((void *)rx_desc, sizeof(IPSEC_DESCRIPTOR_T), 
						PCI_DMA_TODEVICE);
			}
		}
		ipsec_auth_and_cipher(packet_ptr, 1, current_count, cur_loc);
	}
	return;
}

//static int ipsec_hw_handle_vpn(volatile unsigned char *ctrl_pkt, 
//				int ctrl_len, volatile unsigned char *data_pkt, 
static int ipsec_hw_handle_vpn(unsigned char *ctrl_pkt, int ctrl_len, 
				unsigned char *data_pkt, int data_len, unsigned int tqflag, 
				int count)
{
	int i;
	IPSEC_DESCRIPTOR_T *tx_desc;
	int first_flag = 0;

	if (tx_desc_count == 0) {
		first_flag = 1;
		first_batch_tx_desc = tp->tx_cur_desc;
	}
	tx_desc = first_batch_tx_desc;

	/* move tx_desc to the tx_desc that's going to be filled with the 
	 * information */
	for (i=0; i<(count+count); i++) {
		tx_desc = (IPSEC_DESCRIPTOR_T *)(
						(tx_desc->next_desc.next_descriptor & 0xfffffff0)
						+ tx_desc_virtual_base);
		if (tx_desc->frame_ctrl.bits.own != CPU) {
			printk("%s::Not enough TX Descriptors@%x a\n", __func__, 
					(unsigned int)tx_desc);
			ipsec_read_reg(0x0000);
		}
	}

	/* fill desc for control packet */
	ipsec_fill_desc(tx_desc, (unsigned char*)ctrl_pkt, ctrl_len, tqflag, DMA);
	tx_desc_count++;

	/* fill desc for data packet */
	tx_desc = (IPSEC_DESCRIPTOR_T *)(
					(tx_desc->next_desc.next_descriptor & 0xfffffff0) 
					+ tx_desc_virtual_base);
	if (tx_desc->frame_ctrl.bits.own != CPU) {
		printk("%s::Not enough TX Descriptors@%x b\n", __func__, 
				(unsigned int)tx_desc);
		ipsec_read_reg(0x0000);
	}

	ipsec_fill_desc(tx_desc, (unsigned char*)data_pkt, data_len, 0, DMA);
	tx_desc_count++;

	if (first_flag == 1)
		tp->tx_cur_desc = (IPSEC_DESCRIPTOR_T *)(
							(tx_desc->next_desc.next_descriptor & 0xfffffff0) 
							+ tx_desc_virtual_base);

	return 0;
}

static int ipsec_fill_desc(IPSEC_DESCRIPTOR_T *desc, unsigned char * data, 
				int len, unsigned int flag, int ownership)
{
	if (desc->frame_ctrl.bits.own == CPU) {
		int desc_cnt = (len/TX_BUF_SIZE);
		if (desc_cnt > 1)
			printk("%s::don't allow more than 1 descriptor for 1 packet\n", 
					__func__);
		desc->frame_ctrl.bits32 = 0;
		desc->frame_ctrl.bits.buffer_size = len;
		desc->flag_status.bits32 = 0;
		desc->flag_status.bits_tx_flag.tqflag = flag;
		desc->next_desc.bits.eofie = 1;
		desc->next_desc.bits.dec = 0;
		desc->next_desc.bits.sof_eof = 0x03;
//		wmb();
		consistent_sync(data, len, PCI_DMA_TODEVICE);
		desc->buf_adr = (unsigned int)__pa(data);
		//desc->buf_adr = (unsigned int)virt_to_phys(data);
		wmb();
		desc->frame_ctrl.bits.own = ownership;
		consistent_sync(desc, sizeof(IPSEC_DESCRIPTOR_T), PCI_DMA_TODEVICE);
	}
	return 0;
}

/***************************************************************************
 * Name: desc_free_space
 * Description: An API for crypto batch implementation
 *				It will return the number of free desc space, so caller 
 *				function can control the number of crypto packet sending to 
 *				the crypto engine w/o overflooding the crypto engine's 
 *				descriptor.
 * Return: rxq_available_space > txq_available_space ? 
 * 						txq_available_space : rxq_available_space
 * Note: to avoid some weird RX bugs, it's better that 
 * 			#_TX_desc >= 2 (#_RX_desc + 2)
 **************************************************************************/
static int desc_free_space(void)
{
	IPSEC_DESCRIPTOR_T *tx_desc_wptr = tp->tx_cur_desc;
	IPSEC_DESCRIPTOR_T *tx_desc_rptr = (IPSEC_DESCRIPTOR_T *)(
						(ipsec_read_reg(IPSEC_TXDMA_CURR_DESC) & 0xfffffff0) 
						+ tx_desc_virtual_base);
	IPSEC_DESCRIPTOR_T *rx_desc_rptr = tp->rx_cur_desc;
	IPSEC_DESCRIPTOR_T *rx_desc_wptr = (IPSEC_DESCRIPTOR_T *)(
						(ipsec_read_reg(IPSEC_RXDMA_CURR_DESC) & 0xfffffff0) 
						+ rx_desc_virtual_base);
	unsigned int rx_space, tx_space;
	int result;

	/* calculate available space in rxq */
	if ((rx_desc_wptr->frame_ctrl.bits.own == CPU)
			&& ((unsigned int)rx_desc_wptr == (unsigned int)rx_desc_rptr)) {
		rx_space = 0;
//		if (flag_tasklet_scheduled == 0)
//			printk("%s::all the rx desc are in used, and tasklet is not scheduled?\n",__func__);
	} else {
		if ((unsigned int)rx_desc_wptr >= (unsigned int)rx_desc_rptr)
			rx_space = IPSEC_RX_DESC_NUM - (((unsigned int)rx_desc_wptr 
							- (unsigned int)rx_desc_rptr) 
							/ sizeof(IPSEC_DESCRIPTOR_T));
		else
			rx_space = ((unsigned int)rx_desc_rptr 
							- (unsigned int)rx_desc_wptr) 
							/ sizeof(IPSEC_DESCRIPTOR_T);
	}

	/* calculate current used space in txq */
	if (tx_desc_wptr->frame_ctrl.bits.own != CPU)
		tx_space = 0;
	else {
		if ((unsigned int)tx_desc_wptr >= (unsigned int)tx_desc_rptr)
			tx_space = IPSEC_TX_DESC_NUM - (((unsigned int)tx_desc_wptr 
							- (unsigned int)tx_desc_rptr) 
							/ sizeof(IPSEC_DESCRIPTOR_T));
		else
			tx_space = ((unsigned int)tx_desc_rptr 
							- (unsigned int)tx_desc_wptr) 
					/ sizeof(IPSEC_DESCRIPTOR_T);
	}
	
	tx_space = tx_space >> 1;

	result = (int)((rx_space < tx_space) ? rx_space : tx_space);

//	if (result == 0) {
//		printk("%s::rx_space = %d, tx_space = %d\n", __func__, rx_space, 
//				tx_space);
//		if (rx_desc_wptr->frame_ctrl.bits.own == CPU)
//			printk("%s::rx_desc_wptr is owned by CPU\n", __func__);
//		if (tx_desc_wptr->frame_ctrl.bits.own != CPU)
//			printk("%s::tx_desc_wptr is owned by DMA\n", __func__);
//	}
	return result;
}
#endif

/***************************************************
 * Name: crypto_enable_interrupt
 * Description: request IRQ for crypto engine, initialize tasklet and/or 
 * 				a virtual network device for crypto engine NAPI mode.
 **************************************************/
static void crypto_enable_interrupt(void)
{
#ifdef CONFIG_SL2312_IPSEC_TASKLET
	IPSEC_TASKLET_INFO_T *ipsec_tasklet_info;
#endif

#ifdef CONFIG_SL2312_IPSEC_INTERRUPT
	/* Install interrupt request */
	request_irq(IRQ_IPSEC, ipsec_interrupt, SA_INTERRUPT, "SL2312-IPSEC", NULL);
#endif
#ifdef CONFIG_SL2312_IPSEC_TASKLET
	request_irq(IRQ_IPSEC, ipsec_interrupt, SA_INTERRUPT, "SL2312-IPSEC", NULL);
	ipsec_tasklet_info = (IPSEC_TASKLET_INFO_T*)&ipsec_tasklet_data;
	memset(ipsec_tasklet_info, 0x00, sizeof(IPSEC_TASKLET_INFO_T));
//	sema_init(&ipsec_tasklet_info->sem, 1);
	tasklet_init(&ipsec_tasklet_info->tasklet, (void *)ipsec_tasklet_func, 
			(unsigned long)ipsec_tasklet_info);
	clear_bit(0, &ipsec_tasklet_info->sched);
#endif
#ifdef CONFIG_SL2312_IPSEC_NAPI
	if (crypto_rx_dev == NULL) {
		crypto_rx_dev = alloc_etherdev(0);
		SET_MODULE_OWNER(crypto_rx_dev);

		if (crypto_rx_dev == NULL) {
			printk("%s::cannot allocate etherdev for crypto engine\n", 
					__func__);
		}
		request_irq(IRQ_IPSEC, ipsec_interrupt, SA_INTERRUPT, "SL2312-IPSEC", 
					NULL);
		netif_start_queue(crypto_rx_dev);
		crypto_rx_dev->open = NULL;
		crypto_rx_dev->stop = NULL;
		crypto_rx_dev->irq = IRQ_IPSEC;
		crypto_rx_dev->hard_start_xmit = NULL;
		crypto_rx_dev->poll = ipsec_rx_poll;
		crypto_rx_dev->weight = 16;
		if (register_netdev(crypto_rx_dev)) {
			printk("%s::fail to register dummy crypto rx device\n", __func__);
		}
	} else {
		netif_wake_queue(crypto_rx_dev);
	}
#endif

	/* on default, make sure hw crypto support for kernel is on. */
	storlink_ctl.hw_crypto = 1;
}

/*******************************************
 * Name: crypto_disable_interrupt
 * Description: free IRQ for crypto engine, kill running tasklet, and/or 
 * 				stop the running crypto engine virtual network device
 ******************************************/
static void crypto_disable_interrupt(void)
{
#ifdef CONFIG_SL2312_IPSEC_TASKLET
	IPSEC_TASKLET_INFO_T *ipsec_info;
#endif

#if defined(CONFIG_SL2312_IPSEC_INTERRUPT) || defined(CONFIG_SL2312_IPSEC_TASKLET) || defined(CONFIG_SL2312_IPSEC_NAPI)
	disable_irq(IRQ_IPSEC);
//	synchronize_irq();
	free_irq(IRQ_IPSEC, NULL);
#endif

#ifdef CONFIG_SL2312_IPSEC_TASKLET
	ipsec_info = (IPSEC_TASKLET_INFO_T  *)&ipsec_tasklet_data;
	clear_bit(0, &ipsec_info->sched);
	flag_tasklet_scheduled = 0;
	tasklet_kill(&ipsec_info->tasklet);
#endif

#ifdef CONFIG_SL2312_IPSEC_NAPI
	netif_stop_queue(crypto_rx_dev);
#endif
	storlink_ctl.hw_crypto = 0;
}

/*************************************************************
 * Name: crypto_hw_stop
 * Description: clean some of the main crypto engine registers
 ************************************************************/
static void crypto_hw_stop(void)
{
	IPSEC_TXDMA_CTRL_T txdma_ctrl_mask;
	IPSEC_RXDMA_CTRL_T rxdma_ctrl_mask;

	ipsec_write_reg(IPSEC_TXDMA_CURR_DESC,0x00,0xffffffff);
	ipsec_write_reg(IPSEC_RXDMA_CURR_DESC,0x00,0xffffffff);
	ipsec_write_reg(IPSEC_DMA_STATUS,0x00,0xffffffff);

	txdma_ctrl_mask.bits32 = 0;
	txdma_ctrl_mask.bits.td_start = 1;
	ipsec_write_reg(IPSEC_TXDMA_CTRL, 0x00, txdma_ctrl_mask.bits32);

	rxdma_ctrl_mask.bits32 = 0;
	rxdma_ctrl_mask.bits.rd_start = 1;
	ipsec_write_reg(IPSEC_RXDMA_CTRL, 0x00, rxdma_ctrl_mask.bits32);
}

/***************************************************
 * Name: crypto_release_buffers
 * Description: free descriptor queues. return a fail status to all 
 * 				the transferred cryptography processes. set NULL to 
 * 				all the descriptor pointers
 **************************************************/
static void crypto_release_buffers(void)
{
	struct IPSEC_PACKET_S *op_info;

	/* clean descriptor */
	if (tp->tx_desc) {
		DMA_MFREE(tp->tx_desc, IPSEC_TX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
				(unsigned int)tp->tx_desc_dma);
	}
	if (tp->rx_desc) {
		DMA_MFREE(tp->rx_desc, IPSEC_RX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
				(unsigned int)tp->rx_desc_dma);
	}

	/* clean all the queue entries */
	while ((op_info = ipsec_get_queue(ipsec_queue))!=NULL) {
		op_info->status = CRYPTO_RESET;	/* 3 means, in need to restart all crypto engine */
		if  (op_info->callback != NULL) {
//			printk("%s::cleaing packet with callback\n", __func__);
			op_info->callback(op_info);
		}
//		else
//		{
//			/* will need to check different cases in this situation? */
//			printk("%s::cleaning packet w/o callback\n",__func__);
//		}
	}
	tp->tx_desc = NULL;
	tp->rx_desc = NULL;
	tp->tx_cur_desc = NULL;
	tp->rx_cur_desc = NULL;
	tp->tx_finished_desc = NULL;
	tp->rx_finished_desc = NULL;
	tp->tx_desc_dma = 0;
	tp->rx_desc_dma = 0;
}

/******************************************************************************
 * Name: reset_crypto_engine
 * Description: reset crypto engine!! such as clean up all the entries in 
 * 				descriptors and queue entries
 * Return: 0 if succeeds, 1 otherwise.
 *****************************************************************************/
static int reset_crypto_engine(void)
{
	/* stop all the related process, HW information and clean all the buffers
	 * stop IRQ and tasklet/NAPI */
#ifdef CONFIG_SL2312_IPSEC_NAPI
	if (flag_tasklet_scheduled == 1)
		netif_rx_complete(crypto_rx_dev);
#endif
	/* disable IRQ and Tasklet/NAPI */
	crypto_disable_interrupt();
	/* stop HW crypto engine & clean all status bit */
	crypto_hw_stop();
	/* release all buffers */
	crypto_release_buffers();
	/* reset the crypto engine */
	ipsec_sw_reset();
//	ipsec_write_reg(IPSEC_DMA_STATUS, 0x00003000, 0x00003000);

	while (ipsec_get_queue(ipsec_queue) != NULL) {
	}

	ipsec_queue = &dummy[2];
	ipsec_queue->next = ipsec_queue->prev = ipsec_queue;

	/* start restoring
	 * re-allocate buffers */
	ipsec_buf_init();
	/* restart HW crypto engine */
	ipsec_hw_start();
	/* restart interrupt */
	crypto_enable_interrupt();

	pid = 0;
	last_rx_pid = 255;
	rx_index = 0;
	polling_process_id = -1;
	polling_flag = 0;
	flag_tasklet_scheduled = 0;

	return 0;
}

/******************************************************************************
 * Name: ipsec_initial
 * Description: Initialization for crypto engine
 * Return: 0 if succeeds, 1 otherwise.
 *****************************************************************************/
static int __init ipsec_initial(void)
{
	printk ("ipsec_init : cryptographic accelerator \n");

	ipsec_queue = &dummy[2];
	ipsec_queue->next = ipsec_queue->prev = ipsec_queue;

	ipsec_fcs_init();
	ipsec_buf_init();
	ipsec_hw_start();
	crypto_enable_interrupt();

	// initialize all the locks
	spin_lock_init(&ipsec_irq_lock);
	spin_lock_init(&ipsec_q_lock);
	spin_lock_init(&ipsec_polling_lock);
	spin_lock_init(&ipsec_tx_lock);
	spin_lock_init(&ipsec_pid_lock);
//	spin_lock_init(&ipsec_rx_lock);

#if 0
	for (;;) {
		unsigned int t1,t2;

		t1 = ipsec_get_time();
//		ipsec_checksum_test();
//		ipsec_adv_auth_fix_algorithm_test();
//		ipsec_adv_auth_vary_algorithm_test();
//		ipsec_adv_cipher_fix_algorithm_test();
//		ipsec_adv_cipher_vary_algorithm_test();
//		ipsec_adv_auth_then_decrypt_test();
//		ipsec_adv_encrypt_then_auth_test();

		t2 = ipsec_get_time();
		printk("Time = %d \n",t1-t2);
	}
#endif

	return 0;
}

static void __exit ipsec_cleanup (void)
{
#ifdef CONFIG_SL2312_IPSEC_TASKLET
	IPSEC_TASKLET_INFO_T *ipsec_info;
#endif
	free_irq(IRQ_IPSEC, NULL);
	if (tp->tx_desc) {
		DMA_MFREE(tp->tx_desc, IPSEC_TX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
				(unsigned int)tp->tx_desc_dma);
	}
	if (tp->rx_desc) {
		DMA_MFREE(tp->rx_desc, IPSEC_RX_DESC_NUM*sizeof(IPSEC_DESCRIPTOR_T), 
				(unsigned int)tp->rx_desc_dma);
	}
#ifdef CONFIG_SL2312_IPSEC_TASKLET
	ipsec_info = (IPSEC_TASKLET_INFO_T *)&ipsec_tasklet_data;
	tasklet_kill(&ipsec_info->tasklet);
#endif
}
EXPORT_SYMBOL(ipsec_crypto_hw_process);
module_init(ipsec_initial);
module_exit(ipsec_cleanup);
