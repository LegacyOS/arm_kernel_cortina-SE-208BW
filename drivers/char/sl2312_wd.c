#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/watchdog.h>
#include <asm/uaccess.h>
#include <asm/arch/sl2312.h>
#include <asm/arch/hardware.h>
#include <asm/arch/irqs.h>
#include <asm/arch/watchdog.h>
#include <asm/io.h>
#include <linux/interrupt.h>

#define WATCHDOG_TEST 1

static int soft_margin = WATCHDOG_TIMEOUT_MARGIN;
static int open_state=WATCHDOG_DRIVER_CLOSE;
static int wd_expire=0;
 
static void watchdog_disable(void) 
{
    unsigned long wdcr;

    wdcr = *((unsigned long *)WATCHDOG_CR);
    wdcr &= ~WATCHDOG_WDENABLE_MSK;
    *((unsigned long *)WATCHDOG_CR) = wdcr;
}

static void watchdog_enable(void)
{
    unsigned long wdcr;

    wdcr = *((unsigned long *)WATCHDOG_CR);
    wdcr |= (WATCHDOG_WDENABLE_MSK|WATCHDOG_WDRST_MSK);
#ifdef WATCHDOG_TEST     
    wdcr |= WATCHDOG_WDINTR_MSK;
    wdcr &= ~WATCHDOG_WDRST_MSK;
#endif          
    wdcr &= ~WATCHDOG_WDCLOCK_MSK;
    *((unsigned long *)WATCHDOG_CR) = wdcr;
}

#ifdef WATCHDOG_TEST
static irqreturn_t watchdog_fire(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned int clear;
    *((unsigned long *)WATCHDOG_CLEAR) = WATCHDOG_CLEAR_STATUS;
    printk("Watchdog timeout, resetting system...\n");	
    clear = __raw_readl(IO_ADDRESS(SL2312_INTERRUPT_BASE)+0x0C);
    clear &= 0x01;
    __raw_writel(clear,IO_ADDRESS(SL2312_INTERRUPT_BASE)+0x08);
    wd_expire = 1;
    return IRQ_HANDLED;
}	

#endif

struct file_operations watchdog_fops = {
    .owner= THIS_MODULE,
    .write watchdog_write,
    .read= watchdog_read,
    .open= watchdog_open,
    .release= watchdog_release,
    .ioctl= watchdog_ioctl,
};

static int watchdog_open(struct inode *inode, struct file *filp)
{
    unsigned long timeout;	

    printk("watchdog_open : \n");
    if(open_state == WATCHDOG_DRIVER_OPEN)
	return -EBUSY;
	
	wd_expire = 0;
#ifdef WATCHDOG_TEST
    printk("request watchdog irq %x \n", IRQ_WATCHDOG);    
    if(request_irq(IRQ_WATCHDOG,watchdog_fire,SA_INTERRUPT,"sl2312_wdt",NULL))
    {
		printk(KERN_ERR "watchdog request interrupt %x fail \n", IRQ_WATCHDOG);	
	}
	
#endif		
    watchdog_disable();
    timeout = WATCHDOG_TIMEOUT_SCALE * WATCHDOG_TIMEOUT_MARGIN;
    *((unsigned long *)WATCHDOG_LOAD) = timeout;
    *((unsigned long *)WATCHDOG_RESTART) = WATCHDOG_RESTART_VALUE;
    watchdog_enable();
        
    open_state = WATCHDOG_DRIVER_OPEN;
    printk("watchdog_open complete : \n");
    return 0;
}

static int watchdog_release(struct inode *inode, struct file *filp)
{
#ifdef WATCHDOG_TEST	
    free_irq(IRQ_WATCHDOG, NULL);
#endif
    open_state = WATCHDOG_DRIVER_CLOSE;
    watchdog_disable();
    wd_expire = 0;
    return 0;
}

static ssize_t watchdog_read(struct file *filp, char *buf, size_t count, loff_t *off)
{
    int i;
    unsigned long val;

    
    for (i=0;i< count;i++)
    {
    	if((i%4)==0)
    		val = *((unsigned long *)WATCHDOG_COUNTER);
		buf[i] = (val & 0xFF);
		val >>= 8;
    }
    return count;
}

static ssize_t watchdog_write(struct file *filp, const char *buf, size_t len, loff_t *off) 
{
    /*  Can't seek (pwrite) on this device  */
    if (off != &filp->f_pos)
         return -ESPIPE;
 
    /*  Refresh the timer. */
    if(len)
    {
      *((unsigned long *)WATCHDOG_RESTART) = WATCHDOG_RESTART_VALUE;
       return 1;
    }
    return 0;
	
}

static int watchdog_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg) 
{
    int margin, timeout;
    unsigned int wdcr;
	
//    printk("watchdog_ioctl cmd is %x \n", cmd);
    switch(cmd)
    {
	default:
		return -ENOTTY;
	case WDIOC_KEEPALIVE:
//	     printk("WDIOC_KEEPALIVE : \n");
         *((unsigned long *)WATCHDOG_RESTART) = WATCHDOG_RESTART_VALUE;
		return 0;
	case WDIOC_SETTIMEOUT:
	     if (get_user(margin, (int *)arg))
		 	return -EFAULT;
	     
	     /* Arbitrary, can't find the card's limits */
	     if ((margin < 0) || (margin > 60))
		 	return -EINVAL;
	     soft_margin = margin;
  	     timeout = WATCHDOG_TIMEOUT_SCALE * soft_margin;
         *((unsigned long *)WATCHDOG_LOAD) = timeout;
         *((unsigned long *)WATCHDOG_RESTART) = WATCHDOG_RESTART_VALUE;

         wdcr = *((unsigned long *)WATCHDOG_CR);
         wdcr |= WATCHDOG_WDRST_MSK;
         *((unsigned long *)WATCHDOG_CR) = wdcr;

         return put_user(soft_margin, (int *)arg);
         
		/* Fall */
	case WDIOC_GETTIMEOUT:
			margin = *((unsigned long *)WATCHDOG_COUNTER) / WATCHDOG_TIMEOUT_SCALE ;
			return put_user(margin, (int *)arg);
			
	case WDIOC_GETSTATUS:
			if (wd_expire==1){
				wd_expire = 0;
				return put_user(1, (int *)arg);
			}
			else
				return put_user(0, (int *)arg);
	}
}

static struct miscdevice wd_dev= {
	WATCHDOG_MINOR,
	"watchog",
	&watchdog_fops
};

static int __init watchdog_init(void)
{
	
	int ret;
	
	ret = misc_register(&wd_dev);
	printk(KERN_INFO "Watchdog Timer Initialized\n");
	return ret;
}

module_init(watchdog_init);
