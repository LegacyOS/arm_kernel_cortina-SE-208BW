/*
 * FILE NAME gemini_ssp_led.c
 *
 * BRIEF MODULE DESCRIPTION
 *  API for gemini SSP LED module
 *  Driver for gemini SSP LED module
 *
 *  Author: Cortina Systems, Inc.
 *          Becker Hung <becker.hung@cortina-systems.com>
 *
 * Copyright 2009 Cortina Systems, Inc.
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMit8712D  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE	LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMit8712D   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, writ8712  to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 */

 //
 //This file is used for fabrik LED
 //
 
#include <linux/module.h>
#include <linux/config.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>
#include <asm/hardware.h>
#include <asm/io.h>
#include <asm/arch/sl2312.h>
#include <linux/delay.h>

//create an char device
// mknod /dev/ssp_led c 10 186


/****/
/*defines for the ioctl*/
#define GEMINI_SSP_LED_SET_DUTY_CYCLE      1  
#define GEMINI_SSP_LED_START_BOOT          2  
#define GEMINI_SSP_LED_END_BOOT            3  
#define GEMINI_SSP_LED_START_BACKUP        4  
#define GEMINI_SSP_LED_SLIENT_BACKUP       5  
#define GEMINI_SSP_LED_END_BACKUP          6  
#define GEMINI_SSP_LED_WAIT_STATE          7  
#define GEMINI_SSP_LED_NETWORK_CONNECT     8  
#define GEMINI_SSP_LED_NETWORK_DISCONNECT  9  
#define GEMINI_SSP_LED_ERROR_STATE         10  
#define GEMINI_SSP_LED_PASSWORD_RESET      11  
#define GEMINI_SSP_LED_FACTORY_RESET       12  


/*SSP value of LED on*/  
#define GEMINI_SSP_LED_ON                              0x7f
/*SSP value of LED off*/  
#define GEMINI_SSP_LED_OFF                             0x01

#define GEMINI_SSP_LED_DEFAULT_TIMEOUT    (1*HZ)

/*start boot*/  
#define GEMINI_SSP_LED_START_BOOT_LED_ON_MSEC          (1*HZ)  
#define GEMINI_SSP_LED_START_BOOT_LED_OFF_MSEC         (1*HZ)
/*network disconnect*/  
#define GEMINI_SSP_LED_NETWORK_DISCONNECT_LED_ON_MSEC  (1*HZ)
#define GEMINI_SSP_LED_NETWORK_DISCONNECT_LED_OFF_MSEC (2*HZ)
/*error state*/  
#define GEMINI_SSP_LED_ERROR_STATE_LED_ON_MSEC         ((1*HZ)/2)
#define GEMINI_SSP_LED_ERROR_STATE_LED_OFF_MSEC        ((1*HZ)/2)  
/*password reset*/  
#define GEMINI_SSP_LED_PASSWORD_RESET_LED_ON_MSEC      ((1*HZ)/2)  
#define GEMINI_SSP_LED_PASSWORD_RESET_LED_OFF_MSEC     (1*HZ)  
/*factory reset*/  
#define GEMINI_SSP_LED_FACTORY_RESET_LED_ON_MSEC       (1*HZ)  
#define GEMINI_SSP_LED_FACTORY_RESET_LED_OFF_MSEC      (1*HZ)  


/****/

#define    SSP_DEVICE_ID            0x00
#define    SSP_CTRL_STATUS          0x04
#define    SSP_FRAME_CTRL           0x08
#define    SSP_BAUD_RATE            0x0c
#define    SSP_FRAME_CTRL2          0x10
#define    SSP_FIFO_CTRL            0x14
#define    SSP_TX_SLOT_VALID0       0x18
#define    SSP_TX_SLOT_VALID1       0x1c
#define    SSP_TX_SLOT_VALID2       0x20
#define    SSP_TX_SLOT_VALID3       0x24
#define    SSP_RX_SLOT_VALID0       0x28
#define    SSP_RX_SLOT_VALID1       0x2c
#define    SSP_RX_SLOT_VALID2       0x30
#define    SSP_RX_SLOT_VALID3       0x34
#define    SSP_SLOT_SIZE0           0x38
#define    SSP_SLOT_SIZE1           0x3c
#define    SSP_SLOT_SIZE2           0x40
#define    SSP_SLOT_SIZE3           0x44
#define    SSP_READ_PORT            0x48
#define    SSP_WRITE_PORT           0x4c
 
/***************************************/
/* define GPIO module base address     */
/***************************************/
#define SSP_BASE                      (IO_ADDRESS(SL2312_SSP_CTRL_BASE))
#define GLOBAL_BASE                   (IO_ADDRESS(SL2312_GLOBAL_BASE))
 
/* define read/write register utility */
#define SSP_READ_REG(offset)          (__raw_readl(offset+SSP_BASE))
#define SSP_WRITE_REG(offset,val)     (__raw_writel(val,offset+SSP_BASE))
 
#define READ_GLOBAL_REG(offset)       (__raw_readl(offset+GLOBAL_BASE))
#define WRITE_GLOBAL_REG(offset,val)  (__raw_writel(val,offset+GLOBAL_BASE))

static unsigned long timeout=GEMINI_SSP_LED_DEFAULT_TIMEOUT;
int ssp_led_curr_state=GEMINI_SSP_LED_START_BOOT;
int ssp_led_saved_state=GEMINI_SSP_LED_END_BOOT;
int ssp_led_on_off_flag=0;
int ioctl_data=GEMINI_SSP_LED_OFF;

void ssp_led_init_ctl(void)
{
	unsigned int data=0;
#ifdef CONFIG_SL3516_ASIC
	data = READ_GLOBAL_REG(0x30);
	data|=0x100;
	data&=0xfffeffbf;
	WRITE_GLOBAL_REG(0x30,data);
	
	SSP_WRITE_REG(SSP_FRAME_CTRL, 0x04010FFF ); //0x04010030//ext clk : bit17
	SSP_WRITE_REG(SSP_BAUD_RATE, 0x3f020601);
#else
	
	SSP_WRITE_REG(SSP_FRAME_CTRL, 0x04010030 ); //0x04010030//ext clk : bit17
	SSP_WRITE_REG(SSP_BAUD_RATE, 0x1F020502);
	
#endif
	
	SSP_WRITE_REG(SSP_FRAME_CTRL2, 0x000F807F);//0x0003800f
	SSP_WRITE_REG(SSP_FIFO_CTRL, 0x00004714);
	SSP_WRITE_REG(SSP_TX_SLOT_VALID0, 0x00000001);
	SSP_WRITE_REG(SSP_TX_SLOT_VALID1, 0x00000000);
	SSP_WRITE_REG(SSP_TX_SLOT_VALID2, 0x00000000);
	SSP_WRITE_REG(SSP_TX_SLOT_VALID3, 0x00000000);
	SSP_WRITE_REG(SSP_RX_SLOT_VALID0, 0x00000001);
	SSP_WRITE_REG(SSP_RX_SLOT_VALID1, 0x00000000);
	SSP_WRITE_REG(SSP_RX_SLOT_VALID2, 0x00000000);
	SSP_WRITE_REG(SSP_RX_SLOT_VALID3, 0x00000000);
	SSP_WRITE_REG(SSP_SLOT_SIZE0, 0xffffffff);
	SSP_WRITE_REG(SSP_SLOT_SIZE1, 0xffffffff);
	SSP_WRITE_REG(SSP_SLOT_SIZE2, 0xffffffff);
	SSP_WRITE_REG(SSP_SLOT_SIZE3, 0xffffffff);
	SSP_WRITE_REG(SSP_CTRL_STATUS, 0x1F100000);//0x9F100000
	mdelay(250);
	SSP_WRITE_REG(SSP_CTRL_STATUS, 0x00100000);//0x80100000

}

void ssp_led_ctl(unsigned char duty)
{
	unsigned int val;

	val = SSP_READ_REG(SSP_FRAME_CTRL2);//0x0003800f
	val &= ~0x7F;
	val |= (duty&0x7F);
	SSP_WRITE_REG(SSP_FRAME_CTRL2, val);//0x0003800f
}

extern unsigned int get_random_int(void);
unsigned long ssp_led_get_random_timeout_value(void)
{
    unsigned long val;
    val = get_random_int() % (1*HZ);
    return val;
}/**/
unsigned char ssp_led_get_duty_cycle(void)
{
	
	static int retval=1;

    switch(ssp_led_curr_state) {
        case GEMINI_SSP_LED_SET_DUTY_CYCLE:// Set LED duty cycle
             timeout =GEMINI_SSP_LED_DEFAULT_TIMEOUT;
             retval=ioctl_data;	     
            break;
        case GEMINI_SSP_LED_START_BOOT:
	    if (ssp_led_on_off_flag &1){
                   timeout =GEMINI_SSP_LED_START_BOOT_LED_ON_MSEC;
                   retval=GEMINI_SSP_LED_ON;
	    }else{
                  timeout=GEMINI_SSP_LED_START_BOOT_LED_OFF_MSEC;
		    retval=GEMINI_SSP_LED_OFF;
	    }
            break;
        case GEMINI_SSP_LED_END_BOOT:
             timeout =GEMINI_SSP_LED_DEFAULT_TIMEOUT;
             retval=GEMINI_SSP_LED_ON;
            break;
        case GEMINI_SSP_LED_START_BACKUP:
	     timeout = 10; /*100ms*/
            retval=0x7f - (ssp_led_get_random_timeout_value() %20);		 
            break;
        case GEMINI_SSP_LED_SLIENT_BACKUP:
             timeout =GEMINI_SSP_LED_DEFAULT_TIMEOUT;
             retval=GEMINI_SSP_LED_OFF;	     
            break;
        case GEMINI_SSP_LED_END_BACKUP:
             timeout =GEMINI_SSP_LED_DEFAULT_TIMEOUT;
             retval=GEMINI_SSP_LED_ON;			
            break;
        case GEMINI_SSP_LED_WAIT_STATE:
             timeout =GEMINI_SSP_LED_DEFAULT_TIMEOUT;
             retval=GEMINI_SSP_LED_ON;		
            break;
        case GEMINI_SSP_LED_NETWORK_CONNECT:
             timeout =GEMINI_SSP_LED_DEFAULT_TIMEOUT;
             retval=GEMINI_SSP_LED_ON;
		ssp_led_curr_state =	ssp_led_saved_state;			
            break;
        case GEMINI_SSP_LED_NETWORK_DISCONNECT:
	    if (ssp_led_on_off_flag &1){
                   timeout =GEMINI_SSP_LED_NETWORK_DISCONNECT_LED_ON_MSEC;
                   retval=GEMINI_SSP_LED_ON;
	    }else{
                  timeout=GEMINI_SSP_LED_NETWORK_DISCONNECT_LED_OFF_MSEC;
		    retval=GEMINI_SSP_LED_OFF;
	    }			
            break;
        case GEMINI_SSP_LED_ERROR_STATE:
 	    if (ssp_led_on_off_flag &1){
                   timeout =GEMINI_SSP_LED_ERROR_STATE_LED_ON_MSEC;
                   retval=GEMINI_SSP_LED_ON;
	    }else{
                  timeout=GEMINI_SSP_LED_ERROR_STATE_LED_OFF_MSEC;
		    retval=GEMINI_SSP_LED_OFF;
	    }			
           break;
        case GEMINI_SSP_LED_PASSWORD_RESET:
 	    if (ssp_led_on_off_flag &1){
                   timeout =GEMINI_SSP_LED_PASSWORD_RESET_LED_ON_MSEC;
                   retval=GEMINI_SSP_LED_ON;
	    }else{
                  timeout=GEMINI_SSP_LED_PASSWORD_RESET_LED_OFF_MSEC;
		    retval=GEMINI_SSP_LED_OFF;
	    }			
           break;
        case GEMINI_SSP_LED_FACTORY_RESET:
 	    if (ssp_led_on_off_flag &1){
                   timeout =GEMINI_SSP_LED_FACTORY_RESET_LED_ON_MSEC;
                   retval=GEMINI_SSP_LED_ON;
	    }else{
                  timeout=GEMINI_SSP_LED_FACTORY_RESET_LED_OFF_MSEC;
		    retval=GEMINI_SSP_LED_OFF;
	    }			
           break;
        default:   
           retval = GEMINI_SSP_LED_ON;
    }/*switch*/
    ssp_led_on_off_flag++;
//printk("retval=%x\n", (unsigned char)retval);
return (unsigned char)retval;
}



pid_t ssp_led_pid;
wait_queue_head_t   ssp_led_thread_wait;
int blinking=0;   /*blinking flag*/
void ssp_led_thread(void *data)
{
	unsigned char duty;
	   
	printk("SSP LED Thread start\n");
	daemonize("ssp_led"); 
	allow_signal(SIGTERM);

	while (1)
	{
		duty = ssp_led_get_duty_cycle();
		ssp_led_ctl(duty);
		do
		{
			timeout = interruptible_sleep_on_timeout (&ssp_led_thread_wait, timeout);
		} while (!signal_pending (current) && (timeout > 0));
	
		if (signal_pending (current))
		{
			//			spin_lock_irq(&current->sigmask_lock);
			flush_signals(current);
			//			spin_unlock_irq(&current->sigmask_lock);
		}/*if*/
	} /*while*/
}


static int gemini_ssp_led_open(struct inode *inode, struct file *file)
{
	return 0;
}


static int gemini_ssp_led_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int gemini_ssp_led_ioctl(struct inode *inode, struct file *file,
    unsigned int cmd, unsigned long arg)
{
    if (copy_from_user(&ioctl_data, (int *)arg, sizeof(int)))
        return -EFAULT;
    printk("gemini_gpio ioctl :cmd=%u, data=%x\n", cmd,(unsigned char) ioctl_data);
	
    ssp_led_on_off_flag=1;
    switch(cmd) {
        case GEMINI_SSP_LED_SET_DUTY_CYCLE:// Set LED duty cycle
            ssp_led_ctl( (unsigned char) ioctl_data);
            break;
        case GEMINI_SSP_LED_START_BOOT:
            break;
        case GEMINI_SSP_LED_END_BOOT:
            break;
        case GEMINI_SSP_LED_START_BACKUP:
	     ssp_led_saved_state=cmd;
            break;
        case GEMINI_SSP_LED_SLIENT_BACKUP:
            break;
        case GEMINI_SSP_LED_END_BACKUP:
	     ssp_led_curr_state=ssp_led_saved_state;
	
            break;
        case GEMINI_SSP_LED_WAIT_STATE:
            break;
        case GEMINI_SSP_LED_NETWORK_CONNECT:
            break;
        case GEMINI_SSP_LED_NETWORK_DISCONNECT:
            break;
        case GEMINI_SSP_LED_ERROR_STATE:
            break;
        case GEMINI_SSP_LED_PASSWORD_RESET:
            break;
        case GEMINI_SSP_LED_FACTORY_RESET:
            break;
        default:
        return -ENOIOCTLCMD;
    }/*switch*/
    ssp_led_curr_state=cmd;

    return 0;
}




static struct file_operations gemini_ssp_led_fops = {
	.owner	=	THIS_MODULE,
	.ioctl	=	gemini_ssp_led_ioctl,
	.open	=	gemini_ssp_led_open,
	.release=	gemini_ssp_led_release,
};

/* SSP_LED_MINOR in include/linux/miscdevice.h */
static struct miscdevice gemini_ssp_led_miscdev =
{
	SSP_LED_MINOR,
	"ssp_led",
	&gemini_ssp_led_fops
};

 
int __init gemini_ssp_led_init(void)
{
	misc_register(&gemini_ssp_led_miscdev);
	printk("Gemini SSP LED init\n");

	ssp_led_init_ctl();

	init_waitqueue_head (&ssp_led_thread_wait);
	ssp_led_pid = kernel_thread ((void *)ssp_led_thread, NULL, CLONE_FS | CLONE_FILES);
	if (ssp_led_pid < 0)
    	{
    		printk ("Unable to start  ssp_led thread\n");
    	}
 	return 0;
}

void __exit gemini_ssp_led_exit(void)
{
	misc_deregister(&gemini_ssp_led_miscdev);
}

module_init(gemini_ssp_led_init);
module_exit(gemini_ssp_led_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Becker Hung <becker.hung@cortina-systems.com>");
MODULE_DESCRIPTION("Cortina SSP LED driver");

