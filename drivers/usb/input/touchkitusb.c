/******************************************************************************
 * touchkitusb.c  --  Driver for eGalax TouchKit USB Touchscreens
 *
 * Copyright (C) 2004 by Daniel Ritz
 * Copyright (C) by Todd E. Johnson (mtouchusb.c)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Based upon mtouchusb.c
 *
 *****************************************************************************/

//#define DEBUG

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/usb.h>
#include <linux/usb_input.h>

#define TOUCHKIT_MIN_XC			0x0
#define TOUCHKIT_MAX_XC			0x07ff
#define TOUCHKIT_XC_FUZZ		0x0
#define TOUCHKIT_XC_FLAT		0x0
#define TOUCHKIT_MIN_YC			0x0
#define TOUCHKIT_MAX_YC			0x07ff
#define TOUCHKIT_YC_FUZZ		0x0
#define TOUCHKIT_YC_FLAT		0x0
#define TOUCHKIT_REPORT_DATA_SIZE	8

#define TOUCHKIT_DOWN			0x01
#define TOUCHKIT_POINT_TOUCH		0x81
#define TOUCHKIT_POINT_NOTOUCH		0x80

#define TOUCHKIT_GET_TOUCHED(dat)	((((dat)[0]) & TOUCHKIT_DOWN) ? 1 : 0)
#define TOUCHKIT_GET_X(dat)		(((dat)[3] << 7) | (dat)[4])
#define TOUCHKIT_GET_Y(dat)		(((dat)[1] << 7) | (dat)[2])

#define DRIVER_VERSION			"v0.1"
#define DRIVER_AUTHOR			"Daniel Ritz <daniel.ritz@gmx.ch>"
#define DRIVER_DESC			"eGalax TouchKit USB HID Touchscreen Driver"

static int swap_xy;
module_param(swap_xy, bool, 0644);
MODULE_PARM_DESC(swap_xy, "If set X and Y axes are swapped.");

struct touchkit_usb {
	unsigned char *data;
	dma_addr_t data_dma;
	struct urb *irq;
	struct usb_device *udev;
	struct input_dev *input;
	char name[128];
	char phys[64];
};

static struct usb_device_id touchkit_devices[] = {
	{USB_DEVICE(0x3823, 0x0001)},
	{USB_DEVICE(0x0123, 0x0001)},
	{USB_DEVICE(0x0eef, 0x0001)},
	{USB_DEVICE(0x0eef, 0x0002)},
	{}
};

static void touchkit_irq(struct urb *urb, struct pt_regs *regs)
{
	struct touchkit_usb *touchkit = urb->context;
	int retval;
	int x, y;

	switch (urb->status) {
	case 0:
		/* success */
		break;
	case -ETIMEDOUT:
		/* this urb is timing out */
		dbg("%s - urb timed out - was the device unplugged?",
		    __FUNCTION__);
		return;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
		/* this urb is terminated, clean up */
		dbg("%s - urb shutting down with status: %d",
		    __FUNCTION__, urb->status);
		return;
	default:
		dbg("%s - nonzero urb status received: %d",
		    __FUNCTION__, urb->status);
		goto exit;
	}

	if (swap_xy) {
		y = TOUCHKIT_GET_X(touchkit->data);
		x = TOUCHKIT_GET_Y(touchkit->data);
	} else {
		x = TOUCHKIT_GET_X(touchkit->data);
		y = TOUCHKIT_GET_Y(touchkit->data);
	}

	input_regs(touchkit->input, regs);
	input_report_key(touchkit->input, BTN_TOUCH,
	                 TOUCHKIT_GET_TOUCHED(touchkit->data));
	input_report_abs(touchkit->input, ABS_X, x);
	input_report_abs(touchkit->input, ABS_Y, y);
	input_sync(touchkit->input);

exit:
	retval = usb_submit_urb(urb, GFP_ATOMIC);
	if (retval)
		err("%s - usb_submit_urb failed with result: %d",
		    __FUNCTION__, retval);
}

static int touchkit_open(struct input_dev *input)
{
	struct touchkit_usb *touchkit = input->private;

	touchkit->irq->dev = touchkit->udev;

	if (usb_submit_urb(touchkit->irq, GFP_ATOMIC))
		return -EIO;

	return 0;
}

static void touchkit_close(struct input_dev *input)
{
	struct touchkit_usb *touchkit = input->private;

	usb_kill_urb(touchkit->irq);
}

static int touchkit_alloc_buffers(struct usb_device *udev,
				  struct touchkit_usb *touchkit)
{
	touchkit->data = usb_buffer_alloc(udev, TOUCHKIT_REPORT_DATA_SIZE,
	                                  SLAB_ATOMIC, &touchkit->data_dma);

	if (!touchkit->data)
		return -1;

	return 0;
}

static void touchkit_free_buffers(struct usb_device *udev,
				  struct touchkit_usb *touchkit)
{
	if (touchkit->data)
		usb_buffer_free(udev, TOUCHKIT_REPORT_DATA_SIZE,
		                touchkit->data, touchkit->data_dma);
}

static int touchkit_probe(struct usb_interface *intf,
			  const struct usb_device_id *id)
{
	struct touchkit_usb *touchkit;
	struct input_dev *input_dev;
	struct usb_host_interface *interface;
	struct usb_endpoint_descriptor *endpoint;
	struct usb_device *udev = interface_to_usbdev(intf);

	interface = intf->cur_altsetting;
	endpoint = &interface->endpoint[0].desc;

//	printk("*****>>>>> touchkit_probe\n");

	touchkit = kzalloc(sizeof(struct touchkit_usb), GFP_KERNEL);
	input_dev = input_allocate_device();
	if (!touchkit || !input_dev)
		goto out_free;

	if (touchkit_alloc_buffers(udev, touchkit))
		goto out_free;

	touchkit->irq = usb_alloc_urb(0, GFP_KERNEL);
	if (!touchkit->irq) {
		dbg("%s - usb_alloc_urb failed: touchkit->irq", __FUNCTION__);
		goto out_free_buffers;
	}

	touchkit->udev = udev;
	touchkit->input = input_dev;

	if (udev->manufacturer)
		strlcpy(touchkit->name, udev->manufacturer, sizeof(touchkit->name));

	if (udev->product) {
		if (udev->manufacturer)
			strlcat(touchkit->name, " ", sizeof(touchkit->name));
		strlcat(touchkit->name, udev->product, sizeof(touchkit->name));
	}

	if (!strlen(touchkit->name))
		snprintf(touchkit->name, sizeof(touchkit->name),
			"USB Touchscreen %04x:%04x",
			 le16_to_cpu(udev->descriptor.idVendor),
			 le16_to_cpu(udev->descriptor.idProduct));

	usb_make_path(udev, touchkit->phys, sizeof(touchkit->phys));
	strlcpy(touchkit->phys, "/input0", sizeof(touchkit->phys));

	input_dev->name = touchkit->name;
	input_dev->phys = touchkit->phys;
	usb_to_input_id(udev, &input_dev->id);
	input_dev->cdev.dev = &intf->dev;
	input_dev->private = touchkit;
	input_dev->open = touchkit_open;
	input_dev->close = touchkit_close;

	input_dev->evbit[0] = BIT(EV_KEY) | BIT(EV_ABS);
	input_dev->keybit[LONG(BTN_TOUCH)] = BIT(BTN_TOUCH);
	input_set_abs_params(input_dev, ABS_X, TOUCHKIT_MIN_XC, TOUCHKIT_MAX_XC,
				TOUCHKIT_XC_FUZZ, TOUCHKIT_XC_FLAT);
	input_set_abs_params(input_dev, ABS_Y, TOUCHKIT_MIN_YC, TOUCHKIT_MAX_YC,
				TOUCHKIT_YC_FUZZ, TOUCHKIT_YC_FLAT);

	usb_fill_int_urb(touchkit->irq, touchkit->udev,
			 usb_rcvintpipe(touchkit->udev, 0x81),
			 touchkit->data, TOUCHKIT_REPORT_DATA_SIZE,
			 touchkit_irq, touchkit, endpoint->bInterval);

	input_register_device(touchkit->input);

	usb_set_intfdata(intf, touchkit);
//	printk("*****>>>>> touchkit_probe: good\n");
	return 0;

out_free_buffers:
	touchkit_free_buffers(udev, touchkit);
out_free:
	input_free_device(input_dev);
	kfree(touchkit);
//	printk("*****>>>>> touchkit_probe fail\n");
	return -ENOMEM;
}

static void touchkit_disconnect(struct usb_interface *intf)
{
	struct touchkit_usb *touchkit = usb_get_intfdata(intf);

//	printk("*****>>>>> touchkit_disconnect\n");

	dbg("%s - called", __FUNCTION__);

	if (!touchkit)
		return;

	dbg("%s - touchkit is initialized, cleaning up", __FUNCTION__);
	usb_set_intfdata(intf, NULL);
	usb_kill_urb(touchkit->irq);
	input_unregister_device(touchkit->input);
	usb_free_urb(touchkit->irq);
	touchkit_free_buffers(interface_to_usbdev(intf), touchkit);
	kfree(touchkit);
}

MODULE_DEVICE_TABLE(usb, touchkit_devices);

static struct usb_driver touchkit_driver = {
	.owner		= THIS_MODULE,
	.name		= "touchkitusb",
	.probe		= touchkit_probe,
	.disconnect	= touchkit_disconnect,
	.id_table	= touchkit_devices,
};

static int __init touchkit_init(void)
{
//	printk("*****>>>>> touchkit_init\n");
	return usb_register(&touchkit_driver);
}

static void __exit touchkit_cleanup(void)
{
//	printk("*****>>>>> touchkit_cleanup\n");
	usb_deregister(&touchkit_driver);
}

module_init(touchkit_init);
module_exit(touchkit_cleanup);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL");