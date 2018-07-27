#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
main()
{
        int fd = -1;
        int temp = 0;

        fd = open("/dev/FOTG2XX", O_RDWR);
        printf("fd = %d\r\n", fd);
        if (fd > 0)
        {
                temp = ioctl(fd, 5);
                printf("USB_driver_Flag_1 %x\n",temp);
                if (temp)
                {
                  system("rmmod ehci_hcd_FOTG2XX");
                  system("insmod ehci-hcd-FOTG2XX.ko");
                }
                
        }
        
        int fd_1 = -1; int temp1 = 0;

        fd_1 = open("/dev/FOTG2XX_1", O_RDWR);
        printf("fd_1 = %d\r\n", fd_1);
        if (fd_1 > 0)
        {
                temp1 = ioctl(fd_1, 5);
                printf("USB_driver_Flag_1 %x\n",temp1);
                if (temp1)
                {
                  system("rmmod ehci_hcd_FOTG2XX_1");
                  system("insmod ehci-hcd-FOTG2XX_1.ko");
                }
                
        }
}
