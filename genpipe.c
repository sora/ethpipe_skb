#include <linux/semaphore.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/version.h>

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/errno.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>

#include <linux/if_packet.h>

#define VERSION "0.0.0"

/* module parameters */
static int debug = 0;

#define _SKP  0x20

static const unsigned char _atob[] = {
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 0-7 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 8-15 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 16-23 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 24-31 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 32-39 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 40-47 */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,     /* 48-55 */
	0x08, 0x09, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 56-63 */
	_SKP, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, _SKP,     /* 64-71 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 72-79 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 80-87 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 88-95 */
	_SKP, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, _SKP,     /* 96-103 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 104-111 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 112-119 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 120-127 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 128-135 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 136-143 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 144-151 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 152-159 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 160-167 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 168-175 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 176-183 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 184-191 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 192-199 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 200-207 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 208-215 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 216-223 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 224-231 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 232-239 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP,     /* 240-247 */
	_SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP, _SKP };   /* 248-255 */

static const short _btoa[] = {
	0x3030, 0x3130, 0x3230, 0x3330, 0x3430, 0x3530, 0x3630, 0x3730,     /* 0-7 */
	0x3830, 0x3930, 0x4130, 0x4230, 0x4330, 0x4430, 0x4530, 0x4630,     /* 8-15 */
	0x3031, 0x3131, 0x3231, 0x3331, 0x3431, 0x3531, 0x3631, 0x3731,     /* 16-23 */
	0x3831, 0x3931, 0x4131, 0x4231, 0x4331, 0x4431, 0x4531, 0x4631,     /* 24-31 */
	0x3032, 0x3132, 0x3232, 0x3332, 0x3432, 0x3532, 0x3632, 0x3732,     /* 32-39 */
	0x3832, 0x3932, 0x4132, 0x4232, 0x4332, 0x4432, 0x4532, 0x4632,     /* 40-47 */
	0x3033, 0x3133, 0x3233, 0x3333, 0x3433, 0x3533, 0x3633, 0x3733,     /* 48-55 */
	0x3833, 0x3933, 0x4133, 0x4233, 0x4333, 0x4433, 0x4533, 0x4633,     /* 56-63 */
	0x3034, 0x3134, 0x3234, 0x3334, 0x3434, 0x3534, 0x3634, 0x3734,     /* 64-71 */
	0x3834, 0x3934, 0x4134, 0x4234, 0x4334, 0x4434, 0x4534, 0x4634,     /* 72-79 */
	0x3035, 0x3135, 0x3235, 0x3335, 0x3435, 0x3535, 0x3635, 0x3735,     /* 80-87 */
	0x3835, 0x3935, 0x4135, 0x4235, 0x4335, 0x4435, 0x4535, 0x4635,     /* 88-95 */
	0x3036, 0x3136, 0x3236, 0x3336, 0x3436, 0x3536, 0x3636, 0x3736,     /* 96-103 */
	0x3836, 0x3936, 0x4136, 0x4236, 0x4336, 0x4436, 0x4536, 0x4636,     /* 104-111 */
	0x3037, 0x3137, 0x3237, 0x3337, 0x3437, 0x3537, 0x3637, 0x3737,     /* 112-119 */
	0x3837, 0x3937, 0x4137, 0x4237, 0x4337, 0x4437, 0x4537, 0x4637,     /* 120-127 */
	0x3038, 0x3138, 0x3238, 0x3338, 0x3438, 0x3538, 0x3638, 0x3738,     /* 128-135 */
	0x3838, 0x3938, 0x4138, 0x4238, 0x4338, 0x4438, 0x4538, 0x4638,     /* 136-143 */
	0x3039, 0x3139, 0x3239, 0x3339, 0x3439, 0x3539, 0x3639, 0x3739,     /* 144-151 */
	0x3839, 0x3939, 0x4139, 0x4239, 0x4339, 0x4439, 0x4539, 0x4639,     /* 152-159 */
	0x3041, 0x3141, 0x3241, 0x3341, 0x3441, 0x3541, 0x3641, 0x3741,     /* 160-167 */
	0x3841, 0x3941, 0x4141, 0x4241, 0x4341, 0x4441, 0x4541, 0x4641,     /* 168-175 */
	0x3042, 0x3142, 0x3242, 0x3342, 0x3442, 0x3542, 0x3642, 0x3742,     /* 176-183 */
	0x3842, 0x3942, 0x4142, 0x4242, 0x4342, 0x4442, 0x4542, 0x4642,     /* 184-191 */
	0x3043, 0x3143, 0x3243, 0x3343, 0x3443, 0x3543, 0x3643, 0x3743,     /* 192-199 */
	0x3843, 0x3943, 0x4143, 0x4243, 0x4343, 0x4443, 0x4543, 0x4643,     /* 200-207 */
	0x3044, 0x3144, 0x3244, 0x3344, 0x3444, 0x3544, 0x3644, 0x3744,     /* 208-215 */
	0x3844, 0x3944, 0x4144, 0x4244, 0x4344, 0x4444, 0x4544, 0x4644,     /* 216-223 */
	0x3045, 0x3145, 0x3245, 0x3345, 0x3445, 0x3545, 0x3645, 0x3745,     /* 224-231 */
	0x3845, 0x3945, 0x4145, 0x4245, 0x4345, 0x4445, 0x4545, 0x4645,     /* 232-239 */
	0x3046, 0x3146, 0x3246, 0x3346, 0x3446, 0x3546, 0x3646, 0x3746,     /* 240-247 */
	0x3846, 0x3946, 0x4146, 0x4246, 0x4346, 0x4446, 0x4546, 0x4646 };   /* 248-255 */

#ifndef	DRV_NAME
#define	DRV_NAME	"genpipe"
#endif
#ifndef	DRV_IDX
#define	DRV_IDX		(0)
#endif
#ifndef	IF_NAME
#define	IF_NAME		"eth0"
#endif

#ifndef	PACKET_BUF_MAX
#define	PACKET_BUF_MAX	(1024*1024)
#endif
#ifndef	MTU
#define	MTU		(9014)
#endif

static char *interface = IF_NAME;
module_param( interface , charp , S_IRUGO);
MODULE_PARM_DESC( interface, "interface" );

#define	INFO_SKB(X) \
printk( "len=%u,", X->len); \
printk( "data_len=%u,", X->data_len); \
printk( "mac_header=%x,", (unsigned int)X->mac_header); \
printk( "network_header=%x,", (unsigned int)X->network_header); \
printk( "transport_header=%x,", (unsigned int)X->transport_header); \
printk( "*head=%p,", X->head); \
printk( "*data=%p,", X->data); \
printk( "tail=%x,", (unsigned int)X->tail); \
printk( "end=%x\n", (unsigned int)X->end);

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,8,0)
#define	__devinit
#define	__devexit
#define	__devexit_p
#endif

static struct semaphore genpipe_sem;
static wait_queue_head_t write_q;
static wait_queue_head_t read_q;

/* receive and transmitte buffer */
struct _pbuf_dma {
	unsigned char   *rx_start_ptr;		/* rx buf start */
	unsigned char   *rx_end_ptr;		/* rx buf end */
	unsigned char   *rx_write_ptr;		/* rx write ptr */
	unsigned char   *rx_read_ptr;		/* rx read ptr */
	unsigned char   *tx_start_ptr;		/* tx buf start */
	unsigned char   *tx_end_ptr;		/* tx buf end */
	unsigned char   *tx_write_ptr;		/* tx write ptr */
	unsigned char   *tx_read_ptr;		/* tx read ptr */
} static pbuf0={0,0,0,0,0,0,0,0};

struct net_device* device = NULL;

int genpipe_pack_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *dev2)
{
	int i, frame_len;
	unsigned char *p;

	if (skb->pkt_type == PACKET_OUTGOING)	 // DROP loopback PACKET
		goto lend;

	frame_len = (skb->len)*3+31;

	if (debug) {
		pr_info( "Test protocol: Packet Received with length: %u\n", skb->len+18 );
	}

	if ( down_interruptible( &genpipe_sem ) ) {
		pr_info( "down_interruptible for read failed\n" );
		return -ERESTARTSYS;
	}

	if ( (pbuf0.rx_write_ptr + frame_len + 0x10) > pbuf0.rx_end_ptr ) {
		memcpy( pbuf0.rx_start_ptr, pbuf0.rx_read_ptr, (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr ));
		pbuf0.rx_write_ptr -= (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr );
		pbuf0.rx_read_ptr = pbuf0.rx_start_ptr;
	}

	p = skb_mac_header(skb);
	for ( i = 0; i < 14; ++i ) {
		*(unsigned short *)pbuf0.rx_write_ptr = _btoa[ p[i] ];
		pbuf0.rx_write_ptr += 2;
		if ( pbuf0.rx_write_ptr > pbuf0.rx_end_ptr )
			pbuf0.rx_write_ptr -= (pbuf0.rx_end_ptr - pbuf0.rx_start_ptr + 1);
		if ( i == 5 || i== 11 || i == 13 ) {
			*pbuf0.rx_write_ptr++ = ' ';
		}
	}
	p = skb->data;
	for ( i = 0; i < (skb->len) ; ++i) {
		*(unsigned short *)pbuf0.rx_write_ptr = _btoa[ p[i] ];
		pbuf0.rx_write_ptr += 2;
		if ( pbuf0.rx_write_ptr > pbuf0.rx_end_ptr )
			pbuf0.rx_write_ptr -= (pbuf0.rx_end_ptr - pbuf0.rx_start_ptr + 1);
		if ( likely( i != ((skb->len) - 1 ) ) ) {
			*pbuf0.rx_write_ptr++ = ' ';
		} else {
			*pbuf0.rx_write_ptr++ = '\n';
		}
		if ( pbuf0.rx_write_ptr > pbuf0.rx_end_ptr )
			pbuf0.rx_write_ptr -= (pbuf0.rx_end_ptr - pbuf0.rx_start_ptr + 1);
	}

	wake_up_interruptible( &read_q );

	up( &genpipe_sem );

lend:
	/* Don't mangle buffer if shared */
	if (!(skb = skb_share_check(skb, GFP_ATOMIC)))
		return 0;

	kfree_skb(skb);
	return skb->len;
}

static int genpipe_open(struct inode *inode, struct file *filp)
{
	if (debug) {
		pr_info( "%s\n", __func__ );
	}

	rtnl_lock();
	dev_set_promiscuity(device, 1);
	rtnl_unlock();

	return 0;
}

static ssize_t genpipe_read(struct file *filp, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int copy_len, available_read_len;

	if (debug) {
		pr_info( "%s\n", __func__ );
	}

	if ( wait_event_interruptible( read_q, ( pbuf0.rx_read_ptr != pbuf0.rx_write_ptr ) ) )
		return -ERESTARTSYS;

	available_read_len = (pbuf0.rx_write_ptr - pbuf0.rx_read_ptr);

	if ( count > available_read_len )
		copy_len = available_read_len;
	else
		copy_len = count;

	if ( copy_to_user( buf, pbuf0.rx_read_ptr, copy_len ) ) {
		pr_info( "copy_to_user failed\n" );
		return -EFAULT;
	}

	pbuf0.rx_read_ptr += copy_len;

	return copy_len;
}

/* from af_packet.c */
static int packet_direct_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	const struct net_device_ops *ops = dev->netdev_ops;
	netdev_features_t features;
	struct netdev_queue *txq;
	int ret = NETDEV_TX_BUSY;
	u16 queue_map;

	if (unlikely(!netif_running(dev) || !netif_carrier_ok(dev)))
		goto drop;

	features = netif_skb_features(skb);
	if (skb_needs_linearize(skb, features) && __skb_linearize(skb))
		goto drop;

	queue_map = skb_get_queue_mapping(skb);
	txq = netdev_get_tx_queue(dev, queue_map);

	local_bh_disable();

	HARD_TX_LOCK(dev, txq, smp_processor_id());
	if (!netif_xmit_frozen_or_drv_stopped(txq)) {
		ret = ops->ndo_start_xmit(skb, dev);
		if (ret == NETDEV_TX_OK)
			txq_trans_update(txq);
	}
	HARD_TX_UNLOCK(dev, txq);

	local_bh_enable();

	if (!dev_xmit_complete(ret))
		kfree_skb(skb);

	return ret;
drop:
	atomic_long_inc(&dev->tx_dropped);
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

static ssize_t genpipe_write(struct file *filp, const char __user *buf,
			    size_t count, loff_t *ppos)

{
	int i, copy_len, ret, frame_len, data, data2;
	struct sk_buff *tx_skb;
	unsigned char *cr;
	static unsigned char tmp_pkt[MTU+14]={0};

	copy_len = 0;
	tx_skb = NULL;

	if ( (pbuf0.tx_write_ptr +  count) > pbuf0.tx_end_ptr ) {
		memcpy( pbuf0.tx_start_ptr, pbuf0.tx_read_ptr, (pbuf0.tx_write_ptr - pbuf0.tx_start_ptr ));
		pbuf0.tx_write_ptr -= (pbuf0.tx_write_ptr - pbuf0.tx_start_ptr );
		pbuf0.tx_read_ptr = pbuf0.tx_start_ptr;
		if ( pbuf0.tx_read_ptr < pbuf0.tx_start_ptr )
			pbuf0.tx_read_ptr = pbuf0.tx_start_ptr;
	}

	if ( count > (pbuf0.tx_end_ptr - pbuf0.tx_write_ptr))
		count = (pbuf0.tx_end_ptr - pbuf0.tx_write_ptr);

	if (debug) {
		pr_info( "%s count=%d\n", __func__, (int)count );
	}

	if ( copy_from_user( pbuf0.tx_write_ptr, buf, count ) ) {
		pr_info( "copy_from_user failed\n" );
		return -EFAULT;
	}

	pbuf0.tx_write_ptr += count;
	copy_len = count;

genpipe_write_loop:
	for ( cr = pbuf0.tx_read_ptr; cr < pbuf0.tx_write_ptr && *cr != '\n'; ++cr );
	if ( cr == pbuf0.tx_write_ptr )	/* not found CR */
		goto genpipe_write_exit;

	if (debug) {
		pr_info( "pbuf0.tx_read_ptr=%s\n", pbuf0.tx_read_ptr );
	}

	frame_len = 0;

	for ( ; pbuf0.tx_read_ptr < cr && frame_len < MTU ; ++pbuf0.tx_read_ptr ) {

		// skip space
		if ( (data = *pbuf0.tx_read_ptr) == ' ')
			continue;

		// ascii to number
		data2 = *(++pbuf0.tx_read_ptr);
		if (_atob[data] != _SKP && _atob[data2] != _SKP) {
			tmp_pkt[frame_len+14] = (_atob[data] << 4) | _atob[data2];
			++frame_len;
		}
	}

	if (debug) {
		pr_info(
			"%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %02x%02x %02x %02x\n",
			tmp_pkt[14], tmp_pkt[15], tmp_pkt[16], tmp_pkt[17], tmp_pkt[18],
			tmp_pkt[19], tmp_pkt[20], tmp_pkt[21], tmp_pkt[22], tmp_pkt[23],
			tmp_pkt[24], tmp_pkt[25], tmp_pkt[26], tmp_pkt[27], tmp_pkt[27],
			tmp_pkt[28] );
	}

	tx_skb = netdev_alloc_skb_ip_align(device, frame_len+14);
	skb_reserve(tx_skb, 2);	/* align IP on 16B boundary */
	if (likely(tx_skb)) {

		if (debug) {
			INFO_SKB(tx_skb);
		}

		skb_reset_mac_header(tx_skb);
		skb_reset_transport_header(tx_skb);
		skb_reset_network_header(tx_skb);
		memcpy(skb_put(tx_skb, frame_len+14), tmp_pkt, frame_len+14);
		skb_set_network_header(tx_skb,38);

		if (debug) {
			INFO_SKB(tx_skb);
		}

#if 0
		tx_skb->dev = device;
		tx_skb->protocol = eth_type_trans(tx_skb, device);
		ret = dev_queue_xmit(tx_skb);
		if (ret) {
			pr_info( "fail to dev_queue_xmit=%d\n", ret );
		}
#endif
		// xmit
		tx_skb->dev = device;
		tx_skb->protocol = eth_type_trans(tx_skb, device);
		ret = packet_direct_xmit(tx_skb);
		if (ret) {
			pr_info( "fail packet_direct_xmit=%d\n", ret );
		}
	}

	pbuf0.tx_read_ptr = cr + 1;

	i = (pbuf0.tx_read_ptr - pbuf0.tx_start_ptr );
	if (i > 0) {
		memcpy( pbuf0.tx_start_ptr, pbuf0.tx_read_ptr, ( pbuf0.tx_write_ptr - pbuf0.tx_read_ptr ) );
		pbuf0.tx_read_ptr -= i;
		pbuf0.tx_write_ptr -= i;
	}

	goto genpipe_write_loop;

genpipe_write_exit:

	return copy_len;
}

static int genpipe_release(struct inode *inode, struct file *filp)
{
	if (debug) {
		pr_info( "%s\n", __func__ );
	}

	rtnl_lock();
	dev_set_promiscuity(device, -1);
	rtnl_unlock();

	return 0;
}

static unsigned int genpipe_poll( struct file* filp, poll_table* wait )
{
	unsigned int retmask = 0;

	if (debug) {
		pr_info("%s\n", __func__);
	}

	poll_wait( filp, &read_q,  wait );
//	poll_wait( filp, &write_q, wait );

	if ( pbuf0.rx_read_ptr != pbuf0.rx_write_ptr ) {
		retmask |= ( POLLIN  | POLLRDNORM );
//		log_format( "POLLIN  | POLLRDNORM" );
	}
/*
   読み込みデバイスが EOF の場合は retmask に POLLHUP を設定
   デバイスがエラー状態である場合は POLLERR を設定
   out-of-band データが読み出せる場合は POLLPRI を設定
 */

	return retmask;
}


static long genpipe_ioctl(struct file *filp,
			unsigned int cmd, unsigned long arg)
{
	pr_info( "%s\n", __func__ );

	return  -ENOTTY;
}

static struct file_operations genpipe_fops = {
	.owner		= THIS_MODULE,
	.read		= genpipe_read,
	.write		= genpipe_write,
	.poll		= genpipe_poll,
	.compat_ioctl	= genpipe_ioctl,
	.open		= genpipe_open,
	.release	= genpipe_release,
};

static struct miscdevice genpipe_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DRV_NAME,
	.fops = &genpipe_fops,
};

static struct packet_type genpipe_pack =
{
	__constant_htons(ETH_P_ALL),
	NULL,
	genpipe_pack_rcv,

	(void *) 1,
	NULL
};

static int __init genpipe_init(void)
{
	int ret;
	static char name[16];

	pr_info( "%s\n", __func__ );

	device = dev_get_by_name(&init_net, interface);
	if ( !device ) {
		pr_warn( "Could not find %s\n", interface );
		ret = -1;
		goto error;
	}

	/* Set receive buffer */
	if ( ( pbuf0.rx_start_ptr = kmalloc(PACKET_BUF_MAX, GFP_KERNEL) ) == 0 ) {
		pr_info( "fail to kmalloc\n" );
		ret = -1;
		goto error;
	}
	pbuf0.rx_end_ptr = (pbuf0.rx_start_ptr + PACKET_BUF_MAX - 1);
	pbuf0.rx_write_ptr = pbuf0.rx_start_ptr;
	pbuf0.rx_read_ptr  = pbuf0.rx_start_ptr;

	/* Set transmitte buffer */
	if ( ( pbuf0.tx_start_ptr = kmalloc(PACKET_BUF_MAX, GFP_KERNEL) ) == 0 ) {
		pr_info( "fail to kmalloc\n" );
		ret = -1;
		goto error;
	}
	pbuf0.tx_end_ptr = (pbuf0.tx_start_ptr + PACKET_BUF_MAX - 1);
	pbuf0.tx_write_ptr = pbuf0.tx_start_ptr;
	pbuf0.tx_read_ptr  = pbuf0.tx_start_ptr;

	/* register character device */
	sprintf( name, "%s/%d", DRV_NAME, DRV_IDX );
	genpipe_dev.name = name;
	ret = misc_register(&genpipe_dev);
	if (ret) {
		pr_info( "fail to misc_register (MISC_DYNAMIC_MINOR)\n" );
		goto error;
	}

	sema_init( &genpipe_sem, 1 );
	init_waitqueue_head( &read_q );
	init_waitqueue_head( &write_q );

	genpipe_pack.dev = device;
	dev_add_pack(&genpipe_pack);

	return 0;

error:
	if ( pbuf0.rx_start_ptr ) {
		kfree( pbuf0.rx_start_ptr );
		pbuf0.rx_start_ptr = NULL;
	}

	if ( pbuf0.tx_start_ptr ) {
		kfree( pbuf0.tx_start_ptr );
		pbuf0.tx_start_ptr = NULL;
	}

	return ret;
}

static void __exit genpipe_cleanup(void)
{
	pr_info( "%s\n", __func__ );

	misc_deregister(&genpipe_dev);

	dev_remove_pack(&genpipe_pack);

	if ( pbuf0.rx_start_ptr ) {
		kfree( pbuf0.rx_start_ptr );
		pbuf0.rx_start_ptr = NULL;
	}

	if ( pbuf0.tx_start_ptr ) {
		kfree( pbuf0.tx_start_ptr );
		pbuf0.tx_start_ptr = NULL;
	}
}

module_init(genpipe_init);
module_exit(genpipe_cleanup);

MODULE_AUTHOR("Yohei Kuga <sora@haeena.net>");
MODULE_DESCRIPTION("Ethernet Character device");
MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);
module_param(debug, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug, "Enable debug mode");
