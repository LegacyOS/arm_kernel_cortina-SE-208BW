/*
 * Cryptographic API.
 *
 * Cipher operations.p
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * Copyright (c) 2005 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

//debug_Aaron
#include <asm/delay.h>
#include <asm/scatterlist.h>
#include "internal.h"
#include "scatterwalk.h"

#ifdef CONFIG_SL2312_IPSEC 
#include <asm/arch/sl2312_ipsec.h>
#include <linux/dma-mapping.h>
#include <asm/hardware.h>
#include <asm/io.h>
#include <linux/sysctl_storlink.h>

#if 0 /* old implementation */
unsigned long crypto_flags;
#define     IPSEC_TEXT_LEN    32768 //2048
unsigned char p[IPSEC_TEXT_LEN];
spinlock_t crypto_done_lock = SPIN_LOCK_UNLOCKED;
#endif
#define	RX_BUF_SEG_SIZE	RX_BUF_SIZE
unsigned int crypto_go = 0;
struct IPSEC_PACKET_S crypto_op;

#if 0
void crypto_callback(struct IPSEC_PACKET_S *op_info)
{
	spin_lock_irqsave(&crypto_done_lock,crypto_flags);
	spin_unlock_irqrestore(&crypto_done_lock, crypto_flags);
}
#endif
#endif

static inline void xor_64(u8 *a, const u8 *b)
{
	((u32 *)a)[0] ^= ((u32 *)b)[0];
	((u32 *)a)[1] ^= ((u32 *)b)[1];
}

static inline void xor_128(u8 *a, const u8 *b)
{
	((u32 *)a)[0] ^= ((u32 *)b)[0];
	((u32 *)a)[1] ^= ((u32 *)b)[1];
	((u32 *)a)[2] ^= ((u32 *)b)[2];
	((u32 *)a)[3] ^= ((u32 *)b)[3];
}

static unsigned int crypt_slow(const struct cipher_desc *desc,
			       struct scatter_walk *in,
			       struct scatter_walk *out, unsigned int bsize)
{
	unsigned long alignmask = crypto_tfm_alg_alignmask(desc->tfm);
	u8 buffer[bsize * 2 + alignmask];
	u8 *src = (u8 *)ALIGN((unsigned long)buffer, alignmask + 1);
	u8 *dst = src + bsize;
	unsigned int n;

	n = scatterwalk_copychunks(src, in, bsize, 0);
	scatterwalk_advance(in, n);

	desc->prfn(desc, dst, src, bsize);

	n = scatterwalk_copychunks(dst, out, bsize, 1);
	scatterwalk_advance(out, n);

	return bsize;
}

#ifdef CONFIG_SL2312_IPSEC
void hw_memcpy(char *to, char *from, unsigned long n)
{
        unsigned int p_to = __pa(to);
        unsigned int    p_from = __pa(from);

        consistent_sync(to,n,DMA_BIDIRECTIONAL);
        //consistent_sync(from,n,DMA_BIDIRECTIONAL);
        writel(p_from,IO_ADDRESS(SL2312_DRAM_CTRL_BASE)+0x24);  /* set source address */
        writel(p_to,IO_ADDRESS(SL2312_DRAM_CTRL_BASE)+0x28);    /* set destination address */
        writel(n,IO_ADDRESS(SL2312_DRAM_CTRL_BASE)+0x2c);     /* set byte count */
        wmb();
        writel(0x00000001,IO_ADDRESS(SL2312_DRAM_CTRL_BASE)+0x20);

        while (readl(IO_ADDRESS(SL2312_DRAM_CTRL_BASE)+0x20)==0x00000001);
}

struct scatterlist * alloc_scatterlist(unsigned int size, 
								unsigned int seg_size)
{
	struct scatterlist *result;
	void *buf;
	unsigned int seg_num, i, j, reminder;

	if (size > 65400) return NULL;

	reminder = size % seg_size;

	if (reminder == 0) seg_num = size / seg_size;
	else seg_num = (size - reminder) / seg_size + 1;

	result = (struct scatterlist*)kmalloc(sizeof(struct scatterlist)*seg_num, 
					GFP_ATOMIC);
	if (result == NULL) return NULL;

	for (i=0; i<seg_num; i++) {
		buf = kmalloc(seg_size, GFP_ATOMIC);

		if (buf == NULL) {
			for (j=0; j<i; j++)
				kfree((void*)(kmap(result[j].page) + result[j].offset));
			kfree(result);
			return NULL;
		}
		result[i].page = virt_to_page(buf);
		result[i].offset = offset_in_page(buf);
		if ((i == (seg_num - 1)) && (reminder != 0)) result[i].length = reminder;
		else result[i].length = seg_size;
	}

	return result;
}
EXPORT_SYMBOL(alloc_scatterlist);

int copy_scatterlist(struct scatterlist *src,
							struct scatterlist *dst,
							unsigned int size)
{
	unsigned int len = 0, copied_len;
	unsigned int src_page = 0, src_off = 0;
	unsigned int dst_page = 0, dst_off = 0;
	unsigned char *src_ptr, *dst_ptr;

	while (len < size) {
		if ((src[src_page].length <= 0) || (dst[dst_page].length <= 0))
			printk("%s::something is wrong!!\n", __func__);

		src_ptr = (unsigned char *)(kmap(src[src_page].page)+src[src_page].offset);
		dst_ptr = (unsigned char *)(kmap(dst[dst_page].page)+dst[dst_page].offset);
//		consistent_sync(src_ptr, src[src_page].length, DMA_BIDIRECTIONAL);
		copied_len = (src[src_page].length - src_off) > (dst[dst_page].length - dst_off) ? dst[dst_page].length - dst_off: src[src_page].length - src_off;

		memcpy(&dst_ptr[dst_off], &src_ptr[src_off], copied_len);
		len += copied_len;
		src_off += copied_len;
		dst_off += copied_len;
		if (src_off == src[src_page].length) {
			src_page++;
			src_off = 0;
		}
		if (dst_off == dst[dst_page].length) {
			dst_page++;
			dst_off = 0;
		}
	}
	return 0;
}
EXPORT_SYMBOL(copy_scatterlist);

int free_scatterlist(struct scatterlist *list, 
							unsigned int size)
{
	unsigned int len = 0, i = 0;

	if (list == NULL) return 0;

	while (len < size) {
		len += list[i].length;
		kfree((void*)(kmap(list[i].page) + list[i].offset));
		i++;
	}
	return 0;
}
EXPORT_SYMBOL(free_scatterlist);
#endif

static inline unsigned int crypt_fast(const struct cipher_desc *desc,
				      struct scatter_walk *in,
				      struct scatter_walk *out,
				      unsigned int nbytes, u8 *tmp)
{
	u8 *src, *dst;

	src = in->data;
	dst = scatterwalk_samebuf(in, out) ? src : out->data;

	if (tmp) {
		memcpy(tmp, in->data, nbytes);
		src = tmp;
		dst = tmp;
	}

	nbytes = desc->prfn(desc, dst, src, nbytes);

	if (tmp)
		memcpy(out->data, tmp, nbytes);

	scatterwalk_advance(in, nbytes);
	scatterwalk_advance(out, nbytes);

	return nbytes;
}

/* 
 * Generic encrypt/decrypt wrapper for ciphers, handles operations across
 * multiple page boundaries by using temporary blocks.  In user context,
 * the kernel is given a chance to schedule us once per page.
 */
static int crypt(const struct cipher_desc *desc,
		 struct scatterlist *dst,
		 struct scatterlist *src,
		 unsigned int nbytes)
{
	struct scatter_walk walk_in, walk_out;
	struct crypto_tfm *tfm = desc->tfm;
	const unsigned int bsize = crypto_tfm_alg_blocksize(tfm);
	unsigned int alignmask = crypto_tfm_alg_alignmask(tfm);
	unsigned long buffer = 0;

	if (!nbytes)
		return 0;

	if (nbytes % bsize) {
		tfm->crt_flags |= CRYPTO_TFM_RES_BAD_BLOCK_LEN;
		return -EINVAL;
	}

	scatterwalk_start(&walk_in, src);
	scatterwalk_start(&walk_out, dst);

	for(;;) {
		unsigned int n = nbytes;
		u8 *tmp = NULL;

		if (!scatterwalk_aligned(&walk_in, alignmask) ||
		    !scatterwalk_aligned(&walk_out, alignmask)) {
			if (!buffer) {
				buffer = __get_free_page(GFP_ATOMIC);
				if (!buffer)
					n = 0;
			}
			tmp = (u8 *)buffer;
		}

		scatterwalk_map(&walk_in, 0);
		scatterwalk_map(&walk_out, 1);

		n = scatterwalk_clamp(&walk_in, n);
		n = scatterwalk_clamp(&walk_out, n);

		if (likely(n >= bsize))
			n = crypt_fast(desc, &walk_in, &walk_out, n, tmp);
		else
			n = crypt_slow(desc, &walk_in, &walk_out, bsize);

		nbytes -= n;

		scatterwalk_done(&walk_in, 0, nbytes);
		scatterwalk_done(&walk_out, 1, nbytes);

		if (!nbytes)
			break;

		crypto_yield(tfm);
	}

	if (buffer)
		free_page(buffer);

	return 0;
}

static int crypt_iv_unaligned(struct cipher_desc *desc,
			      struct scatterlist *dst,
			      struct scatterlist *src,
			      unsigned int nbytes)
{
	struct crypto_tfm *tfm = desc->tfm;
	unsigned long alignmask = crypto_tfm_alg_alignmask(tfm);
	u8 *iv = desc->info;

	if (unlikely(((unsigned long)iv & alignmask))) {
		unsigned int ivsize = tfm->crt_cipher.cit_ivsize;
		u8 buffer[ivsize + alignmask];
		u8 *tmp = (u8 *)ALIGN((unsigned long)buffer, alignmask + 1);
		int err;

		desc->info = memcpy(tmp, iv, ivsize);
		err = crypt(desc, dst, src, nbytes);
		memcpy(iv, tmp, ivsize);

		return err;
	}

	return crypt(desc, dst, src, nbytes);
}

static unsigned int cbc_process_encrypt(const struct cipher_desc *desc,
					u8 *dst, const u8 *src,
					unsigned int nbytes)
{
	struct crypto_tfm *tfm = desc->tfm;
	void (*xor)(u8 *, const u8 *) = tfm->crt_u.cipher.cit_xor_block;
	int bsize = crypto_tfm_alg_blocksize(tfm);

	void (*fn)(void *, u8 *, const u8 *) = desc->crfn;
	u8 *iv = desc->info;
	unsigned int done = 0;

	nbytes -= bsize;

	do {
		xor(iv, src);
		fn(crypto_tfm_ctx(tfm), dst, iv);
		memcpy(iv, dst, bsize);

		src += bsize;
		dst += bsize;
	} while ((done += bsize) <= nbytes);

	return done;
}

static unsigned int cbc_process_decrypt(const struct cipher_desc *desc,
					u8 *dst, const u8 *src,
					unsigned int nbytes)
{
	struct crypto_tfm *tfm = desc->tfm;
	void (*xor)(u8 *, const u8 *) = tfm->crt_u.cipher.cit_xor_block;
	int bsize = crypto_tfm_alg_blocksize(tfm);

	u8 stack[src == dst ? bsize : 0];
	u8 *buf = stack;
	u8 **dst_p = src == dst ? &buf : &dst;

	void (*fn)(void *, u8 *, const u8 *) = desc->crfn;
	u8 *iv = desc->info;
	unsigned int done = 0;

	nbytes -= bsize;

	do {
		u8 *tmp_dst = *dst_p;

		fn(crypto_tfm_ctx(tfm), tmp_dst, src);
		xor(tmp_dst, iv);
		memcpy(iv, src, bsize);
		if (tmp_dst != dst)
			memcpy(dst, tmp_dst, bsize);

		src += bsize;
		dst += bsize;
	} while ((done += bsize) <= nbytes);

	return done;
}

static unsigned int ecb_process(const struct cipher_desc *desc, u8 *dst,
				const u8 *src, unsigned int nbytes)
{
	struct crypto_tfm *tfm = desc->tfm;
	int bsize = crypto_tfm_alg_blocksize(tfm);
	void (*fn)(void *, u8 *, const u8 *) = desc->crfn;
	unsigned int done = 0;

	nbytes -= bsize;

	do {
		fn(crypto_tfm_ctx(tfm), dst, src);

		src += bsize;
		dst += bsize;
	} while ((done += bsize) <= nbytes);

	return done;
}

static int setkey(struct crypto_tfm *tfm, const u8 *key, unsigned int keylen)
{
	struct cipher_alg *cia = &tfm->__crt_alg->cra_cipher;
	
	if (keylen < cia->cia_min_keysize || keylen > cia->cia_max_keysize) {
		tfm->crt_flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

#ifdef CONFIG_SL2312_IPSEC
	if (storlink_ctl.hw_crypto == 1) {
		/* get key & key length */
		crypto_op.cipher_key_size = keylen;
		memcpy(crypto_op.cipher_key,key,keylen);
	}
#endif

	return cia->cia_setkey(crypto_tfm_ctx(tfm), key, keylen,
	                       &tfm->crt_flags);
}

static int ecb_encrypt(struct crypto_tfm *tfm,
		       struct scatterlist *dst,
                       struct scatterlist *src, unsigned int nbytes)
{
#ifdef CONFIG_SL2312_IPSEC
	int hw_crypto_result = 0;
	struct scatterlist *out_buffer;
#if 0 /* old implementation */
	int i=0, len=0;
	unsigned char  *q;
#endif

	if (storlink_ctl.hw_crypto == 1) {
		if (crypto_go == 1)
			printk("%s::crypto engine is used by other process", __func__);

		crypto_go = 1;
		crypto_op.op_mode = CIPHER_ENC;
		crypto_op.cipher_algorithm = ipsec_get_cipher_algorithm((unsigned char *)tfm->__crt_alg->cra_name,ECB);
		crypto_op.cipher_header_len = 0;
		crypto_op.cipher_algorithm_len = nbytes;
//		memcpy(crypto_op.iv,tfm->crt_cipher.cit_iv,tfm->crt_cipher.cit_ivsize);
//		crypto_op.iv_size = tfm->crt_cipher.cit_ivsize;
		crypto_op.in_packet = src;
		crypto_op.pkt_len = nbytes;
		crypto_op.callback = NULL;

#if 0 /* old implementation */
		if(crypto_op.pkt_len > IPSEC_TEXT_LEN) {
			printk("%s :length too long !!\n",__func__);
			return -1;
		}
		crypto_op.out_packet2 = (u8 *)&p;
//		kmap(dst->page) + dst->offset;
		crypto_op.out_buffer_len = IPSEC_TEXT_LEN;
#endif
		out_buffer = alloc_scatterlist(nbytes, RX_BUF_SEG_SIZE);

		/* force hw crypto engine return fail before even calling it 
		 * because of memory allocation error */
		if (out_buffer == NULL) hw_crypto_result = 1;

		if (hw_crypto_result == 0) {
			crypto_op.out_packet = out_buffer;
			crypto_op.out_packet2 = NULL;
			crypto_op.out_buffer_len = nbytes;

			hw_crypto_result = ipsec_crypto_hw_process(&crypto_op);
			crypto_go = 0;

			if (hw_crypto_result == 0) {
#if 0 /* old implementation */
				len=0;
				i=0;
				while(len < nbytes){
					q = kmap(dst[i].page) + dst[i].offset;
					memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);
//					consistent_sync(p, nbytes, DMA_BIDIRECTIONAL);
					len+=dst[i].length;
					i++;
				};
#endif
				copy_scatterlist(out_buffer, dst, nbytes);
				free_scatterlist(out_buffer, nbytes);
				kfree((void*)out_buffer);
				memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
				return 0;
			}
		} else {
			//printk("%s::didn't go hw crypto engine at all\n", __func__);
		}
		crypto_go = 0;
		free_scatterlist(out_buffer, nbytes);
		kfree((void*)out_buffer);
		memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
	}
	if ((storlink_ctl.hw_crypto != 1) || (hw_crypto_result !=0))
#endif
	{
		struct cipher_desc desc;
		struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;

		desc.tfm = tfm;
		desc.crfn = cipher->cia_encrypt;
		desc.prfn = cipher->cia_encrypt_ecb ?: ecb_process;

		return crypt(&desc, dst, src, nbytes);
	}
	return 0;
}

static int ecb_decrypt(struct crypto_tfm *tfm,
                       struct scatterlist *dst,
                       struct scatterlist *src,
		       unsigned int nbytes)
{
#ifdef CONFIG_SL2312_IPSEC
	int hw_crypto_result = 0;
	struct scatterlist *out_buffer;
#if 0 /* old implementation */
	int i=0, len=0;
	unsigned char  *q;
#endif

	if (storlink_ctl.hw_crypto == 1) {
		if (crypto_go == 1)
			printk("%s::crypto engine is used by other process\n", __func__);

		crypto_go = 1;
		crypto_op.op_mode = CIPHER_DEC;
		crypto_op.cipher_algorithm = ipsec_get_cipher_algorithm((unsigned char *)tfm->__crt_alg->cra_name,ECB);;
		crypto_op.cipher_header_len = 0;
		crypto_op.cipher_algorithm_len = nbytes;
//		memcpy(crypto_op.iv,tfm->crt_cipher.cit_iv,tfm->crt_cipher.cit_ivsize);
//		crypto_op.iv_size = tfm->crt_cipher.cit_ivsize;
		crypto_op.in_packet = src;
		crypto_op.pkt_len = nbytes;

		crypto_op.callback = NULL;
#if 0 /* old implementation */
		if(crypto_op.pkt_len > IPSEC_TEXT_LEN) {
			printk("%s :length too long !!\n",__func__);
			return -1;
		}
		crypto_op.out_packet2 = (u8 *)&p; //kmap(dst->page) + dst->offset;
		crypto_op.out_buffer_len = IPSEC_TEXT_LEN;
#endif
		out_buffer = alloc_scatterlist(nbytes, RX_BUF_SEG_SIZE);

		if (out_buffer == NULL) hw_crypto_result = 1;

		if (hw_crypto_result == 0) {
			crypto_op.out_packet = out_buffer;
			crypto_op.out_packet2 = NULL;
			crypto_op.out_buffer_len = nbytes;

			hw_crypto_result = ipsec_crypto_hw_process(&crypto_op);

			if (hw_crypto_result == 0) {
#if 0 /* old implementation */
				len=0;
				i=0;
				while(len < nbytes) {
					q = kmap(dst[i].page) + dst[i].offset;
					memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);
//					consistent_sync(p, nbytes, DMA_BIDIRECTIONAL);
					len+=dst[i].length;
					i++;
				};
#endif
				copy_scatterlist(out_buffer, dst, nbytes);
				free_scatterlist(out_buffer, nbytes);
				kfree((void*)out_buffer);
				memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
				return 0;
			}
		} else {
			//printk("%s::didn't go hw crypto engine at all\n", __func__);
		}
		crypto_go = 0;
		free_scatterlist(out_buffer, nbytes);
		kfree((void*)out_buffer);
		memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
	}
	if ((storlink_ctl.hw_crypto != 1) || (hw_crypto_result != 0))
#endif
	{
		struct cipher_desc desc;
		struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;

		desc.tfm = tfm;
		desc.crfn = cipher->cia_decrypt;
		desc.prfn = cipher->cia_decrypt_ecb ?: ecb_process;

		return crypt(&desc, dst, src, nbytes);
	}
	return 0;
}

static int cbc_encrypt(struct crypto_tfm *tfm,
                       struct scatterlist *dst,
                       struct scatterlist *src,
		       unsigned int nbytes)
{
#ifdef CONFIG_SL2312_IPSEC
	int hw_crypto_result = 0;
	struct scatterlist *out_buffer;
#if 0 /* old implementation */
	int i=0, len=0;
	unsigned char *q;
#endif

	if (storlink_ctl.hw_crypto == 1) {
		if (crypto_go == 1)
			printk("%s::crypto engine is used by other process\n", __func__);

		crypto_go = 1;
		crypto_op.op_mode = CIPHER_ENC;
		crypto_op.cipher_algorithm = ipsec_get_cipher_algorithm((unsigned char *)&tfm->__crt_alg->cra_name,CBC);
		crypto_op.cipher_header_len = 0;
		crypto_op.cipher_algorithm_len = nbytes;
		memcpy(crypto_op.iv,tfm->crt_cipher.cit_iv,tfm->crt_cipher.cit_ivsize);

		crypto_op.iv_size = tfm->crt_cipher.cit_ivsize;
		crypto_op.in_packet = src;
		crypto_op.pkt_len = nbytes;
		crypto_op.callback = NULL;
#if 0 /* old implementation */
		if(crypto_op.pkt_len > IPSEC_TEXT_LEN) {
			printk("%s :length too long !!\n",__func__);
			return -1;
		}
		memset(&p, 0x0, IPSEC_TEXT_LEN);
		crypto_op.out_packet2 = (u8 *)&p;
		crypto_op.out_buffer_len = IPSEC_TEXT_LEN;
#endif
		out_buffer = alloc_scatterlist(nbytes, RX_BUF_SEG_SIZE);

		/* force hw crypto engine return fail before even calling it 
		 * because of memory allocation error */
		if (out_buffer == NULL) hw_crypto_result = 1;

		if (hw_crypto_result == 0) {
			crypto_op.out_packet = out_buffer;
			crypto_op.out_packet2 = NULL;
			crypto_op.out_buffer_len = nbytes;

			hw_crypto_result = ipsec_crypto_hw_process(&crypto_op);
			crypto_go = 0;

			if (hw_crypto_result == 0) {
#if 0	/* old implementation */
				len=0;
				i=0;
				while(len < nbytes){
					q = kmap(dst[i].page) + dst[i].offset;
					memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);
					//hw_memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);
					//consistent_sync(p, nbytes, DMA_BIDIRECTIONAL);

					len+=dst[i].length;
					i++;
				};
#endif
				copy_scatterlist(out_buffer, dst, nbytes);
				free_scatterlist(out_buffer, nbytes);
				kfree((void*)out_buffer);
				memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
				return 0;
			}
		} else {
			//printk("%s::didn't go hw crypto engine at all\n", __func__);
		}
		crypto_go = 0;
		free_scatterlist(out_buffer, nbytes);
		kfree((void*)out_buffer);
		memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
	}
	if ((storlink_ctl.hw_crypto != 1) || (hw_crypto_result != 0))
#endif
	{
		struct cipher_desc desc;
		struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;
		desc.tfm = tfm;
		desc.crfn = cipher->cia_encrypt;
		desc.prfn = cipher->cia_encrypt_cbc ?: cbc_process_encrypt;
		desc.info = tfm->crt_cipher.cit_iv;
		return crypt(&desc, dst, src, nbytes);
	}
	return 0;
}

static int cbc_encrypt_iv(struct crypto_tfm *tfm,
                          struct scatterlist *dst,
                          struct scatterlist *src,
                          unsigned int nbytes, u8 *iv)
{
#ifdef CONFIG_SL2312_IPSEC
	int hw_crypto_result = 0;
	struct scatterlist *out_buffer;
#if 0 /* old implementation */
	int i=0,len=0;
	unsigned char *q;
#endif

	if (storlink_ctl.hw_crypto == 1) {
		if(crypto_go == 1)
			printk("%s::crypto engine is used by other process\n", __func__);

		crypto_go = 1;
		crypto_op.op_mode = CIPHER_ENC;
		crypto_op.cipher_algorithm = ipsec_get_cipher_algorithm((unsigned char *)&tfm->__crt_alg->cra_name,CBC);
		crypto_op.cipher_header_len = 0;
		crypto_op.cipher_algorithm_len = nbytes;
		memcpy(crypto_op.iv,iv,tfm->crt_cipher.cit_ivsize);
		crypto_op.iv_size = tfm->crt_cipher.cit_ivsize;
		crypto_op.in_packet = src;
		crypto_op.pkt_len = nbytes;
		crypto_op.callback = NULL;

#if 0 /* old implementation */
		if(crypto_op.pkt_len > IPSEC_TEXT_LEN) {
			printk("%s :length too long !!\n",__func__);
			return -1;
		}
//		crypto_op.callback = crypto_callback;
		crypto_op.out_packet2 = (u8 *)&p;
		crypto_op.out_buffer_len = IPSEC_TEXT_LEN;
#endif
		out_buffer = alloc_scatterlist(nbytes, RX_BUF_SEG_SIZE);

		/* force hw crypto engine return fail before even calling it 
		 * because of memory allocation error */
		if (out_buffer == NULL) hw_crypto_result = 1;

		if (hw_crypto_result == 0) {
			crypto_op.out_packet = out_buffer;
			crypto_op.out_packet2 = NULL;
			crypto_op.out_buffer_len = nbytes;

	    	hw_crypto_result = ipsec_crypto_hw_process(&crypto_op);
			crypto_go = 0;

			if (hw_crypto_result == 0) {
#if 0 /* old implementation */
				len=0;
				i=0;
				while (len < nbytes) {
					q = kmap(dst[i].page) + dst[i].offset;
					memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);
//					consistent_sync(p, nbytes, DMA_BIDIRECTIONAL);
					len+=dst[i].length;
					i++;
				};
#endif
				copy_scatterlist(out_buffer, dst, nbytes);
				free_scatterlist(out_buffer, nbytes);
				kfree((void*)out_buffer);
				memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
				return 0;
			}
		} else {
			//printk("%s::didn't go hw crypto engine at all\n", __func__);
		}
		crypto_go = 0;
		free_scatterlist(out_buffer, nbytes);
		kfree((void*)out_buffer);
		memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
	}
	if ((storlink_ctl.hw_crypto != 1) || (hw_crypto_result != 0))
#endif
	{
		struct cipher_desc desc;
		struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;
		desc.tfm = tfm;
		desc.crfn = cipher->cia_encrypt;
		desc.prfn = cipher->cia_encrypt_cbc ?: cbc_process_encrypt;
		desc.info = iv;
		return crypt_iv_unaligned(&desc, dst, src, nbytes);
	}
	return 0;
}

static int cbc_decrypt(struct crypto_tfm *tfm,
                       struct scatterlist *dst,
                       struct scatterlist *src,
		       unsigned int nbytes)
{
#ifdef CONFIG_SL2312_IPSEC
	int hw_crypto_result = 0;
	struct scatterlist *out_buffer;
#if 0 /* old implementation */
	int i=0, len=0;
	unsigned char  *q;
#endif

	if (storlink_ctl.hw_crypto == 1) {
		if (crypto_go == 1)
			printk("%s::crypto engine is used by other process\n", __func__);

		crypto_go = 1;
//		crypto_op.cipher_key_size = tfm->crt_u.cipher.keylen;
//		memcpy(crypto_op.cipher_key, tfm->crt_u.cipher.key, tfm->crt_u.cipher.keylen);
		crypto_op.op_mode = CIPHER_DEC;
		crypto_op.cipher_algorithm = ipsec_get_cipher_algorithm((unsigned char *)&tfm->__crt_alg->cra_name,CBC);
		crypto_op.cipher_header_len = 0;
		crypto_op.cipher_algorithm_len = nbytes;
		memcpy(crypto_op.iv,tfm->crt_cipher.cit_iv,tfm->crt_cipher.cit_ivsize);
		crypto_op.iv_size = tfm->crt_cipher.cit_ivsize;
		crypto_op.in_packet = src;
		crypto_op.pkt_len = nbytes;
		crypto_op.callback = NULL;
#if 0 /* old implementation */
		if (crypto_op.pkt_len > IPSEC_TEXT_LEN) {
			printk("%s :length too long !!\n",__func__);
			return -1;
		}
//		crypto_op.callback = crypto_callback;
		memset(&p, 0x0, IPSEC_TEXT_LEN);
		crypto_op.out_packet2 = (u8 *)&p; //kmap(dst[i].page) + dst[i].offset;
		crypto_op.out_buffer_len = IPSEC_TEXT_LEN;
#endif
		out_buffer = alloc_scatterlist(nbytes, RX_BUF_SEG_SIZE);

		/* force hw crypto engine return fail before even calling it 
		 * because of memory allocation error */
		if (out_buffer == NULL) hw_crypto_result = 1;

		if (hw_crypto_result == 0) {
			crypto_op.out_packet = out_buffer;
			crypto_op.out_packet2 = NULL;
			crypto_op.out_buffer_len = nbytes;

			hw_crypto_result = ipsec_crypto_hw_process(&crypto_op);
			crypto_go = 0;

			if (hw_crypto_result == 0) {
#if 0 /* old implementation */
				len=0;
				i=0;
				while (len < nbytes) {
					q = kmap(dst[i].page) + dst[i].offset;
					memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);
//					hw_memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);
//					consistent_sync(p, nbytes, DMA_BIDIRECTIONAL);
					len+=dst[i].length;
					i++;
				};
#endif
				copy_scatterlist(out_buffer, dst, nbytes);
				free_scatterlist(out_buffer, nbytes);
				kfree((void*)out_buffer);
				memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
				return 0;
			}
		} else {
			//printk("%s::didn't go hw crypto engine at all\n", __func__);
		}
		crypto_go = 0;
		free_scatterlist(out_buffer, nbytes);
		kfree((void*)out_buffer);
		memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
	}
	if ((storlink_ctl.hw_crypto != 1) || (hw_crypto_result != 0))
#endif
	{
		struct cipher_desc desc;
		struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;
		desc.tfm = tfm;
		desc.crfn = cipher->cia_decrypt;
		desc.prfn = cipher->cia_decrypt_cbc ?: cbc_process_decrypt;
		desc.info = tfm->crt_cipher.cit_iv;
		return crypt(&desc, dst, src, nbytes);
	}
	return 0;
}

static int cbc_decrypt_iv(struct crypto_tfm *tfm,
                          struct scatterlist *dst,
                          struct scatterlist *src,
                          unsigned int nbytes, u8 *iv)
{
#ifdef CONFIG_SL2312_IPSEC
	int hw_crypto_result = 0;
	struct scatterlist *out_buffer;
#if 0 /* old implementation */
	int i=0, len=0;
	unsigned char *q;
#endif

	if (storlink_ctl.hw_crypto == 1) {
		if (crypto_go == 1)
			printk("%s::crypto engine is used by other process\n", __func__);

		crypto_go = 1;
		crypto_op.op_mode = CIPHER_DEC;
		crypto_op.cipher_algorithm = ipsec_get_cipher_algorithm((unsigned char *)&tfm->__crt_alg->cra_name,CBC);
		crypto_op.cipher_header_len = 0;
		crypto_op.cipher_algorithm_len = nbytes;
		memcpy(crypto_op.iv,iv,tfm->crt_cipher.cit_ivsize);
		crypto_op.iv_size = tfm->crt_cipher.cit_ivsize;
		crypto_op.in_packet = src;
		crypto_op.pkt_len = nbytes;
		crypto_op.callback = NULL;

#if 0 /* old implementation */
		if (crypto_op.pkt_len > IPSEC_TEXT_LEN) {
			printk("%s :length too long !!\n",__func__);
			return -1;
		}
//		crypto_op.callback = crypto_callback;
		crypto_op.out_packet2 = (u8 *)&p; //kmap(src[i].page) + src[i].offset;
		crypto_op.out_buffer_len = IPSEC_TEXT_LEN;
#endif
		out_buffer = alloc_scatterlist(nbytes, RX_BUF_SEG_SIZE);

		/* force hw crypto engine return fail before even calling it 
		 * because of memory allocation error */
		if (out_buffer == NULL) hw_crypto_result = 1;

		if (hw_crypto_result == 0) {
			crypto_op.out_packet = out_buffer;
			crypto_op.out_packet2 = NULL;
			crypto_op.out_buffer_len = nbytes;

			hw_crypto_result = ipsec_crypto_hw_process(&crypto_op);
			crypto_go = 0;

			if (hw_crypto_result == 0) {
#if 0 /* old implementation */
				len=0;
				i=0;
				while (len < nbytes) {
					q = kmap(dst[i].page) + dst[i].offset;
					memcpy((u8 *)q, (u8 *)(p+len), dst[i].length);	
					len+=dst[i].length;
					i++;
				};
//				kfree(p);
#endif
				copy_scatterlist(out_buffer, dst, nbytes);
				free_scatterlist(out_buffer, nbytes);
				kfree((void*)out_buffer);
				memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
				return 0;
			}
		} else {
			//printk("%s::didn't go hw crypto engine at all\n", __func__);
		}
		crypto_go = 0;
		free_scatterlist(out_buffer, nbytes);
		kfree((void*)out_buffer);
		memset(&crypto_op, 0x0, sizeof(struct IPSEC_PACKET_S));
	}
	if ((storlink_ctl.hw_crypto != 1) || (hw_crypto_result != 0))
#endif
	{
		struct cipher_desc desc;
		struct cipher_alg *cipher = &tfm->__crt_alg->cra_cipher;
		desc.tfm = tfm;
		desc.crfn = cipher->cia_decrypt;
		desc.prfn = cipher->cia_decrypt_cbc ?: cbc_process_decrypt;
		desc.info = iv;
		return crypt_iv_unaligned(&desc, dst, src, nbytes);
	}
	return 0;
}

static int nocrypt(struct crypto_tfm *tfm,
                   struct scatterlist *dst,
                   struct scatterlist *src,
		   unsigned int nbytes)
{
	return -ENOSYS;
}

static int nocrypt_iv(struct crypto_tfm *tfm,
                      struct scatterlist *dst,
                      struct scatterlist *src,
                      unsigned int nbytes, u8 *iv)
{
	return -ENOSYS;
}

int crypto_init_cipher_flags(struct crypto_tfm *tfm, u32 flags)
{
	u32 mode = flags & CRYPTO_TFM_MODE_MASK;
	tfm->crt_cipher.cit_mode = mode ? mode : CRYPTO_TFM_MODE_ECB;
	return 0;
}

int crypto_init_cipher_ops(struct crypto_tfm *tfm)
{
	int ret = 0;
	struct cipher_tfm *ops = &tfm->crt_cipher;

	ops->cit_setkey = setkey;

	switch (tfm->crt_cipher.cit_mode) {
	case CRYPTO_TFM_MODE_ECB:
		ops->cit_encrypt = ecb_encrypt;
		ops->cit_decrypt = ecb_decrypt;
		break;
		
	case CRYPTO_TFM_MODE_CBC:
		ops->cit_encrypt = cbc_encrypt;
		ops->cit_decrypt = cbc_decrypt;
		ops->cit_encrypt_iv = cbc_encrypt_iv;
		ops->cit_decrypt_iv = cbc_decrypt_iv;
		break;
		
	case CRYPTO_TFM_MODE_CFB:
		ops->cit_encrypt = nocrypt;
		ops->cit_decrypt = nocrypt;
		ops->cit_encrypt_iv = nocrypt_iv;
		ops->cit_decrypt_iv = nocrypt_iv;
		break;
	
	case CRYPTO_TFM_MODE_CTR:
		ops->cit_encrypt = nocrypt;
		ops->cit_decrypt = nocrypt;
		ops->cit_encrypt_iv = nocrypt_iv;
		ops->cit_decrypt_iv = nocrypt_iv;
		break;

	default:
		BUG();
	}
	
	if (ops->cit_mode == CRYPTO_TFM_MODE_CBC) {
		unsigned long align;
		unsigned long addr;
	    	
	    	switch (crypto_tfm_alg_blocksize(tfm)) {
	    	case 8:
	    		ops->cit_xor_block = xor_64;
	    		break;
	    		
	    	case 16:
	    		ops->cit_xor_block = xor_128;
	    		break;
	    		
	    	default:
	    		printk(KERN_WARNING "%s: block size %u not supported\n",
	    		       crypto_tfm_alg_name(tfm),
	    		       crypto_tfm_alg_blocksize(tfm));
	    		ret = -EINVAL;
	    		goto out;
	    	}
	    	
		ops->cit_ivsize = crypto_tfm_alg_blocksize(tfm);
		align = crypto_tfm_alg_alignmask(tfm) + 1;
		addr = (unsigned long)crypto_tfm_ctx(tfm);
		addr = ALIGN(addr, align);
		addr += ALIGN(tfm->__crt_alg->cra_ctxsize, align);
		ops->cit_iv = (void *)addr;
	}

out:	
	return ret;
}

void crypto_exit_cipher_ops(struct crypto_tfm *tfm)
{
}

