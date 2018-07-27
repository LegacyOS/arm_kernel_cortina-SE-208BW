/*
 * Cryptographic API.
 *
 * Digest operations.
 *
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 */
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <asm/scatterlist.h>
#include "internal.h"

#ifdef CONFIG_SL2312_IPSEC
#include <linux/dma-mapping.h>
#include <asm/arch/sl2312_ipsec.h>
#include <linux/sysctl_storlink.h>

#if 0 /* old implementation */
#define     IPSEC_TEXT_LEN    32768 //2048
unsigned char di_packet[IPSEC_TEXT_LEN];
extern  spinlock_t crypto_done_lock;
#define	DSG_NUMBER	32
struct scatterlist dsg[DSG_NUMBER];
#endif
#define	RX_BUF_SEG_SIZE	RX_BUF_SIZE
unsigned int DSG_number;
struct scatterlist *dsg=NULL;
extern  unsigned int crypto_go ;
struct IPSEC_PACKET_S digest_op;

#if 0 /* old implementation */
extern void crypto_callback(struct IPSEC_PACKET_S *op_info);
#endif
extern struct scatterlist * alloc_scatterlist(unsigned int size, unsigned int seg_size);
extern int free_scatterlist(struct scatterlist *list, unsigned int size);

static inline void add_scatterlist(struct scatterlist *sg, unsigned int nsg)
{
	struct scatterlist *new_dsg;

	if (dsg == NULL) {
		dsg = (struct scatterlist*)kmalloc(sizeof(struct scatterlist)*nsg, GFP_ATOMIC);
		DSG_number = nsg;
		memcpy(dsg, sg, nsg*sizeof(struct scatterlist));
	} else {
		/* dsg is existed, have to extend dsg */
		new_dsg = (struct scatterlist*)kmalloc(sizeof(struct scatterlist)*(nsg+DSG_number), GFP_ATOMIC);
		memcpy(new_dsg, dsg, DSG_number*sizeof(struct scatterlist));
		memcpy(&(new_dsg[DSG_number]), sg, nsg*sizeof(struct scatterlist));
		DSG_number += nsg;
		kfree((void*)dsg);
		dsg = new_dsg;
	}
}
#endif

static void init(struct crypto_tfm *tfm)
{
	tfm->__crt_alg->cra_digest.dia_init(crypto_tfm_ctx(tfm));
#ifdef CONFIG_SL2312_IPSEC
	memset(&digest_op, 0x0, sizeof(struct IPSEC_PACKET_S));
	dsg = NULL;
	DSG_number = 0;
#endif	
}

static void update(struct crypto_tfm *tfm,
                   struct scatterlist *sg, unsigned int nsg)
{
	unsigned int i;
#ifdef CONFIG_SL2312_IPSEC
	unsigned int plen=0;
	unsigned char *in_packet;

	if (storlink_ctl.hw_crypto == 1) {
//		if(crypto_go == 0)
//			printk("%s: crypto_go = %x\n",__func__,crypto_go);
		crypto_go = 0;

		for (i=0; i<nsg; i++) {
			plen += sg[i].length;	
			in_packet = kmap(sg[i].page) + sg[i].offset;

			if (digest_op.pkt_len == 0) {
				digest_op.pkt_len = sg[i].length;
				digest_op.auth_algorithm_len = sg[i].length;
			} else {
				digest_op.pkt_len += sg[i].length;
				digest_op.auth_algorithm_len += sg[i].length;
			}
		}

#if 0
		for(i=0; i<DSG_NUMBER; i++) {
			if (dsg[i].length == 0) {
				memcpy(&dsg[i],sg,nsg*sizeof(struct scatterlist));
				break;
			}
		}
#endif
		add_scatterlist(sg, nsg);

		digest_op.op_mode = AUTH;
		digest_op.auth_algorithm = ipsec_get_auth_algorithm((unsigned char *)tfm->__crt_alg->cra_name, 0); //(0) AUTH; (1) HMAC
//		digest_op.callback = crypto_callback;
		digest_op.callback = NULL;
		digest_op.auth_header_len = 0;
	}
#endif
	for (i = 0; i < nsg; i++) {

		struct page *pg = sg[i].page;
		unsigned int offset = sg[i].offset;
		unsigned int l = sg[i].length;

		do {
			unsigned int bytes_from_page = min(l, ((unsigned int)
							   (PAGE_SIZE)) - 
							   offset);
			char *p = crypto_kmap(pg, 0) + offset;

			tfm->__crt_alg->cra_digest.dia_update
					(crypto_tfm_ctx(tfm), p,
					 bytes_from_page);
			crypto_kunmap(p, 0);
			crypto_yield(tfm);
			offset = 0;
			pg++;
			l -= bytes_from_page;
		} while (l > 0);
	}
}

static void final(struct crypto_tfm *tfm, u8 *out)
{
#ifdef CONFIG_SL2312_IPSEC
	int hw_crypto_result = 0;
	struct scatterlist *out_buffer;
	unsigned int alloc_size;

	if (storlink_ctl.hw_crypto == 1) {
		crypto_go = 1;
#if 0 /* old implementation */
		if(digest_op.pkt_len > IPSEC_TEXT_LEN) {
			printk("%s :length too long !!\n",__func__);
			return;
		}
		digest_op.out_packet2 = (u8 *)&di_packet;
		digest_op.out_buffer_len = IPSEC_TEXT_LEN;
#endif
		//digest_op.in_packet = (struct scatterlist *)&dsg;
		digest_op.in_packet = dsg;
		alloc_size = digest_op.pkt_len + crypto_tfm_alg_digestsize(tfm);
		out_buffer = alloc_scatterlist(alloc_size, RX_BUF_SEG_SIZE);

		/* force hw crypto engine return fail before even calling it 
		 * because of memory allocation error */
		if (out_buffer == NULL) hw_crypto_result = 1;

		if (likely(hw_crypto_result == 0)) {
			digest_op.out_packet2 = NULL;
			digest_op.out_packet = out_buffer;
			digest_op.out_buffer_len = alloc_size;

			hw_crypto_result = ipsec_crypto_hw_process(&digest_op);	
			crypto_go = 0;
 
			if (likely(hw_crypto_result == 0)) {
				//memcpy(out, (u8 *)(digest_op.out_packet2+digest_op.pkt_len),crypto_tfm_alg_digestsize(tfm));
//				memcpy(out, &di_packet[digest_op.pkt_len],crypto_tfm_alg_digestsize(tfm));	/* old */
				unsigned char * target_ptr;
				unsigned int page = 0, offset = 0, len = 0;

				while (len <= digest_op.pkt_len) {
					if ((len + out_buffer[page].length) > digest_op.pkt_len) {
						offset = digest_op.pkt_len - len;
						len += out_buffer[page].length;
					} else {
						len += out_buffer[page].length;
						page++;
					}
				}

				target_ptr = (unsigned char*)(kmap(out_buffer[page].page) + out_buffer[page].offset);
				if (len >= (digest_op.pkt_len + crypto_tfm_alg_digestsize(tfm))) {
					memcpy(out, (unsigned char*)(target_ptr+offset), crypto_tfm_alg_digestsize(tfm));
				} else {
					unsigned int diff;
					diff = digest_op.pkt_len + crypto_tfm_alg_digestsize(tfm) - len;
					memcpy(out, target_ptr, crypto_tfm_alg_digestsize(tfm) - diff);
					target_ptr = (unsigned char*)(kmap(out_buffer[page+1].page) + out_buffer[page+1].offset);
					memcpy((u8*)((unsigned int)out+crypto_tfm_alg_digestsize(tfm)-diff), target_ptr, diff);
				}
			}
		} else {
			//printk("%s::didn't go to HW crypto engine\n", __func__);
		}
		crypto_go = 0;
		free_scatterlist(out_buffer, alloc_size);
		kfree((void*)out_buffer);
		kfree((void*)dsg);
	}
	if ((storlink_ctl.hw_crypto != 1) || (hw_crypto_result != 0))
#endif  	
		tfm->__crt_alg->cra_digest.dia_final(crypto_tfm_ctx(tfm), out);
}

static int setkey(struct crypto_tfm *tfm, const u8 *key, unsigned int keylen)
{
	u32 flags;
#ifdef CONFIG_SL2312_IPSEC
	if (storlink_ctl.hw_crypto == 1) {
		digest_op.auth_key_size = keylen;
		memcpy(digest_op.auth_key, key, keylen);
	}
#endif
	if (tfm->__crt_alg->cra_digest.dia_setkey == NULL)
		return -ENOSYS;
	return tfm->__crt_alg->cra_digest.dia_setkey(crypto_tfm_ctx(tfm),
					     key, keylen, &flags);
}

static void digest(struct crypto_tfm *tfm,
                   struct scatterlist *sg, unsigned int nsg, u8 *out)
{
	unsigned int i;

	tfm->crt_digest.dit_init(tfm);

#ifdef CONFIG_SL2312_IPSEC
	if (storlink_ctl.hw_crypto == 1) {
		update(tfm, sg, nsg);
		final(tfm, out);
	} else 
#endif
	{
		for (i = 0; i < nsg; i++) {
			char *p = crypto_kmap(sg[i].page, 0) + sg[i].offset;
			tfm->__crt_alg->cra_digest.dia_update(crypto_tfm_ctx(tfm), 
							p, sg[i].length);
			crypto_kunmap(p, 0);
			crypto_yield(tfm);
		}
		crypto_digest_final(tfm, out);
	}
}

int crypto_init_digest_flags(struct crypto_tfm *tfm, u32 flags)
{
	return flags ? -EINVAL : 0;
}

int crypto_init_digest_ops(struct crypto_tfm *tfm)
{
	struct digest_tfm *ops = &tfm->crt_digest;
	
	ops->dit_init	= init;
	ops->dit_update	= update;
	ops->dit_final	= final;
	ops->dit_digest	= digest;
	ops->dit_setkey	= setkey;
	
	return crypto_alloc_hmac_block(tfm);
}

void crypto_exit_digest_ops(struct crypto_tfm *tfm)
{
	crypto_free_hmac_block(tfm);
}

