/* crypto/mem.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include "cryptlib.h"

#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#define	NULL 0

static void morecore();
static int findbucket();

/*
 * The overhead on a block is at least 4 bytes.  When free, this space
 * contains a pointer to the next free block, and the bottom two bits must
 * be zero.  When in use, the first byte is set to MAGIC, and the second
 * byte is the size index.  The remaining bytes are for alignment.
 * If range checking is enabled then a second word holds the size of the
 * requested block, less 1, rounded up to a multiple of sizeof(RMAGIC).
 * The order of elements is critical: ov_magic must overlay the low order
 * bits of ov_next, and ov_magic can not be a valid ov_next bit pattern.
 */
union	overhead {
	union	overhead *ov_next;	/* when free */
	struct {
		u_char	ovu_magic;	/* magic number */
		u_char	ovu_index;	/* bucket # */
#ifdef RCHECK
		u_short	ovu_rmagic;	/* range magic number */
		u_int	ovu_size;	/* actual block size */
#endif
	} ovu;
        u_char  alignment_pad[8];       /* *** eight-byte alignment *** */
#define	ov_magic	ovu.ovu_magic
#define	ov_index	ovu.ovu_index
#define	ov_rmagic	ovu.ovu_rmagic
#define	ov_size		ovu.ovu_size
};

#define	MAGIC		0xef		/* magic # on accounting info */
#define RMAGIC		0x5555		/* magic # on range info */

#ifdef RCHECK
#define	RSLOP		sizeof (u_short)
#else
#define	RSLOP		0
#endif

/*
 * nextf[i] is the pointer to the next free block of size 2^(i+3).  The
 * smallest allocatable block is 8 bytes.  The overhead information
 * precedes the data area returned to the user.
 */
#define	NBUCKETS 30
union overhead *nextf[NBUCKETS];

#ifdef HPUX
#ifdef _CLASSIC_XOPEN_TYPES
extern  char *sbrk();
#else
extern  void *sbrk();
#endif
#endif

static	int pagesz;			/* page size */
static	int pagebucket;			/* page size bucket */

#ifdef MSTATS
/*
 * nmalloc[i] is the difference between the number of mallocs and frees
 * for a given block size.
 */
static	VOLATILE u_int nmalloc[NBUCKETS];
#include <stdio.h>
#endif

#if defined(DEBUG) || defined(RCHECK)
#define	ASSERT(p)   if (!(p)) botch("p")
#include <stdio.h>
static
botch(s)
	char *s;
{
	static char im_routine[] = "botch";

        IM_INFO(ISIS_MGT_MLIB_MODULE, im_routine,
		("%s%s",
		 "assertion botched: ", s));
	abort();
}
#else
#define	ASSERT(p)
#endif

char memory[15728640];
char *__next = memory;

void *
_malloc(nbytes)
	unsigned nbytes;
{
  	register union overhead *op;
  	register int bucket, n;
	register unsigned amt;

	/*
	 * First time malloc is called, setup page size and
	 * align break pointer so all data will be page aligned.
	 */

	if (pagesz == 0) {
#if defined( HPUX )
                pagesz = n = (int)sysconf(_SC_PAGE_SIZE);
#elif defined( SOLARIS ) || defined ( SOLARIS_X86 ) || defined (UNIXWARE)
                pagesz = n = (int)sysconf(_SC_PAGESIZE);
#else
                pagesz = n = getpagesize();
#endif
		op = (union overhead *)memory;//sbrk(0);
  		n = n - sizeof (*op) - ((int)op & (n - 1));
		if (n < 0)
			n += pagesz;
  		if (n) {
  			/*if ((char *)sbrk(n) == (char *)-1)
			{
				return (NULL);
			}*/
		}
		bucket = 0;
		amt = 8;
		while (pagesz > amt) {
			amt <<= 1;
			bucket++;
		}
		pagebucket = bucket;
	}
	/*
	 * Convert amount of memory requested into closest block size
	 * stored in hash buckets which satisfies request.
	 * Account for space used per block for accounting.
	 */
	if (nbytes <= (n = pagesz - sizeof (*op) - RSLOP)) {
#ifndef RCHECK
		amt = 8;	/* size of first bucket */
		bucket = 0;
#else
		amt = 16;	/* size of first bucket */
		bucket = 1;
#endif
		n = -(sizeof (*op) + RSLOP);
	} else {
		amt = pagesz;
		bucket = pagebucket;
	}
	while (nbytes > amt + n) {
		amt <<= 1;
		if (amt == 0)
		{
			return (NULL);
		}
		bucket++;
	}
	/*
	 * If nothing in hash bucket right now,
	 * request more memory from the system.
	 */
  	if ((op = nextf[bucket]) == NULL) {
            {
                /* Start of inlined morecore. */
                int bucket1 = bucket;
                register union overhead *op;
                register int sz;		/* size of desired block */
                int amt;			/* amount to allocate */
                int nblks;			/* how many blocks we get */

                /*
                 * sbrk_size <= 0 only for big, FLUFFY, requests (about
                 * 2^30 bytes on a VAX, I think) or for a negative arg.
                 */
                sz = 1 << (bucket1 + 3); //nbytes + 8;
#ifdef DEBUG
                ASSERT(sz > 0);
#else
                if (sz <= 0)
                    goto morecore_return;
#endif
                if (sz < pagesz) {
                    amt = pagesz;
                    nblks = amt / sz;
                } else {
                    amt = sz + pagesz;
                    nblks = 1;
                }
                op = (union overhead *)__next;//sbrk(amt);
                __next += amt;
                /* no more room! */
                if ((int)op == -1)
                    goto morecore_return;
                /*
                 * Add new memory allocated to that on
                 * free list for this hash bucket.
                 */
                nextf[bucket1] = op;
                while (--nblks > 0) {
                    op->ov_next = (union overhead *)((caddr_t)op + sz);
                    op = (union overhead *)((caddr_t)op + sz);
                } /* End of inlined morecore. */
              morecore_return:;
            }
            if ((op = nextf[bucket]) == NULL)
            {
                return (NULL);
            }
	}
	/* remove from linked list */
  	nextf[bucket] = op->ov_next;
	op->ov_magic = MAGIC;
	op->ov_index = bucket;
#ifdef MSTATS
  	nmalloc[bucket]++;
#endif
#ifdef RCHECK
	/*
	 * Record allocated size of block and
	 * bound space with magic numbers.
	 */
	op->ov_size = (nbytes + RSLOP - 1) & ~(RSLOP - 1);
	op->ov_rmagic = RMAGIC;
  	*(u_short *)((caddr_t)(op + 1) + op->ov_size) = RMAGIC;
#endif
  	return ((char *)(op + 1));
}

/*
 * Allocate more memory to the indicated bucket.
 */
static void
morecore(bucket)
	int bucket;
{
  	register union overhead *op;
	register int sz;		/* size of desired block */
  	int amt;			/* amount to allocate */
  	int nblks;			/* how many blocks we get */

	/*
	 * sbrk_size <= 0 only for big, FLUFFY, requests (about
	 * 2^30 bytes on a VAX, I think) or for a negative arg.
	 */
	sz = 1 << (bucket + 3);
#ifdef DEBUG
	ASSERT(sz > 0);
#else
	if (sz <= 0)
		return;
#endif
	if (sz < pagesz) {
		amt = pagesz;
  		nblks = amt / sz;
	} else {
		amt = sz + pagesz;
		nblks = 1;
	}
	op = (union overhead *)__next;//sbrk(amt);
	__next += amt;
	/* no more room! */
  	if ((int)op == -1)
  		return;
	/*
	 * Add new memory allocated to that on
	 * free list for this hash bucket.
	 */
  	nextf[bucket] = op;
  	while (--nblks > 0) {
		op->ov_next = (union overhead *)((caddr_t)op + sz);
		op = (union overhead *)((caddr_t)op + sz);
  	}
}

_free(cp)
	void *cp;
{
  	register int size;
	register union overhead *op;

  	if (cp == NULL)
  		return;
	op = (union overhead *)((caddr_t)cp - sizeof (union overhead));
#ifdef DEBUG
  	ASSERT(op->ov_magic == MAGIC);		
#else
	if (op->ov_magic != MAGIC)
	{
		return;				
	}
#endif
#ifdef RCHECK
  	ASSERT(op->ov_rmagic == RMAGIC);
	ASSERT(*(u_short *)((caddr_t)(op + 1) + op->ov_size) == RMAGIC);
#endif
  	size = op->ov_index;
  	ASSERT(size < NBUCKETS);
	op->ov_next = nextf[size];
  	nextf[size] = op;
#ifdef MSTATS
  	nmalloc[size]--;
#endif
}

/*
 * When a program attempts "storage compaction" as mentioned in the
 * old malloc man page, it realloc's an already freed block.  Usually
 * this is the last block it freed; occasionally it might be farther
 * back.  We have to search all the free lists for the block in order
 * to determine its bucket: 1st we make one pass thru the lists
 * checking only the first block in each; if that fails we search
 * ``realloc_srchlen'' blocks in each list for a match (the variable
 * is extern so the caller can modify it).  If that fails we just copy
 * however many bytes was given to realloc() and hope it's not huge.
 */
int realloc_srchlen = 4;	/* 4 should be plenty, -1 =>'s whole list */

void *
_realloc(cp, nbytes)
	void *cp;
	unsigned nbytes;
{
  	register u_int onb;
	register int i;
	union overhead *op;
  	char *res;
	int was_alloced = 0;

  	if (cp == NULL)
  		return (_malloc(nbytes));
	op = (union overhead *)((caddr_t)cp - sizeof (union overhead));
	if (op->ov_magic == MAGIC) {
		was_alloced++;
		i = op->ov_index;
	} else {
		/*
		 * Already free, doing "compaction".
		 *
		 * Search for the old block of memory on the
		 * free list.  First, check the most common
		 * case (last element free'd), then (this failing)
		 * the last ``realloc_srchlen'' items free'd.
		 * If all lookups fail, then assume the size of
		 * the memory block being realloc'd is the
		 * largest possible (so that all "nbytes" of new
		 * memory are copied into).  Note that this could cause
		 * a memory fault if the old area was tiny, and the moon
		 * is gibbous.  However, that is very unlikely.
		 */
		if ((i = findbucket(op, 1)) < 0 &&
		    (i = findbucket(op, realloc_srchlen)) < 0)
			i = NBUCKETS;
	}
	onb = 1 << (i + 3);
	if (onb < pagesz)
		onb -= sizeof (*op) + RSLOP;
	else
		onb += pagesz - sizeof (*op) - RSLOP;
	/* avoid the copy if same size block */
	if (was_alloced) {
		if (i) {
			i = 1 << (i + 2);
			if (i < pagesz)
				i -= sizeof (*op) + RSLOP;
			else
				i += pagesz - sizeof (*op) - RSLOP;
		}
		if (nbytes <= onb && nbytes > i) {
#ifdef RCHECK
			op->ov_size = (nbytes + RSLOP - 1) & ~(RSLOP - 1);
			*(u_short *)((caddr_t)(op + 1) + op->ov_size) = RMAGIC;
#endif
			return(cp);
		} else
			_free(cp);
	}
  	if ((res = _malloc(nbytes)) == NULL)
	{
  		return (NULL);
	}
  	if (cp != res)		/* common optimization if "compacting" */
		memcpy(res, cp, (nbytes < onb) ? nbytes : onb);
  	return (res);
}

/*
 * Search ``srchlen'' elements of each free list for a block whose
 * header starts at ``freep''.  If srchlen is -1 search the whole list.
 * Return bucket number, or -1 if not found.
 */
static
findbucket(freep, srchlen)
	union overhead *freep;
	int srchlen;
{
	register union overhead *p;
	register int i, j;

	for (i = 0; i < NBUCKETS; i++) {
		j = 0;
		for (p = nextf[i]; p && j != srchlen; p = p->ov_next) {
			if (p == freep)
				return (i);
			j++;
		}
	}
	return (-1);
}



static int allow_customize = 1;      /* we provide flexible functions for */
static int allow_customize_debug = 1;/* exchanging memory-related functions at
                                      * run-time, but this must be done
                                      * before any blocks are actually
                                      * allocated; or we'll run into huge
                                      * problems when malloc/free pairs
                                      * don't match etc. */



/* the following pointers may be changed as long as 'allow_customize' is set */

static void *(*malloc_func)(size_t)         = _malloc;
static void *default_malloc_ex(size_t num, const char *file, int line)
	{ return malloc_func(num); }
static void *(*malloc_ex_func)(size_t, const char *file, int line)
        = default_malloc_ex;

static void *(*realloc_func)(void *, size_t)= _realloc;
static void *default_realloc_ex(void *str, size_t num,
        const char *file, int line)
	{ return realloc_func(str,num); }
static void *(*realloc_ex_func)(void *, size_t, const char *file, int line)
        = default_realloc_ex;

static void (*free_func)(void *)            = _free;

static void *(*malloc_locked_func)(size_t)  = _malloc;
static void *default_malloc_locked_ex(size_t num, const char *file, int line)
	{ return malloc_locked_func(num); }
static void *(*malloc_locked_ex_func)(size_t, const char *file, int line)
        = default_malloc_locked_ex;

static void (*free_locked_func)(void *)     = _free;



/* may be changed as long as 'allow_customize_debug' is set */
/* XXX use correct function pointer types */
#ifdef CRYPTO_MDEBUG
/* use default functions from mem_dbg.c */
static void (*malloc_debug_func)(void *,int,const char *,int,int)
	= CRYPTO_dbg_malloc;
static void (*realloc_debug_func)(void *,void *,int,const char *,int,int)
	= CRYPTO_dbg_realloc;
static void (*free_debug_func)(void *,int) = CRYPTO_dbg_free;
static void (*set_debug_options_func)(long) = CRYPTO_dbg_set_options;
static long (*get_debug_options_func)(void) = CRYPTO_dbg_get_options;
#else
/* applications can use CRYPTO_malloc_debug_init() to select above case
 * at run-time */
static void (*malloc_debug_func)(void *,int,const char *,int,int) = NULL;
static void (*realloc_debug_func)(void *,void *,int,const char *,int,int)
	= NULL;
static void (*free_debug_func)(void *,int) = NULL;
static void (*set_debug_options_func)(long) = NULL;
static long (*get_debug_options_func)(void) = NULL;
#endif

int CRYPTO_set_mem_functions(void *(*m)(size_t), void *(*r)(void *, size_t),
	void (*f)(void *))
	{
	/* Dummy call just to ensure OPENSSL_init() gets linked in */
	OPENSSL_init();
	if (!allow_customize)
		return 0;
	if ((m == 0) || (r == 0) || (f == 0))
		return 0;
	malloc_func=m; malloc_ex_func=default_malloc_ex;
	realloc_func=r; realloc_ex_func=default_realloc_ex;
	free_func=f;
	malloc_locked_func=m; malloc_locked_ex_func=default_malloc_locked_ex;
	free_locked_func=f;
	return 1;
	}

int CRYPTO_set_mem_ex_functions(
        void *(*m)(size_t,const char *,int),
        void *(*r)(void *, size_t,const char *,int),
	void (*f)(void *))
	{
	if (!allow_customize)
		return 0;
	if ((m == 0) || (r == 0) || (f == 0))
		return 0;
	malloc_func=0; malloc_ex_func=m;
	realloc_func=0; realloc_ex_func=r;
	free_func=f;
	malloc_locked_func=0; malloc_locked_ex_func=m;
	free_locked_func=f;
	return 1;
	}

int CRYPTO_set_locked_mem_functions(void *(*m)(size_t), void (*f)(void *))
	{
	if (!allow_customize)
		return 0;
	if ((m == NULL) || (f == NULL))
		return 0;
	malloc_locked_func=m; malloc_locked_ex_func=default_malloc_locked_ex;
	free_locked_func=f;
	return 1;
	}

int CRYPTO_set_locked_mem_ex_functions(
        void *(*m)(size_t,const char *,int),
        void (*f)(void *))
	{
	if (!allow_customize)
		return 0;
	if ((m == NULL) || (f == NULL))
		return 0;
	malloc_locked_func=0; malloc_locked_ex_func=m;
	free_func=f;
	return 1;
	}

int CRYPTO_set_mem_debug_functions(void (*m)(void *,int,const char *,int,int),
				   void (*r)(void *,void *,int,const char *,int,int),
				   void (*f)(void *,int),
				   void (*so)(long),
				   long (*go)(void))
	{
	if (!allow_customize_debug)
		return 0;
	OPENSSL_init();
	malloc_debug_func=m;
	realloc_debug_func=r;
	free_debug_func=f;
	set_debug_options_func=so;
	get_debug_options_func=go;
	return 1;
	}


void CRYPTO_get_mem_functions(void *(**m)(size_t), void *(**r)(void *, size_t),
	void (**f)(void *))
	{
	if (m != NULL) *m = (malloc_ex_func == default_malloc_ex) ? 
	                     malloc_func : 0;
	if (r != NULL) *r = (realloc_ex_func == default_realloc_ex) ? 
	                     realloc_func : 0;
	if (f != NULL) *f=free_func;
	}

void CRYPTO_get_mem_ex_functions(
        void *(**m)(size_t,const char *,int),
        void *(**r)(void *, size_t,const char *,int),
	void (**f)(void *))
	{
	if (m != NULL) *m = (malloc_ex_func != default_malloc_ex) ?
	                    malloc_ex_func : 0;
	if (r != NULL) *r = (realloc_ex_func != default_realloc_ex) ?
	                    realloc_ex_func : 0;
	if (f != NULL) *f=free_func;
	}

void CRYPTO_get_locked_mem_functions(void *(**m)(size_t), void (**f)(void *))
	{
	if (m != NULL) *m = (malloc_locked_ex_func == default_malloc_locked_ex) ? 
	                     malloc_locked_func : 0;
	if (f != NULL) *f=free_locked_func;
	}

void CRYPTO_get_locked_mem_ex_functions(
        void *(**m)(size_t,const char *,int),
        void (**f)(void *))
	{
	if (m != NULL) *m = (malloc_locked_ex_func != default_malloc_locked_ex) ?
	                    malloc_locked_ex_func : 0;
	if (f != NULL) *f=free_locked_func;
	}

void CRYPTO_get_mem_debug_functions(void (**m)(void *,int,const char *,int,int),
				    void (**r)(void *,void *,int,const char *,int,int),
				    void (**f)(void *,int),
				    void (**so)(long),
				    long (**go)(void))
	{
	if (m != NULL) *m=malloc_debug_func;
	if (r != NULL) *r=realloc_debug_func;
	if (f != NULL) *f=free_debug_func;
	if (so != NULL) *so=set_debug_options_func;
	if (go != NULL) *go=get_debug_options_func;
	}


void *CRYPTO_malloc_locked(int num, const char *file, int line)
	{
	void *ret = NULL;

	if (num <= 0) return NULL;

	allow_customize = 0;
	if (malloc_debug_func != NULL)
		{
		allow_customize_debug = 0;
		malloc_debug_func(NULL, num, file, line, 0);
		}
	ret = malloc_locked_ex_func(num,file,line);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         > 0x%p (%d)\n", ret, num);
#endif
	if (malloc_debug_func != NULL)
		malloc_debug_func(ret, num, file, line, 1);

#ifndef OPENSSL_CPUID_OBJ
        /* Create a dependency on the value of 'cleanse_ctr' so our memory
         * sanitisation function can't be optimised out. NB: We only do
         * this for >2Kb so the overhead doesn't bother us. */
        if(ret && (num > 2048))
	{	extern unsigned char cleanse_ctr;
		((unsigned char *)ret)[0] = cleanse_ctr;
	}
#endif

	return ret;
	}

void CRYPTO_free_locked(void *str)
	{
	if (free_debug_func != NULL)
		free_debug_func(str, 0);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         < 0x%p\n", str);
#endif
	free_locked_func(str);
	if (free_debug_func != NULL)
		free_debug_func(NULL, 1);
	}

void *CRYPTO_malloc(int num, const char *file, int line)
	{
	void *ret = NULL;

	if (num <= 0) return NULL;

	allow_customize = 0;
	if (malloc_debug_func != NULL)
		{
		allow_customize_debug = 0;
		malloc_debug_func(NULL, num, file, line, 0);
		}
	ret = malloc_ex_func(num,file,line);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         > 0x%p (%d)\n", ret, num);
#endif
	if (malloc_debug_func != NULL)
		malloc_debug_func(ret, num, file, line, 1);

#ifndef OPENSSL_CPUID_OBJ
        /* Create a dependency on the value of 'cleanse_ctr' so our memory
         * sanitisation function can't be optimised out. NB: We only do
         * this for >2Kb so the overhead doesn't bother us. */
        if(ret && (num > 2048))
	{	extern unsigned char cleanse_ctr;
                ((unsigned char *)ret)[0] = cleanse_ctr;
	}
#endif

	return ret;
	}
char *CRYPTO_strdup(const char *str, const char *file, int line)
	{
	char *ret = CRYPTO_malloc(strlen(str)+1, file, line);

	strcpy(ret, str);
	return ret;
	}

void *CRYPTO_realloc(void *str, int num, const char *file, int line)
	{
	void *ret = NULL;

	if (str == NULL)
		return CRYPTO_malloc(num, file, line);

	if (num <= 0) return NULL;

	if (realloc_debug_func != NULL)
		realloc_debug_func(str, NULL, num, file, line, 0);
	ret = realloc_ex_func(str,num,file,line);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         | 0x%p -> 0x%p (%d)\n", str, ret, num);
#endif
	if (realloc_debug_func != NULL)
		realloc_debug_func(str, ret, num, file, line, 1);

	return ret;
	}

void *CRYPTO_realloc_clean(void *str, int old_len, int num, const char *file,
			   int line)
	{
	void *ret = NULL;

	if (str == NULL)
		return CRYPTO_malloc(num, file, line);

	if (num <= 0) return NULL;

	/* We don't support shrinking the buffer. Note the memcpy that copies
	 * |old_len| bytes to the new buffer, below. */
	if (num < old_len) return NULL;

	if (realloc_debug_func != NULL)
		realloc_debug_func(str, NULL, num, file, line, 0);
	ret=malloc_ex_func(num,file,line);
	if(ret)
		{
		memcpy(ret,str,old_len);
		OPENSSL_cleanse(str,old_len);
		free_func(str);
		}
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr,
		"LEVITTE_DEBUG_MEM:         | 0x%p -> 0x%p (%d)\n",
		str, ret, num);
#endif
	if (realloc_debug_func != NULL)
		realloc_debug_func(str, ret, num, file, line, 1);

	return ret;
	}

void CRYPTO_free(void *str)
	{
	if (free_debug_func != NULL)
		free_debug_func(str, 0);
#ifdef LEVITTE_DEBUG_MEM
	fprintf(stderr, "LEVITTE_DEBUG_MEM:         < 0x%p\n", str);
#endif
	free_func(str);
	if (free_debug_func != NULL)
		free_debug_func(NULL, 1);
	}

void *CRYPTO_remalloc(void *a, int num, const char *file, int line)
	{
	if (a != NULL) OPENSSL_free(a);
	a=(char *)OPENSSL_malloc(num);
	return(a);
	}

void CRYPTO_set_mem_debug_options(long bits)
	{
	if (set_debug_options_func != NULL)
		set_debug_options_func(bits);
	}

long CRYPTO_get_mem_debug_options(void)
	{
	if (get_debug_options_func != NULL)
		return get_debug_options_func();
	return 0;
	}
