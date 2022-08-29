/* Below bitop functions are copied from linux arch/mips/include/asm/bitops.h */
#define SZLONG_MASK 63UL
#define SZLONG_LOG 6
#define BITS_PER_LONG 64
#define BITOP_WORD(nr)		((nr) / BITS_PER_LONG)

/*
 * test_and_set_bit - Set a bit and return its old value
 * @nr: Bit to set
 * @addr: Address to count from
 */
static inline int test_and_set_bit(unsigned long nr,
	volatile unsigned long *addr)
{
	int bit = nr & SZLONG_MASK;
	unsigned long res;
	unsigned long *m = ((unsigned long *) addr) + (nr >> SZLONG_LOG);
	unsigned long temp;

	CVMX_SYNCWS;

        do {
                __asm__ __volatile__(
                "	.set	mips3				\n"
                "	" "lld " "%0, %1	# test_and_set_bit	\n"
                "	or	%2, %0, %3			\n"
                "	" "scd "	"%2, %1				\n"
                "	.set	mips0				\n"
                : "=&r" (temp), "+m" (*m), "=&r" (res)
                : "r" (1UL << bit)
                : "memory");
        } while (cvmx_unlikely(!res));

        res = temp & (1UL << bit);

        CVMX_SYNCWS;

	return res != 0;
}

/*
 * test_and_clear_bit - Clear a bit and return its old value
 * @nr: Bit to clear
 * @addr: Address to count from
 *
 * This operation is atomic and cannot be reordered.
 * It also implies a memory barrier.
 */
static inline int test_and_clear_bit(unsigned long nr,
	volatile unsigned long *addr)
{
	int bit = nr & SZLONG_MASK;
	unsigned long res;
        unsigned long *m = ((unsigned long *) addr) + (nr >> SZLONG_LOG);
        unsigned long temp;


	CVMX_SYNCWS;

        do {
                __asm__ __volatile__(
                "	.set	mips3				\n"
                "	""lld " "%0, %1 # test_and_clear_bit	\n"
                "	or	%2, %0, %3			\n"
                "	xor	%2, %3				\n"
                "	""scd "	"%2, %1				\n"
                "	.set	mips0				\n"
                : "=&r" (temp), "+m" (*m), "=&r" (res)
                : "r" (1UL << bit)
                : "memory");
        } while (cvmx_unlikely(!res));

        res = temp & (1UL << bit);
	
        CVMX_SYNCWS;

	return res != 0;
}

#define ffz(x)  __ffs(~(x))

/*
 * Return the bit position (0..63) of the most significant 1 bit in a word
 * Returns -1 if no 1 bit exists
 */
static inline unsigned long __fls(unsigned long word)
{
	int num;
        
        __asm__(
        "	.set	push					\n"
        "	.set	mips64					\n"
        "	dclz	%0, %1					\n"
        "	.set	pop					\n"
        : "=r" (num)
        : "r" (word));

        return 63 - num;
}

/*
 * __ffs - find first bit in word.
 * @word: The word to search
 *
 * Returns 0..SZLONG-1
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long __ffs(unsigned long word)
{
	return __fls(word & -word);
}

#define find_first_zero_bit(addr, size) find_next_zero_bit((addr), (size), 0)

/*
 * This implementation of find_{first,next}_zero_bit was stolen from
 * Linus' asm-alpha/bitops.h.
 */
static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
				 unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found_middle:
	return result + ffz(tmp);
}

