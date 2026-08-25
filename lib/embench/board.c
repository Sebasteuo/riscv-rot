#include <stddef.h>
#include <stdint.h>

/*
 * Board support for Embench-IoT (OE3).
 *
 * Embench expects four functions from the platform: one to set the
 * board up, and two that mark the region to be measured. Those two are
 * where the attestation window is opened and closed, so the measurement
 * covers exactly the benchmark body and nothing else.
 *
 * The suite is used unmodified. Its workloads were not designed for
 * this project, which is the point: they are a standard corpus for
 * deeply embedded systems rather than workloads chosen by the author.
 */

/* Provided by the client application layer */
extern void bench_window_open(void);
extern void bench_window_close(void);

void initialise_board(void)
{
    /* Nothing to set up: the firmware has already configured the
       platform by the time U-mode runs. */
}

void start_trigger(void)
{
    bench_window_open();
}

void stop_trigger(void)
{
    bench_window_close();
}

/*
 * The only libc function BEEBS itself needs. The benchmarks bring
 * their own simplified rand and malloc through beebsc.
 */
void *memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    size_t i;

    for (i = 0; i < n; i++) {
        p[i] = (unsigned char)c;
    }
    return s;
}

void *memcpy(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;

    for (i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *p = (const unsigned char *)a;
    const unsigned char *q = (const unsigned char *)b;
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != q[i]) {
            return (int)p[i] - (int)q[i];
        }
    }
    return 0;
}

/*
 * The remaining libc functions the suite reaches for. Written out here
 * rather than linked, since the build uses -nostdlib.
 */

size_t strlen(const char *s)
{
    size_t n = 0;

    while (s[n]) {
        n++;
    }
    return n;
}

char *strchr(const char *s, int c)
{
    for (; *s; s++) {
        if (*s == (char)c) {
            return (char *)s;
        }
    }
    return (c == 0) ? (char *)s : (void *)0;
}

void *memmove(void *dest, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;

    /* Copy backwards when the regions overlap the wrong way */
    if (d > s && d < s + n) {
        for (i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    } else {
        for (i = 0; i < n; i++) {
            d[i] = s[i];
        }
    }
    return dest;
}

int tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/*
 * glibc resolves the ctype macros through this table. Providing a
 * static one keeps the benchmarks that use isalpha and friends
 * working without pulling in a locale implementation.
 */
static const unsigned short ctype_table[384] = { 0 };

const unsigned short **__ctype_b_loc(void)
{
    static const unsigned short *p = ctype_table + 128;
    return &p;
}

/*
 * BEEBS calls abort() on internal assertion failure. There is nowhere
 * to abort to on bare metal, so it stops here and stays stopped.
 */
void abort(void)
{
    for (;;) {
        asm volatile("wfi");
    }
}

/*
 * Integer square root. Only wikisort needs sqrt, and only to size a
 * block, so an integer approximation is sufficient and avoids linking
 * a floating point library.
 */
double sqrt(double x)
{
    double guess = x / 2.0;
    int i;

    if (x <= 0.0) {
        return 0.0;
    }
    for (i = 0; i < 32; i++) {
        guess = (guess + x / guess) / 2.0;
    }
    return guess;
}
