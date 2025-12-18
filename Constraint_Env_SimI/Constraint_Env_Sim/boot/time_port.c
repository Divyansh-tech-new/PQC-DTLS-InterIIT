#include <stdint.h>

#include <generated/csr.h>             // LiteX timer CSRs
#include <wolfssl/wolfcrypt/types.h>   // word32

/* Simple local timer init – same idea as in main.c */
static int time_init_done = 0;

static void time_init(void) {
    if (time_init_done)
        return;

    timer0_en_write(0);
    timer0_load_write(0xFFFFFFFF);
    timer0_reload_write(0xFFFFFFFF);
    timer0_en_write(1);

    time_init_done = 1;
}

/* This is what wolfSSL will call instead of using gettimeofday() */
word32 TimeNowInMilliseconds(void)
{
    time_init();

    // LiteX timer counts down from 0xFFFFFFFF
    timer0_update_value_write(1);
    uint32_t current_ticks = timer0_value_read();
    uint32_t elapsed_us   = 0xFFFFFFFFu - current_ticks;  // microseconds

    return (word32)(elapsed_us / 1000u);  // convert to ms
}

