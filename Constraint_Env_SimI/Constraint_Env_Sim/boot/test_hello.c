#include <stdio.h>
#include <stdlib.h>
#include <libbase/uart.h>
#include <libbase/console.h>

int main(void) {
    // Basic UART init (if not done by BIOS/crt0)
    uart_init();
    
    printf("\n");
    printf("=========================================\n");
    printf("     MINIMAL SIMULATION TEST FIRMWARE    \n");
    printf("=========================================\n");
    printf("If you can see this, the Boot Process is working!\n");
    
    int counter = 0;
    while(1) {
        printf("Hello Simulation! Counter: %d\n", counter++);
        // Busy wait
        for(volatile int i=0; i<1000000; i++);
    }
    return 0;
}
