#include <stdio.h>
volatile unsigned int * mmio3 = (volatile unsigned int *) 897897800;
typedef struct a {
	char a;
	int reg_b;
	int reg_c;
} A;
A *mmio_s =  (A *)100;
void access2(volatile unsigned int * par) __attribute__((noinline)) {
	*par = 100;
}
void access(volatile unsigned int * par) __attribute__((noinline)) {
	access2(par);
}

volatile unsigned long * getPointer(void) __attribute__((noinline)) {
	int i = 0;
	volatile unsigned long * addr = mmio_s + i;
	return addr;
}
int main(int argc, char * argv[]) {
	//*mmio3 = 10;
	volatile A *mmio_s1  = (A*) 12345678;
	volatile unsigned char * addr = mmio_s;
	*addr = 0;
	//int a = mmio_s->reg_c;
	//mmio_s1->reg_b = 10;
	//int a = mmio_s1 -> reg_b;

	//mmio_s -> reg_b = 10;
	//*mmio3 = 10;
#if 0
	mmio_s1->reg_b = 1;	
	volatile unsigned int * mmio3 = (volatile unsigned int *) 123456;
	*(mmio3 + 8) = 9;
	volatile unsigned int * mmio2 = mmio3 + 3;
	*mmio2 = 1;
	volatile unsigned int * mmio1 = mmio2 + 1;
	*mmio1 = 2;
	volatile unsigned int * mmio0 = mmio1+ 1;
	*mmio0 =3;
	volatile unsigned int * mmio5 = mmio0 + 1;
	volatile unsigned int * mmio6 = mmio5 + 1;
	volatile unsigned int * mmio7 = mmio6 + 1;
	volatile unsigned int * mmio10 = mmio7 - 8;
	const int a = 10 + 9;
	volatile unsigned int * mmio8 = a; 
	volatile unsigned int * mmio_un = 1+ 1000;
	volatile unsigned int * mmio_d = (volatile unsigned int *) 12345;
	*mmio_un = 10;
	//*mmio_d = 1; 
	 
	/* volatile unsigned int * mmio9 = 19;
	*mmio9 = 1; 
	volatile unsigned int * mmio = argc + 1 + 1;
        *mmio = 1;	*/
	*mmio_d = 10;
	access(mmio_d);
	access(&mmio_s->reg_b);
	access(&mmio_s1->reg_b);
#endif 
	volatile unsigned long * pointer = getPointer();
	*pointer = 100;
	return 0;
}
