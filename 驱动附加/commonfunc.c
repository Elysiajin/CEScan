#include <ntddk.h>
#include <intrin.h>

#ifdef AMD64
KIRQL WPOFF()        //ԭWPOFFx64
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPON(KIRQL irql)        //ԭWPONx64
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}
#else
KIRQL WPOFF()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	__asm
	{
		CLI                                        //dissable interrupt
			MOV        EAX, CR0                //move CR0 register into EAX
			AND        EAX, NOT 10000H        //disable WP bit 
			MOV        CR0, EAX                //write register back
	}
	return irql;
}

void WPON(KIRQL irql)
{
	__asm
	{
		MOV        EAX, CR0        //move CR0 register into EAX
			OR        EAX, 10000H        //enable WP bit     
			MOV        CR0, EAX        //write register back        
			STI                                //enable interrupt
	}
	KeLowerIrql(irql);
}
#endif



