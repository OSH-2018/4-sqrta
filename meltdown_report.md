# meltdown 实验报告
实验环境为 Ubuntu 17.12 内核版本在14.1以上<br>
首先 [关闭meltdown补丁](https://community.spiceworks.com/topic/2108250-meltdown-patch-disable-fedora-27)

## 流程解读

直接运行 
    ./melt.sh
即可得到结果
![](https://github.com/OSH-2018/4-sqrta/blob/master/result.png)<br>
对指定地址的内容尝试读取1000次，每次会返回一个猜测的值，然后认为该地址的值位这1000次猜测中最多的<br>
一次对攻击地址的猜测的全流程参见下面的readbyte函数

    int readbyte(int fd,char *addr){//运用meltdown原理读取指定地址addr内一个字节的内容
    
    static char buf[256];
    memset(check, 1, sizeof(check));
    pread(fd, buf, sizeof(buf), 0);
    
    flush();
    //_mm_mfence();   
    attack(addr);

    return reload();
    }   

该函数内每一个函数的详细解释见[代码](https://github.com/OSH-2018/4-sqrta/blob/master/myattack.c)内的详细注释，这里只说明攻击流程<br>

check数组是一个全局数组，大小是256*4096，用来观察哪个值的读取时间快来确认攻击地址的值<br>
首先memset check，这一步非常重要，否则该数组会有一些值存留在cache中<br>
pread读取一个文件，参考的是proc 猜测效果是保证清空cache<br>
flush将check的所有内容从cache中清空<br>
//_mm_mfence(); proc中所说是提高成功率，不过去掉后在我的电脑中也能成功<br>
attack 尝试攻击指定地址的内容，即用该地址的内容作为下标读取check的内容，虽然由于权限不会实际加载，但由于指令预执行会在check数组里留下痕迹，即cache会出现变化<br>
reload 检查check数组里每个值的提取时间，最少那个即猜测结果。<br>

将上述重复1000次即得到了一个字节的猜测结果,本次试验读取了20个地址的内容<br>
