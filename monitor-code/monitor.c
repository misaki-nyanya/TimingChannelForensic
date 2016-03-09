/*
compile: gcc monitor.c -o monitor -lvmi -lpthread
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include "log.h"
//#define MEM_DEBUG

//#define LOG_TO_DB
#define MAX_PROCESSES 32764
#define ACCESS_R 0
#define ACCESS_W 1
#define ACCESS_X 2
//#define MAX_PROCESSES 32764
//#define NPAGES 1024*256 
//262144
#define NPAGES 200000
//#define IGNORE_PID 2121
#define MAXPID 10000

typedef unsigned long long ticks;

ticks cpu_init_ticks;			// duration of request in cpu ticks
unsigned long long nano_seconds;	// duration of request in nanoseconds
unsigned long long cpu_speed;		// aprox cpu speed 
ticks start_ticks;  //now ticks

int count=0;

reg_t cr3;
int register_all_time_count = 0;  
int ignore_pid=2185;

vmi_instance_t vmi = NULL;

vmi_event_t mem_monitor_event[NPAGES];
int event_flag[202];

typedef struct task_info{
    vmi_pid_t pid;
    char *procname;
}task_info;

task_info ta[MAXPID];
addr_t pgd_flag[MAXPID];
int ta_flag = 0;

uint64_t vmid;
FILE *fp;
char *procname = NULL;
vmi_pid_t pid = 0;

MYSQL mysql;


unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0,mm_offset = 0,pgd_offset = 0;


/**
 * get_ticks
 *
 * runs assembly code to get number of cpu ticks 
 * 
 * @return	number of cpu ticks since cpu started
*/
ticks get_ticks()
{
	ticks           ret = 0;
	unsigned long   minor = 0;
	unsigned long   mayor = 0;

	asm             volatile(
                                                 "cpuid \n"
				                 "rdtsc"
				 :               "=a"(minor),
				                 "=d"(mayor)
                                 : "a" (0)
                                 : "%ebx", "%ecx"
	);

	ret = ((((ticks) mayor) << 32) | ((ticks) minor));

	return ret;
}
/** 
 * get_aprox_cpu_speed
 *
 * calculates the current cpu clock speed
 *
 * @return	cpu speed in number of ticks
*/
unsigned long long get_aprox_cpu_speed(){

	unsigned long long speed;
	ticks start_ticks, end_ticks;
	start_ticks = get_ticks();
	sleep(1);
	end_ticks = get_ticks();
	speed = (end_ticks - start_ticks);

	return speed;

}

/** 
 * convert_ticks_to_nanosecs
 *
 * calculates how much time in nanoseconds has passed 
 * at given ticks on a cpu with a given frequency
 * saves the result to nano_seconds
 *
 * @param no_ticks	number of cpu ticks 
 * @param speed		cpu speed in Hz
*/
double convert_ticks_to_nanosecs(ticks no_ticks, long long speed){
	double nano_seconds = 0.0;
	nano_seconds = (double)no_ticks / (double)speed * 1000000000.0;
	return nano_seconds;
}


void init_process_list(vmi_instance_t vmi){
    unsigned char *memory = NULL;
    uint32_t offset;
    addr_t list_head = 0, next_list_entry = 0;
    addr_t task_pgd = 0;
    addr_t current_process = 0;
    addr_t tmp_next = 0;

    
    addr_t ptr = 0;
    status_t status;
    uint8_t width = 0;

    /* get the head of the list */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        /* Begin at PID 0, the 'swapper' task. It's not typically shown by OS
         *  utilities, but it is indeed part of the task list and useful to
         *  display as such.
         */
        list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;
    }

    next_list_entry = list_head;
    width = vmi_get_address_width (vmi);
    /* walk the task list */
    do {
        ptr = 0;
        current_process = next_list_entry - tasks_offset;
    vmi_read_addr_va(vmi, current_process + mm_offset, 0, &ptr);

 
        if(!ptr && width)
            vmi_read_addr_va(vmi, current_process + mm_offset + width, 0, &ptr);
        vmi_read_addr_va(vmi, ptr + pgd_offset, 0, &task_pgd);
        task_pgd = vmi_translate_kv2p(vmi, task_pgd);
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);
        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        pgd_flag[ta_flag] = task_pgd;
        ta[ta_flag].pid = pid;
        ta[ta_flag].procname = procname;
        ta_flag ++;
        /* follow the next pointer */

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            goto error_exit;
        }
    } while(next_list_entry != list_head);

    error_exit:
    return ;
}

int get_task_info(vmi_instance_t vmi,addr_t pgd){
    unsigned char *memory = NULL;
    uint32_t offset;
    addr_t list_head = 0, next_list_entry = 0;
    addr_t task_pgd = 0;
    addr_t current_process = 0;
    addr_t tmp_next = 0;
    int i = 0;
    
    addr_t ptr = 0;
    status_t status;
    uint8_t width = 0;

    if(ta_flag > 1)
    for(i = ta_flag-1;i>=0;i--){
        if(pgd_flag[i] == pgd)
            return i;
    }


    /* get the head of the list */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
         /*Begin at PID 0, the 'swapper' task. It's not typically shown by OS
         *  utilities, but it is indeed part of the task list and useful to
         *  display as such.*/
         
        list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;
    }

    next_list_entry = list_head;
    width = vmi_get_address_width (vmi);
    /* walk the task list */
    do {
        ptr = 0;
        current_process = next_list_entry - tasks_offset;
        vmi_read_addr_va(vmi, current_process + mm_offset, 0, &ptr);

 
        if(!ptr && width)
            vmi_read_addr_va(vmi, current_process + mm_offset + width, 0, &ptr);
        vmi_read_addr_va(vmi, ptr + pgd_offset, 0, &task_pgd);
        task_pgd = vmi_translate_kv2p(vmi, task_pgd);
        if (task_pgd == pgd) {
            vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);
            procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
            pgd_flag[ta_flag] = task_pgd;
            ta[ta_flag].pid = pid;
            ta[ta_flag].procname = procname;
            ta_flag ++;
            return ta_flag-1;
        } 
        /* follow the next pointer */

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
            goto error_exit;
        }
    } while(next_list_entry != list_head);

error_exit:
    return -1;
}

void print_event(vmi_event_t event){

#if defined MEM_DEBUG
    printf("PAGE %"PRIx64" ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
        event.mem_event.physical_address,
        (event.mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event.mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event.mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event.mem_event.gfn,
        event.mem_event.offset,
        event.mem_event.gla,
        event.vcpu_id
    );
#endif
    fprintf(fp,"PAGE %"PRIx64" ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
        event.mem_event.physical_address,
        (event.mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event.mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event.mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event.mem_event.gfn,
        event.mem_event.offset,
        event.mem_event.gla,
        event.vcpu_id
    );
}

void dr_event_re_register_all(){
    int i = 0;
#if defined MEM_DEBUG
    printf("event_re_register_all start...!\n");
#endif
    if(count > 0 ) return;
    for(i=1;i<=count;i++){
        if(vmi_register_event(vmi,&mem_monitor_event[event_flag[i]]) == VMI_FAILURE)
            fprintf(stderr, "event_re_register_all.Could not install mem_monitor handler.\n");  
    }
    count = 0;
}


void dr_event_re_register(){
    int i = 0,j=0;
    int wait_num = 3;
#if defined MEM_DEBUG 
    printf("event_re_register start...!\n");

#endif
    if(count < wait_num ) return;
    for(i=1;i<=(count-wait_num);i++){
        if(vmi_register_event(vmi,&mem_monitor_event[event_flag[i]]) == VMI_FAILURE)
            fprintf(stderr, "event_re_register.Could not install mem_monitor handler.\n");   
    }
    for(j=1;i<=count;i++,j++){
        event_flag[j] = event_flag[i];
    }
    count = wait_num;
}



void mem_monitor_cb(vmi_instance_t vmi, vmi_event_t *event){
    int task_flag = 0;
    int access = 0;
    register_all_time_count = 0;
    vmi_pid_t current_pid = 0;
    vmi_get_vcpureg(vmi, &cr3, CR3, event->vcpu_id);
    start_ticks = get_ticks() - cpu_init_ticks;
    nano_seconds = convert_ticks_to_nanosecs(start_ticks,cpu_speed);
    //printf("CPU Speed: %llu\n", cpu_speed);
    //current_pid = vmi_dtb_to_pid(vmi, cr3);
    task_flag = get_task_info(vmi,cr3);
    if(ta[task_flag].pid > ignore_pid){
   // if(current_pid > ignore_pid){
#ifdef MEM_DEBUG 

#endif

#ifdef LOG_TO_DB
	if(event->mem_event.out_access & VMI_MEMACCESS_R)access = ACCESS_R;
	else if(event->mem_event.out_access & VMI_MEMACCESS_W)access = ACCESS_W;
	else if(event->mem_event.out_access & VMI_MEMACCESS_X)access = ACCESS_X;
        insert_memMonitorInfoTable(&mysql,
            ta[task_flag].pid,
            cr3,
            ta[task_flag].procname,
            nano_seconds,
            event->mem_event.physical_address,
            access,
            event->mem_event.gfn,
            event->mem_event.offset,
	        event->mem_event.gla,
            event->vcpu_id);
#endif
        fprintf(fp,"PID: %"PRIi32", CR3=%"PRIx64", PROCNAME=%s ",ta[task_flag].pid,cr3,ta[task_flag].procname);
 	//fprintf(fp,"PID: %"PRIi32", CR3=%"PRIx64", ",current_pid,cr3);
        fprintf(fp,"Time: %llu nanosec , ",  nano_seconds);
        fprintf(fp,"PAGE %"PRIx64" ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"PRIx64") gla %016"PRIx64" (vcpu %"PRIu32")\n",
        event->mem_event.physical_address,
        (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event->mem_event.gfn,
        event->mem_event.offset,
        event->mem_event.gla,
        event->vcpu_id
        );
    } /* */
    vmi_clear_event(vmi, event);
    
    if(ta[task_flag].pid < ignore_pid)return;
   // if(current_pid < ignore_pid)return;
    count++;
    event_flag[count] = (int)event->data;
    if(count > 5){
#ifdef MEM_DEBUG 
	printf("PID: %"PRIi32", CR3=%"PRIx64", ",current_pid,cr3);
        printf("thread count: %d\n",count);
#endif

    dr_event_re_register();
    }
}

static int interrupted = 0;
static void close_handler(int sig){
    interrupted = sig;
}


int main (int argc, char **argv)
{
    int ret = 0;
    int err = 0;
    pthread_t id;
    status_t status = VMI_SUCCESS;
    int i = 0,j = 0;
    struct sigaction act;

    addr_t size = 0;
    addr_t address = 0;
    char *name = NULL;
    vmi_pid_t pid = -1;
    uint64_t npages = 0;
   

    if(argc < 2){
        fprintf(stderr, "Usage: events_example <name of VM> [<ignore_pid>]\n");
        exit(1);
    }

    // Arg 1 is the VM name.
    name = argv[1];
    if(argc == 3){
        ignore_pid = (int) strtoul(argv[2], NULL, 0);
    }

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if((fp = fopen(name,"a+")) == NULL){
        printf("can not open file\n");
        return 1;
    }
    // Initialize the libvmi library.
    if (vmi_init(&vmi, VMI_XEN | VMI_INIT_COMPLETE | VMI_INIT_EVENTS, name) == VMI_FAILURE){
        printf("Failed to init LibVMI library.\n");
        if (vmi != NULL ) {
            vmi_destroy(vmi);
        }
        fclose(fp);
        return 1;
    }
    else{
        printf("LibVMI init succeeded!\n");
    }
        /* init the offset values */
    if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
        tasks_offset = vmi_get_offset(vmi, "linux_tasks");
        name_offset = vmi_get_offset(vmi, "linux_name");
        pid_offset = vmi_get_offset(vmi, "linux_pid");
        mm_offset = vmi_get_offset(vmi, "linux_mm");
        pgd_offset = vmi_get_offset(vmi, "linux_pgd");
    }

    if (0 == tasks_offset) {
        printf("Failed to find win_tasks\n");
        goto leave;
    }
    if (0 == pid_offset) {
        printf("Failed to find win_pid\n");
        goto leave;
    }
    if (0 == name_offset) {
        printf("Failed to find win_pname\n");
        goto leave;
    }

#ifdef LOG_TO_DB
    mysql = init_db();
    err = check_db(&mysql,DB_NAME);
    if(err != 0)
    {
        printf("create db is err!\n");
        mysql_close(&mysql);  
        exit(1);  
    }    
    //select which db  
    if(mysql_select_db(&mysql,DB_NAME)) //return 0 is success ,!0 is err  
    {   
        perror("mysql_select_db:");  
        mysql_close(&mysql);  
        exit(1);  
    } 

    if((err=check_table_memMonitorInfoTable(&mysql,TABLE_NAME_MEM_MONITOR))!=0)  
    {   
        printf("create mem table is err!\n");  
        mysql_close(&mysql);  
        exit(1);  
    } 
#endif


    init_process_list(vmi); // get process info cache

    vmid = vmi_get_vmid(vmi);
    size = vmi_get_memsize(vmi);
    //size = vmi_get_max_physical_address(vmi);

    for(i = 0;i < NPAGES;i++){
        memset(&mem_monitor_event[i], 0, sizeof(vmi_event_t));
        mem_monitor_event[i].type = VMI_EVENT_MEMORY;
        mem_monitor_event[i].mem_event.physical_address = address;
        mem_monitor_event[i].mem_event.npages = 1;
        mem_monitor_event[i].mem_event.granularity = VMI_MEMEVENT_PAGE;
        mem_monitor_event[i].mem_event.in_access = VMI_MEMACCESS_RWX;
        mem_monitor_event[i].callback = mem_monitor_cb;
        mem_monitor_event[i].data = i;
        if(vmi_register_event(vmi, &mem_monitor_event[i]) == VMI_FAILURE)
            fprintf(stderr, "Could not install mem_monitor handler.\n");

        address += getpagesize();
    }
    //initial timer
    cpu_init_ticks = 0;
    cpu_speed = 0;
    cpu_speed = get_aprox_cpu_speed();
    cpu_init_ticks = get_ticks();

    //start monitoring
    while(!interrupted){
       // printf("Waiting for events...\n");
        register_all_time_count++;
        status = vmi_events_listen(vmi,500);
        if (status != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
        if(register_all_time_count > 2){
            if(count > 0){
                dr_event_re_register_all();
            }    
            register_all_time_count = 0;       
        }
    }
    printf("Finished with test. %d \n",interrupted);
    for(i = 0;i < NPAGES;i++){
        vmi_clear_event(vmi, &mem_monitor_event[i]);
    }

leave:
    // cleanup any memory associated with the libvmi instance
    vmi_destroy(vmi);
    disconnect(&mysql);
    return 0;
}
