#include <sys/syscall.h>
#include <unistd.h>


#define TRACE_FLAG 511
#define MAX_HOOK_NUM 1000
#define SET_TRACE_SUCCESS 1000
#define SET_TRACE_ERROR 1001

enum trace_info {
    SET_TARGET_FILE,
    SET_MODULE_BASE,
    SET_FUN_INFO,
    SET_TARGET_UID,
    CLEAR_UPROBE,
};

//	unsigned long start, size_t len, unsigned char *vec

int set_module_base(unsigned long module_base){
    int ret = syscall(__NR_mincore,module_base,TRACE_FLAG+SET_MODULE_BASE,"");
    return ret;
}

int set_target_uid(uid_t uid){
    int ret = syscall(__NR_mincore,uid,TRACE_FLAG+SET_TARGET_UID,"");
    return ret;
}

int set_target_file(char* file_name){
    int ret = syscall(__NR_mincore,0,TRACE_FLAG+SET_TARGET_FILE,file_name);
    return ret;
}

int set_fun_info(unsigned long fun_offset,char *fun_name){
    int ret = syscall(__NR_mincore,fun_offset,TRACE_FLAG+SET_FUN_INFO,fun_name);
    return ret;
}

//set_fun_info函数设置成功但失效的情况下再用这个函数
//，最好在一个程序内不要与set_fun_info函数同时使用
int set_fun_info2(unsigned long fun_offset,char *fun_name){
    int ret = syscall(__NR_mincore,fun_offset-0x1000,TRACE_FLAG+SET_FUN_INFO,fun_name);
    return ret;
}

int clear_all_uprobes(){
    int ret = syscall(__NR_mincore,0,TRACE_FLAG+CLEAR_UPROBE,"");
    return ret;
}