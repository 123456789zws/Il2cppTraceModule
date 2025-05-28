#include <dlfcn.h>
#include <fstream>
#include <cstdio>
#include <string>
#include <sstream>
#include <thread>
#include <map>
#include "log.h"
#include "xdl.h"
#include "dobby.h"
#include "il2cpp_trace.h"

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

char data_dir_path[PATH_MAX];
static uint64_t il2cpp_base = 0;
uint64_t funaddrs[MAX_HOOK_FUN_NUM];
int hook_fun_num=0;
std::map<long,std::string> fun_name_dict;

void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}


int init_il2cpp_fun(){
    char* il2cpp_module_name = "libil2cpp.so";
    void *handle = xdl_open(il2cpp_module_name, 0);
    if (handle) {
        int flag = -1;
        init_il2cpp_api(handle);
        if(il2cpp_capture_memory_snapshot && il2cpp_free_captured_memory_snapshot && il2cpp_class_get_methods && il2cpp_method_get_name){
            flag = 0;
            Dl_info dlInfo;
            if (dladdr((void *) il2cpp_capture_memory_snapshot, &dlInfo)) {
                il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
                LOGD("il2cpp_base: %llx", il2cpp_base);
            }
        }
        return flag;
    } else{
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
    return -1;
}

char* get_data_dir_path(){
    char data_dir_path[PATH_MAX];
    std::ifstream file("/proc/self/cmdline");
    if (!file.is_open()) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf(); // 读取文件内容到 stringstream
    snprintf(data_dir_path, PATH_MAX, "/data/data/%s",buffer.str().c_str());
    file.close();
    return data_dir_path;
}

char *get_trace_info(char *trace_file_path){
    FILE* file = fopen(trace_file_path, "r");
    if (!file) {
        LOGE("can not open:%s",trace_file_path);
        return NULL;
    }

    char buffer[1024];
    char last_line[1024];
    while (fgets(buffer, sizeof(buffer), file)){
        strcpy(last_line,buffer);
    }

    fclose(file);
    return last_line;
}

void trace_call_back(RegisterContext *ctx, const HookEntryInfo *info){
    long fun_offset = (uint64_t)info->target_address-il2cpp_base;
    LOGD("%s is calling,offset:0x%llx",fun_name_dict[fun_offset].c_str(),fun_offset);
    return;
}


void hook_all_fun(){
    for (int i = 0; i < hook_fun_num; i++) {
        DobbyInstrument((void *)funaddrs[i], trace_call_back);
    }
    LOGD("success hook all fun");
}

void check_all_methods(void *klass,char *clazzName) {
    void *iter = nullptr;
    long fun_offset;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer) {
            char full_name[MAX_FULL_NAME_LEN];
            auto method_name = il2cpp_method_get_name(method);
            snprintf(full_name,MAX_FULL_NAME_LEN,"%s::%s",clazzName,method_name);
//            LOGD("method_name:%s",full_name);
            fun_offset = (uint64_t)method->methodPointer - il2cpp_base;
            std::string mfull_name(full_name);
            fun_name_dict[fun_offset]=mfull_name;
            funaddrs[hook_fun_num] = (uint64_t)method->methodPointer;
            hook_fun_num++;
        }
    }
    LOGD("success get all fun");
}

void trace_type_info(Il2CppMetadataType type_info,char *clazzName) {
    auto klass = reinterpret_cast<void *>(type_info.typeInfoAddress);
    check_all_methods(klass,clazzName);
}



void start_trace(char* data_dir_path){
    char trace_file_path[PATH_MAX];

    int init_ret = init_il2cpp_fun();
    if(init_ret == -1){
        LOGE("can not get some fun addr");
        return;
    }
    LOGD("success get il2cpp api fun");


    strcpy(trace_file_path,data_dir_path);
    strcat(trace_file_path,"/files/test_trace.txt");
    LOGD("get trace_file_path:%s",trace_file_path);

    char* tinfo = get_trace_info(trace_file_path);
    if (tinfo == NULL || tinfo[0] == '\0') {
        LOGE("can not get any trace item");
        return;
    }
    LOGD("get trace item:%s",tinfo);

//    char test_assemblyName[100];
    char test_clazzName[240];
    strcpy(test_clazzName,tinfo);
    test_clazzName[strlen(test_clazzName)-1] = '\0';

//    char* split_str = strstr(tinfo,"+");
//    if(split_str==NULL){
//        LOGE("can not find split char +");
//        return;
//    }
//
//    strncpy(test_assemblyName,tinfo,split_str-tinfo);
//    strcpy(test_clazzName,split_str+1);
//    test_clazzName[strlen(test_clazzName)-1] = '\0';
//    LOGD("assemblyName:%s,clazzName:%s",test_assemblyName,test_clazzName);

    if (il2cpp_base!=0) {
        auto memorySnapshot = il2cpp_capture_memory_snapshot();
        auto all_type_infos_count = memorySnapshot->metadata.typeCount;
        auto all_type_infos = memorySnapshot->metadata.types;
        LOGD("all_typeCount:%d",all_type_infos_count);
        for (int i = 0; i < all_type_infos_count; ++i) {
            if(strcmp(all_type_infos[i].name,test_clazzName)==0){
                LOGD("trace start");
                trace_type_info(all_type_infos[i],all_type_infos[i].name);
                break;
            }
        }
        il2cpp_stop_gc_world();
        hook_all_fun();
        il2cpp_start_gc_world();
        il2cpp_free_captured_memory_snapshot(memorySnapshot);
    } else {
        LOGE("unknow error");
    }


}



void trace_entry(){
    strcpy(data_dir_path,get_data_dir_path());
    if (data_dir_path == NULL || data_dir_path[0] == '\0') {
        LOGE("Failed to open cmdline");
        return;
    }

    LOGI("game dir:%s", data_dir_path);
    std::thread il2cpp_trace_thread(start_trace, data_dir_path);
    il2cpp_trace_thread.detach();

}
__attribute__((section(".init_array"))) void (*start_fun)() = trace_entry;