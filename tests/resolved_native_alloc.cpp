// Test-only glibc/Linux preload probe. Compiler -include flags supply native
// declarations; no repository source uses textual includes for this probe.
extern "C" void* __libc_malloc(size_t);
extern "C" void* __libc_calloc(size_t,size_t);
extern "C" void* __libc_realloc(void*,size_t);
extern "C" void __libc_free(void*);
namespace {
    struct Entry {void* pointer;size_t size;};
    constexpr size_t capacity=65536;
    Entry entries[capacity];
    bool active=false,persistent=false,fired=false,overflow=false,calibrated=false;
    unsigned long long calls=0,fail_at=0,live=0,bytes=0,peak=0,mallocs=0,callocs=0,reallocs=0,arrays=0,duplicates=0,bounded_duplicates=0;
    uintptr_t library_first=0,library_last=0;
    thread_local bool inside=false;
    pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    int identify(dl_phdr_info* info,size_t,void*) {
        if(!info->dlpi_name || !strstr(info->dlpi_name,"libsystemd.so"))return 0;
        for(unsigned i=0;i<info->dlpi_phnum;++i)if(info->dlpi_phdr[i].p_type==PT_LOAD && (info->dlpi_phdr[i].p_flags&PF_X)) {
            auto first=info->dlpi_addr+info->dlpi_phdr[i].p_vaddr,last=first+info->dlpi_phdr[i].p_memsz;
            if(!library_first || first<library_first)library_first=first;if(last>library_last)library_last=last;
        }
        return 1;
    }
    auto native(void* address)->bool {auto value=reinterpret_cast<uintptr_t>(address);return value>=library_first && value<library_last;}
    auto fail(void* address,char kind)->bool {
        if(!active || !native(address))return false;
        ++calls;if(kind=='m')++mallocs;else if(kind=='c')++callocs;else if(kind=='r')++reallocs;else if(kind=='a')++arrays;else if(kind=='s')++duplicates;else ++bounded_duplicates;
        if(!fail_at || (persistent ? calls<fail_at : calls!=fail_at))return false;
        fired=true;errno=ENOMEM;return true;
    }
    auto hash(void* value)->size_t {return (reinterpret_cast<uintptr_t>(value)>>4)%capacity;}
    auto track(void* value,size_t size)->void {
        if(!value || !active)return;auto index=hash(value);
        for(size_t i=0;i<capacity;++i) {auto& e=entries[(index+i)%capacity];if(!e.pointer || e.pointer==reinterpret_cast<void*>(uintptr_t{1})){e={value,size};++live;bytes+=size;if(bytes>peak)peak=bytes;return;}}
        overflow=true;
    }
    auto release(void* value)->void {
        if(!value)return;auto index=hash(value);
        for(size_t i=0;i<capacity;++i){auto& e=entries[(index+i)%capacity];if(!e.pointer)return;if(e.pointer==value){--live;bytes-=e.size;e={reinterpret_cast<void*>(uintptr_t{1}),0};return;}}
    }
}
extern "C" void nexus_native_audit_arm(unsigned long long point,int persist) {
    pthread_mutex_lock(&mutex);if(!library_first)dl_iterate_phdr(identify,nullptr);
    calls=fail_at=live=bytes=peak=mallocs=callocs=reallocs=arrays=duplicates=bounded_duplicates=0;fail_at=point;persistent=persist;fired=overflow=false;
    for(auto& entry:entries)entry={};active=true;pthread_mutex_unlock(&mutex);
}
extern "C" void nexus_native_audit_disarm(){pthread_mutex_lock(&mutex);active=false;pthread_mutex_unlock(&mutex);}
extern "C" unsigned long long nexus_native_audit_value(int field) {
    pthread_mutex_lock(&mutex);unsigned long long result=0;
    switch(field){case 0:result=calls;break;case 1:result=live;break;case 2:result=bytes;break;case 3:result=peak;break;case 4:result=fired;break;case 5:result=overflow;break;case 6:result=mallocs;break;case 7:result=callocs;break;case 8:result=reallocs;break;case 9:result=library_first!=0;break;case 10:result=calibrated;break;case 11:result=arrays;break;case 12:result=duplicates;break;case 13:result=bounded_duplicates;break;}
    pthread_mutex_unlock(&mutex);return result;
}
extern "C" void* malloc(size_t size) noexcept {
    if(inside)return __libc_malloc(size);inside=true;pthread_mutex_lock(&mutex);auto failure=fail(__builtin_return_address(0),'m');void* result=failure ? nullptr : __libc_malloc(size);track(result,size);pthread_mutex_unlock(&mutex);inside=false;return result;
}
extern "C" void* calloc(size_t count,size_t size) noexcept {
    if(inside)return __libc_calloc(count,size);inside=true;pthread_mutex_lock(&mutex);auto failure=fail(__builtin_return_address(0),'c');void* result=failure ? nullptr : __libc_calloc(count,size);if(!count || size<=SIZE_MAX/count)track(result,count*size);pthread_mutex_unlock(&mutex);inside=false;return result;
}
extern "C" void* realloc(void* pointer,size_t size) noexcept {
    if(inside)return __libc_realloc(pointer,size);inside=true;pthread_mutex_lock(&mutex);auto failure=fail(__builtin_return_address(0),'r');void* result=failure ? nullptr : __libc_realloc(pointer,size);if(result || (!size && !failure))release(pointer);if(result)track(result,size);pthread_mutex_unlock(&mutex);inside=false;return result;
}
extern "C" void free(void* pointer) noexcept {
    if(inside){__libc_free(pointer);return;}inside=true;pthread_mutex_lock(&mutex);release(pointer);__libc_free(pointer);pthread_mutex_unlock(&mutex);inside=false;
}

extern "C" void* reallocarray(void* pointer,size_t count,size_t size) noexcept {
    if(count && size>SIZE_MAX/count){errno=ENOMEM;return nullptr;}
    auto bytes=count*size;if(inside)return __libc_realloc(pointer,bytes);inside=true;pthread_mutex_lock(&mutex);
    auto failure=fail(__builtin_return_address(0),'a');void* result=failure ? nullptr : __libc_realloc(pointer,bytes);
    if(result || (!bytes && !failure))release(pointer);if(result)track(result,bytes);
    pthread_mutex_unlock(&mutex);inside=false;return result;
}
extern "C" char* strdup(char const* source) noexcept {
    auto size=strlen(source)+1;
    if(inside){auto result=static_cast<char*>(__libc_malloc(size));if(result)memcpy(result,source,size);return result;}
    inside=true;pthread_mutex_lock(&mutex);auto failure=fail(__builtin_return_address(0),'s');auto result=failure ? nullptr : static_cast<char*>(__libc_malloc(size));
    if(result)memcpy(result,source,size);track(result,size);pthread_mutex_unlock(&mutex);inside=false;return result;
}
extern "C" char* strndup(char const* source,size_t bound) noexcept {
    auto length=strnlen(source,bound),size=length+1;
    if(inside){auto result=static_cast<char*>(__libc_malloc(size));if(result){memcpy(result,source,length);result[length]=0;}return result;}
    inside=true;pthread_mutex_lock(&mutex);auto failure=fail(__builtin_return_address(0),'n');auto result=failure ? nullptr : static_cast<char*>(__libc_malloc(size));
    if(result){memcpy(result,source,length);result[length]=0;}track(result,size);pthread_mutex_unlock(&mutex);inside=false;return result;
}
