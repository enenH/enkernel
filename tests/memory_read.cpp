// Standalone authorized-device regression; never loads/unloads a module.
#include <dfm/driver.h>
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>
static void require(bool ok,const char* what){
    if(!ok){std::fprintf(stderr,"FAIL: %s errno=%d\n",what,errno);std::exit(1);}
}
static uint64_t pagemap(int fd,uintptr_t va,size_t page){
    uint64_t entry=0;require(pread(fd,&entry,8,off_t((va/page)*8))==8,"read pagemap");return entry;
}
static void describe_driver(){
    struct utsname info{};
    if(!uname(&info))
        std::printf("kernel=%s machine=%s\n",info.release,info.machine);
    dfm_capabilities_req caps{};caps.abi_version=DFM_CAPABILITIES_ABI_VERSION;
    errno=0;
    const int result=ioctl(dfm::native_handle(),MEM_IOC_CAPABILITIES,&caps);
    const int error=result<0?errno:0;
    std::printf("capabilities: result=%d errno=%d abi=%u features=0x%llx\n",
        result,error,caps.out_abi_version,static_cast<unsigned long long>(caps.out_features));
    std::puts("Capability bits do not identify the loaded module commit or prove swap support.");
}
static bool read_fixture(bool cache,uintptr_t address,void* output,size_t size,const char* phase){
    const bool ok=cache?dfm::read_memory_cache(getpid(),address,output,size):
        dfm::read_memory(getpid(),address,output,size);
    const long result=dfm::last_ioctl_result();
    if(!ok){
        const int error=result<0?int(-result):0;
        std::fprintf(stderr,"FAIL: %s op=%s ioctl_result=%ld errno=%d (%s) size=%zu\n",
            phase,cache?"READ_CACHE":"READ",result,error,std::strerror(error),size);
        if(error==EOPNOTSUPP)
            std::fputs("Check CONFIG_SWAP, detected reader ABI and missing swap helper symbols.\n",stderr);
        else if(error==EFAULT)
            std::fputs("EFAULT alone does not identify the cause; verify the loaded module and mapping.\n",stderr);
        else if(error==EAGAIN)
            std::fputs("The mapping/backing identity changed during the read.\n",stderr);
        else if(error==EIO)
            std::fputs("Swap cache acquisition or backing I/O failed.\n",stderr);
    }
    return ok;
}
int main(){
    require(geteuid()==0,"run as root for own pagemap");
    require(dfm::init(),"connect already loaded matching driver");
    describe_driver();
    const auto page=size_t(sysconf(_SC_PAGESIZE));const auto size=16*page;
    auto* memory=static_cast<unsigned char*>(mmap(nullptr,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    require(memory!=MAP_FAILED,"map private anonymous fixture");
    const int map=open("/proc/self/pagemap",O_RDONLY|O_CLOEXEC);require(map>=0,"open own pagemap");
    std::vector<unsigned char> expected(size),output(size,0x55);
    for(size_t i=0;i<size;++i)expected[i]=static_cast<unsigned char>((i*37+i/page)%251);
    std::memcpy(memory,expected.data(),size);
    if(!read_fixture(true,uintptr_t(memory),output.data(),size,"resident"))return 1;
    require(output==expected,"resident bytes match");
    std::fill(output.begin(),output.end(),0x55);
    if(!read_fixture(false,uintptr_t(memory)+page-7,output.data(),page+13,"cross-page"))return 1;
    require(!std::memcmp(output.data(),expected.data()+page-7,page+13),"cross-page bytes match");
    require(!dfm::read_memory(getpid(),0,output.data(),page),"unmapped memory must fail");
    // Swapping is advisory. A run without an observed swapped PTE is a skip,
    // never evidence that the new backing path succeeded.
    int pageout_error=0;size_t swapped=0;
    std::vector<uint64_t> before(16);
    for(unsigned attempt=0;attempt<20&&!swapped;++attempt){
        if(madvise(memory,size,MADV_PAGEOUT)){pageout_error=errno;break;}
        usleep(10000);
        for(size_t i=0;i<16;++i){before[i]=pagemap(map,uintptr_t(memory)+i*page,page);swapped+=bool(before[i]&(1ULL<<62));}
    }
    if(!swapped){
        std::printf("SKIP: resident checks passed, no swapped PTE observed (pageout errno=%d)\n",pageout_error);
        close(map);munmap(memory,size);dfm::close();return 77;
    }
    std::printf("fixture: page_size=%zu swapped_pages=%zu total_pages=16\n",page,swapped);
    for(unsigned cache=0;cache<2;++cache){
        std::fill(output.begin(),output.end(),0x55);
        if(!read_fixture(cache,uintptr_t(memory),output.data(),size,"swap/mixed"))return 1;
        require(output==expected,"swap/mixed bytes equal pre-pageout data");
        for(size_t i=0;i<16;++i)if(before[i]&(1ULL<<62)){
            const auto after=pagemap(map,uintptr_t(memory)+i*page,page);
            require((after&(1ULL<<62)) && !(after&(1ULL<<63)) &&
                ((after^before[i])&((1ULL<<55)-1))==0,"same swap slot remains, target PTE not faulted in");
        }
    }
    std::printf("PASS: resident and swap reads; swapped_pages=%zu, target PTEs unchanged\n",swapped);
    close(map);munmap(memory,size);dfm::close();return 0;
}
