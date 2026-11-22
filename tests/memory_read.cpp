// Standalone authorized-device regression; never loads/unloads a module.
#include <dfm/driver.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
static void require(bool ok,const char* what){
    if(!ok){std::fprintf(stderr,"FAIL: %s errno=%d\n",what,errno);std::exit(1);}
}
static uint64_t pagemap(int fd,uintptr_t va,size_t page){
    uint64_t entry=0;require(pread(fd,&entry,8,off_t((va/page)*8))==8,"read pagemap");return entry;
}
int main(){
    require(geteuid()==0,"run as root for own pagemap");
    require(dfm::init(),"connect already loaded matching driver");
    const auto page=size_t(sysconf(_SC_PAGESIZE));const auto size=16*page;
    auto* memory=static_cast<unsigned char*>(mmap(nullptr,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    require(memory!=MAP_FAILED,"map private anonymous fixture");
    const int map=open("/proc/self/pagemap",O_RDONLY|O_CLOEXEC);require(map>=0,"open own pagemap");
    std::vector<unsigned char> expected(size),output(size,0x55);
    for(size_t i=0;i<size;++i)expected[i]=static_cast<unsigned char>((i*37+i/page)%251);
    std::memcpy(memory,expected.data(),size);
    require(dfm::read_memory_cache(getpid(),uintptr_t(memory),output.data(),size)&&output==expected,"resident cache-clean read");
    require(dfm::read_memory(getpid(),uintptr_t(memory)+page-7,output.data(),page+13)&&
        !std::memcmp(output.data(),expected.data()+page-7,page+13),"resident cross-page read");
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
    for(unsigned cache=0;cache<2;++cache){
        const bool ok=cache?dfm::read_memory_cache(getpid(),uintptr_t(memory),output.data(),size):
            dfm::read_memory(getpid(),uintptr_t(memory),output.data(),size);
        require(ok&&output==expected,"swap/mixed bytes equal pre-pageout data");
        for(size_t i=0;i<16;++i)if(before[i]&(1ULL<<62)){
            const auto after=pagemap(map,uintptr_t(memory)+i*page,page);
            require((after&(1ULL<<62)) && !(after&(1ULL<<63)) &&
                ((after^before[i])&((1ULL<<55)-1))==0,"same swap slot remains, target PTE not faulted in");
        }
    }
    std::printf("PASS: resident and swap reads; swapped_pages=%zu, target PTEs unchanged\n",swapped);
    close(map);munmap(memory,size);dfm::close();return 0;
}
