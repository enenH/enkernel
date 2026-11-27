// Run on an authorized Android device with the matching driver already loaded.
#include <dfm/driver.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "FAIL: %s (errno=%d)\n", message, errno); std::exit(1); }
}
static dfm_file_query_req request(int pid, int fd, unsigned op) {
    dfm_file_query_req req{}; req.pid=pid; req.target_fd=fd; req.op=op; return req;
}
static void success(dfm_file_query_req& req) {
    const auto result=dfm::query_file(req);
    if (result || req.out_errno)
        std::fprintf(stderr, "query op=%u result=%ld errno=%d\n",req.op,result,req.out_errno);
    require(result==0 && req.out_errno==0, "query succeeds");
}
int main() {
    require(dfm::init(), "driver connection");
    struct CloseDriver { ~CloseDriver() { dfm::close(); } } close_driver;
    char path[]="/data/local/tmp/dfm-query.XXXXXX";
    const int fd=mkstemp(path); require(fd>=0, "temporary file");
    struct Cleanup { int fd; const char* path; ~Cleanup() { close(fd); unlink(path); } } cleanup{fd,path};
    require(pwrite(fd,"abc",3,0)==3 && pwrite(fd,"xyz",3,16384)==3, "sparse fixture");
    require(lseek(fd,123,SEEK_SET)==123, "target offset");
    const int reference=open(path,O_RDONLY|O_CLOEXEC); require(reference>=0, "reference file");
    auto req=request(getpid(),fd,DFM_FILE_QUERY_INFO);
    const auto probe=dfm::query_file(req);
    if (probe==-ENOTTY) { std::puts("SKIP: loaded driver has no fd query ABI"); close(reference); return 77; }
    require(probe==0 && req.out_errno==0 && req.out_position==123 && req.out_file_size==16387, "metadata");
    auto raw=req; raw.abi_version=0; raw.out_inode=UINT64_MAX;
    errno=0;
    require(ioctl(dfm::native_handle(),DFM_FILE_IOC_QUERY_FD,&raw)==-1 && errno==EINVAL && raw.out_inode==0,
        "kernel rejects ABI version and clears outputs");
    raw=req; raw.reserved[0]=1; errno=0;
    require(ioctl(dfm::native_handle(),DFM_FILE_IOC_QUERY_FD,&raw)==-1 && errno==EINVAL,
        "kernel rejects reserved fields without SDK validation");
    struct stat metadata{}; require(fstat(fd,&metadata)==0 && req.out_inode==metadata.st_ino &&
        S_ISREG(req.out_mode), "file identity");
    for (int whence:{SEEK_SET,SEEK_CUR,SEEK_END}) {
        req=request(getpid(),fd,DFM_FILE_QUERY_SEEK); req.whence=whence;
        const auto expected=lseek(reference,whence==SEEK_CUR?123:0,whence==SEEK_CUR?SEEK_SET:whence);
        const int error=expected<0?errno:0;
        require(dfm::query_file(req)==0 && req.out_errno==error &&
            (error || req.out_result==expected), "virtual seek matches ordinary file offset");
        require(lseek(fd,0,SEEK_CUR)==123, "seek never changes target offset");
    }
    req=request(getpid(),fd,DFM_FILE_QUERY_SEEK); req.whence=SEEK_CUR; req.offset=-124;
    require(dfm::query_file(req)==0 && req.out_errno==EINVAL, "negative seek result");
    req.offset=INT64_MAX; require(dfm::query_file(req)==0 && req.out_errno==EOVERFLOW, "CUR overflow");
    for (int whence:{SEEK_DATA,SEEK_HOLE}) {
        req=request(getpid(),fd,DFM_FILE_QUERY_SEEK); req.whence=whence;
        require(dfm::query_file(req)==0 && req.out_errno==EOPNOTSUPP && req.out_inode==0,
            "extent seeks are explicitly unsupported");
    }
    char bytes[8]; std::memset(bytes,0x55,sizeof(bytes));
    req=request(getpid(),fd,DFM_FILE_QUERY_PREAD); req.buf=reinterpret_cast<uint64_t>(bytes); req.size=8; req.offset=16384;
    success(req); require(req.out_size==3 && std::memcmp(bytes,"xyz",3)==0 && bytes[3]==0x55, "short read");
    req.offset=16387; success(req); require(req.out_size==0, "EOF");
    req.offset=0; req.size=3; success(req); require(std::memcmp(bytes,"abc",3)==0, "explicit offset");
    require(lseek(fd,0,SEEK_CUR)==123, "pread preserves target offset");
    req.flags=1; require(dfm::query_file(req)==-EINVAL, "unknown flags"); req.flags=0;
    req.reserved[1]=1; require(dfm::query_file(req)==-EINVAL, "reserved input"); req.reserved[1]=0;
    req.size=DFM_FILE_QUERY_MAX_READ+1ULL; require(dfm::query_file(req)==-E2BIG, "read bound");
    req.size=3; req.offset=INT64_MAX; require(dfm::query_file(req)==-EOVERFLOW, "range overflow");
    req.offset=0; req.buf=1; require(dfm::query_file(req)==-EFAULT, "bad user buffer");
    req=request(getpid(),INT32_MAX,DFM_FILE_QUERY_INFO);
    require(dfm::query_file(req)==0 && req.out_errno==EBADF && req.out_inode==0, "invalid target fd");
    int sockets[2]; require(socketpair(AF_UNIX,SOCK_STREAM,0,sockets)==0, "socket fixture");
    req=request(getpid(),sockets[0],DFM_FILE_QUERY_INFO);
    require(dfm::query_file(req)==0 && req.out_errno==EOPNOTSUPP, "socket is never consumed");
    close(sockets[0]); close(sockets[1]);
    const int write_only=open(path,O_WRONLY|O_CLOEXEC); require(write_only>=0, "write-only fixture");
    req=request(getpid(),write_only,DFM_FILE_QUERY_PREAD); req.buf=reinterpret_cast<uint64_t>(bytes); req.size=1;
    require(dfm::query_file(req)==0 && req.out_errno==EBADF, "write-only does not grant reading"); close(write_only);
    const int path_only=open(path,O_PATH|O_CLOEXEC); require(path_only>=0, "O_PATH fixture");
    req=request(getpid(),path_only,DFM_FILE_QUERY_INFO); success(req);
    req.op=DFM_FILE_QUERY_PREAD; req.buf=reinterpret_cast<uint64_t>(bytes); req.size=1;
    require(dfm::query_file(req)==0 && req.out_errno==EBADF, "O_PATH does not grant reading"); close(path_only);
    const int reused=dup(fd); require(reused>=0, "reusable descriptor");
    req=request(getpid(),reused,DFM_FILE_QUERY_INFO); success(req);
    const int null_fd=open("/dev/null",O_RDONLY|O_CLOEXEC); require(null_fd>=0, "replacement descriptor");
    require(dup2(null_fd,reused)==reused, "reuse target fd");
    require(dfm::query_file(req)==0 && req.out_errno==EOPNOTSUPP && req.out_inode==0, "no cached file after fd reuse");
    close(null_fd); close(reused);
    std::atomic<bool> stop{false},changed{false};
    std::thread observer([&] { while (!stop.load()) if (lseek(fd,0,SEEK_CUR)!=123) changed=true; });
    for (int i=0;i<1000;++i) {
        req=request(getpid(),fd,DFM_FILE_QUERY_SEEK); req.whence=SEEK_END; success(req);
    }
    stop=true; observer.join(); require(!changed, "shared description never sees transient seeks");
    int channel[2]; require(pipe(channel)==0, "child coordination");
    const pid_t child=fork(); require(child>=0, "target process");
    if (!child) { close(channel[1]); char byte; const auto n=read(channel[0],&byte,1); _exit(n==0?0:1); }
    close(channel[0]); req=request(child,fd,DFM_FILE_QUERY_PREAD);
    req.buf=reinterpret_cast<uint64_t>(bytes); req.size=3; success(req);
    require(req.out_position==123 && std::memcmp(bytes,"abc",3)==0, "remote PID/FD read");
    close(channel[1]); int child_status=0; require(waitpid(child,&child_status,0)==child, "child exit");
    req=request(child,fd,DFM_FILE_QUERY_INFO); require(dfm::query_file(req)==-ESRCH, "exited target");
    require(unlink(path)==0, "unlink pinned file");
    const int replacement=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
    require(replacement>=0 && write(replacement,"new",3)==3, "replacement pathname");
    close(replacement);
    req=request(getpid(),fd,DFM_FILE_QUERY_PREAD);
    req.buf=reinterpret_cast<uint64_t>(bytes); req.size=3; success(req);
    require(req.out_inode==metadata.st_ino && std::memcmp(bytes,"abc",3)==0,
        "query retains unlinked descriptor identity");
    require(lseek(fd,0,SEEK_CUR)==123, "unlinked read preserves target offset");
    close(reference);
    std::puts("PASS: target fd metadata, virtual seek, pread/EOF, bounds, descriptor identity, concurrency and process exit");
}
