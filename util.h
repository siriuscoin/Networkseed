#ifndef _UTIL_H_
#define _UTIL_H_ 1

#include <pthread.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdarg.h>

#include "uint256.h"
#include "sph_keccak.h"
#include "sph_types.h"

#define loop                for (;;)
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

#define WSAGetLastError()   errno
#define WSAEINVAL           EINVAL
#define WSAEALREADY         EALREADY
#define WSAEWOULDBLOCK      EWOULDBLOCK
#define WSAEMSGSIZE         EMSGSIZE
#define WSAEINTR            EINTR
#define WSAEINPROGRESS      EINPROGRESS
#define WSAEADDRINUSE       EADDRINUSE
#define WSAENOTSOCK         EBADF
#define INVALID_SOCKET      (SOCKET)(~0)
#define SOCKET_ERROR        -1

// Wrapper to automatically initialize mutex
class CCriticalSection
{
protected:
    pthread_rwlock_t mutex;
public:
    explicit CCriticalSection() { pthread_rwlock_init(&mutex, NULL); }
    ~CCriticalSection() { pthread_rwlock_destroy(&mutex); }
    void Enter(bool fShared = false) { 
      if (fShared) {
        pthread_rwlock_rdlock(&mutex);
      } else {
        pthread_rwlock_wrlock(&mutex);
      }
    }
    void Leave() { pthread_rwlock_unlock(&mutex); }
};

// Automatically leave critical section when leaving block, needed for exception safety
class CCriticalBlock
{
protected:
    CCriticalSection* pcs;
public:
    CCriticalBlock(CCriticalSection& cs, bool fShared = false) : pcs(&cs) { pcs->Enter(fShared); }
    operator bool() const { return true; }
    ~CCriticalBlock() { pcs->Leave(); }
};

#define CRITICAL_BLOCK(cs)     \
    if (CCriticalBlock criticalblock = CCriticalBlock(cs))

#define SHARED_CRITICAL_BLOCK(cs)     \
    if (CCriticalBlock criticalblock = CCriticalBlock(cs, true))

template<typename T1>
inline uint256 HashSHA2(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T1>
inline uint256 HashSHA3(const T1 pbegin, const T1 pend)
{
    sph_keccak256_context ctx_keccak;
    static unsigned char pblank[1];
    uint256 hash1;
    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_keccak256_close(&ctx_keccak, static_cast<void*>(&hash1));
    return hash1;
}

void static inline Sleep(int nMilliSec) {
    struct timespec wa;
    wa.tv_sec = nMilliSec/1000;
    wa.tv_nsec = (nMilliSec % 1000) * 1000000;
    nanosleep(&wa, NULL);
}


std::string vstrprintf(const std::string &format, va_list ap);

std::string static inline strprintf(const std::string &format, ...) {
    va_list arg_ptr;
    va_start(arg_ptr, format);
    std::string ret = vstrprintf(format, arg_ptr);
    va_end(arg_ptr);
    return ret;
}

bool static inline error(std::string err, ...) {
    return false;
}

bool static inline my_printf(std::string err, ...) {
    return true;
}

std::vector<unsigned char> DecodeBase32(const char* p, bool* pfInvalid = NULL);
std::string DecodeBase32(const std::string& str);
std::string EncodeBase32(const unsigned char* pch, size_t len);
std::string EncodeBase32(const std::string& str);

#endif
