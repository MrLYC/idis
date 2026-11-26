#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <VideoToolbox/VideoToolbox.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <IOKit/IOMessage.h>
#import <IOKit/pwr_mgt/IOPMLib.h>
#import <ApplicationServices/ApplicationServices.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <os/lock.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

extern char **environ;

typedef void (*IDDiagCallback)(const char *event, const char *detail);
static _Atomic(IDDiagCallback) gDiagCallback = NULL;

void id_macos_set_diag_callback(IDDiagCallback cb) {
    atomic_store_explicit(&gDiagCallback, cb, memory_order_release);
}

static void id_diag_log(const char *event, NSString *fmt, ...) NS_FORMAT_FUNCTION(2, 3);
static void id_diag_log(const char *event, NSString *fmt, ...) {
    IDDiagCallback cb = atomic_load_explicit(&gDiagCallback, memory_order_acquire);
    if (!cb || !event || !fmt) return;
    @autoreleasepool {
        va_list args;
        va_start(args, fmt);
        NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
        va_end(args);
        cb(event, msg.UTF8String ?: "");
    }
}

typedef void (*IDFrameCallback)(
    void *ctx,
    uint32_t width,
    uint32_t height,
    uint32_t bytes_per_row,
    int32_t is_keyframe,
    const uint8_t *data,
    size_t len
);

typedef struct {
    char user_name[128];
    char host_name[256];
    char os_version[256];
    uint64_t physical_memory;
    uint64_t cpu_count;
} IDHostInfo;

void id_macos_get_host_info(IDHostInfo *out) {
    @autoreleasepool {
        if (!out) return;
        memset(out, 0, sizeof(*out));
        NSProcessInfo *pi = [NSProcessInfo processInfo];
        NSString *user = pi.environment[@"USER"] ?: NSUserName() ?: @"user";
        NSString *host = [[NSHost currentHost] localizedName] ?: pi.hostName ?: @"Mac";
        NSString *ver = pi.operatingSystemVersionString ?: @"macOS";
        strlcpy(out->user_name, user.UTF8String, sizeof(out->user_name));
        strlcpy(out->host_name, host.UTF8String, sizeof(out->host_name));
        strlcpy(out->os_version, ver.UTF8String, sizeof(out->os_version));
        out->physical_memory = (uint64_t)pi.physicalMemory;
        out->cpu_count = (uint64_t)pi.processorCount;
    }
}

// ============================================================================
// Private CGVirtualDisplay method signatures (compile-time declarations only;
// classes are resolved dynamically via NSClassFromString so ARC manages
// +1 init returns safely without raw objc_msgSend UB).
// ============================================================================

@protocol IDCGVirtualDisplayModeProto <NSObject>
- (nullable instancetype)initWithWidth:(NSUInteger)width height:(NSUInteger)height refreshRate:(double)refreshRate;
@end

@protocol IDCGVirtualDisplayProto <NSObject>
- (nullable instancetype)initWithDescriptor:(id)descriptor;
- (BOOL)applySettings:(id)settings;
@end

// ============================================================================
// Bonjour publisher (_MSM_Video_Control_Service._tcp. & _MSM_Video_Service._tcp.)
// Uses IOKit IORegisterForSystemPower so wake republish works in headless CLI!
// ============================================================================

#include <time.h>

@interface IDBonjourRunner : NSObject <NSNetServiceDelegate> {
@public
    _Atomic BOOL _stopped;
    _Atomic uint64_t _republishAfterNs;
    io_connect_t _powerPort;
    IONotificationPortRef _powerNotifyPort;
    io_object_t _powerNotifier;
}
@property (nonatomic, copy) NSString *serviceName;
@property (nonatomic, assign) uint16_t telemetryPort;
@property (nonatomic, assign) uint16_t dataPort;
@property (nonatomic, strong) NSNetService *telemetryService;
@property (nonatomic, strong) NSNetService *dataService;
@property (nonatomic, strong) NSThread *runThread;
@property (nonatomic, strong) dispatch_queue_t powerQueue;
@end

static uint64_t id_monotonic_ns(void) {
    return clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
}

static void bonjour_power_callback(void *refCon, io_service_t service, natural_t messageType, void *messageArgument) {
    (void)service;
    IDBonjourRunner *runner = (__bridge IDBonjourRunner *)refCon;
    if (!runner) return;
    switch (messageType) {
        case kIOMessageCanSystemSleep:
        case kIOMessageSystemWillSleep:
            if (runner->_powerPort) {
                IOAllowPowerChange(runner->_powerPort, (long)messageArgument);
            }
            break;
        case kIOMessageSystemHasPoweredOn:
            if (!atomic_load_explicit(&runner->_stopped, memory_order_acquire)) {
                // Delay 2.0s after wake so Wi-Fi/DHCP associates before republishing fresh NSNetService instances.
                uint64_t target = id_monotonic_ns() + (uint64_t)(2000ULL * NSEC_PER_MSEC);
                atomic_store_explicit(&runner->_republishAfterNs, target, memory_order_release);
            }
            break;
        default:
            break;
    }
}

@implementation IDBonjourRunner
- (void)startWithName:(NSString *)name telemetryPort:(uint16_t)tPort dataPort:(uint16_t)dPort {
    atomic_store_explicit(&_stopped, NO, memory_order_release);
    atomic_store_explicit(&_republishAfterNs, 0, memory_order_release);
    self.serviceName = name ?: @"Mac";
    self.telemetryPort = tPort;
    self.dataPort = dPort;

    self.powerQueue = dispatch_queue_create("idis.mac.bonjour.power", DISPATCH_QUEUE_SERIAL);
    _powerPort = IORegisterForSystemPower((__bridge void *)self, &_powerNotifyPort, bonjour_power_callback, &_powerNotifier);
    if (_powerPort && _powerNotifyPort) {
        IONotificationPortSetDispatchQueue(_powerNotifyPort, self.powerQueue);
    }

    self.runThread = [[NSThread alloc] initWithTarget:self selector:@selector(threadMain) object:nil];
    self.runThread.name = @"idis-bonjour";
    [self.runThread start];
}

- (void)publishFreshOnRunLoop:(NSRunLoop *)rl {
    if (self.telemetryService) {
        self.telemetryService.delegate = nil;
        [self.telemetryService stop];
        [self.telemetryService removeFromRunLoop:rl forMode:NSDefaultRunLoopMode];
        self.telemetryService = nil;
    }
    if (self.dataService) {
        self.dataService.delegate = nil;
        [self.dataService stop];
        [self.dataService removeFromRunLoop:rl forMode:NSDefaultRunLoopMode];
        self.dataService = nil;
    }
    self.telemetryService = [[NSNetService alloc] initWithDomain:@"local."
                                                            type:@"_MSM_Video_Control_Service._tcp."
                                                            name:self.serviceName
                                                            port:(int)self.telemetryPort];
    self.dataService = [[NSNetService alloc] initWithDomain:@"local."
                                                       type:@"_MSM_Video_Service._tcp."
                                                       name:self.serviceName
                                                       port:(int)self.dataPort];
    self.telemetryService.delegate = self;
    self.dataService.delegate = self;
    [self.telemetryService scheduleInRunLoop:rl forMode:NSDefaultRunLoopMode];
    [self.dataService scheduleInRunLoop:rl forMode:NSDefaultRunLoopMode];
    [self.telemetryService publish];
    [self.dataService publish];
}

- (void)netServiceDidPublish:(NSNetService *)sender {
    id_diag_log("bonjour_published", @"type=%@ port=%ld", sender.type, (long)sender.port);
}

- (void)netService:(NSNetService *)sender didNotPublish:(NSDictionary<NSString *, NSNumber *> *)errorDict {
    id_diag_log("bonjour_publish_err", @"type=%@ err=%@", sender.type, errorDict);
    if (!atomic_load_explicit(&_stopped, memory_order_acquire)) {
        uint64_t retryAt = id_monotonic_ns() + (uint64_t)(3000ULL * NSEC_PER_MSEC);
        atomic_store_explicit(&_republishAfterNs, retryAt, memory_order_release);
    }
}

- (void)netServiceDidStop:(NSNetService *)sender {
    (void)sender;
}

- (void)threadMain {
    @autoreleasepool {
        NSRunLoop *rl = [NSRunLoop currentRunLoop];
        [self publishFreshOnRunLoop:rl];
        while (!atomic_load_explicit(&_stopped, memory_order_acquire)) {
            BOOL ran = [rl runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.25]];
            if (!ran && !atomic_load_explicit(&_stopped, memory_order_acquire)) {
                usleep(250000);
            }
            uint64_t due = atomic_load_explicit(&_republishAfterNs, memory_order_acquire);
            if (due != 0 && id_monotonic_ns() >= due) {
                if (atomic_compare_exchange_strong_explicit(
                        &_republishAfterNs, &due, 0, memory_order_acq_rel, memory_order_acquire)
                    && !atomic_load_explicit(&_stopped, memory_order_acquire)) {
                    id_diag_log("bonjour_republish", @"name=%@", self.serviceName);
                    [self publishFreshOnRunLoop:rl];
                }
            }
        }
        if (self.telemetryService) {
            self.telemetryService.delegate = nil;
            [self.telemetryService stop];
        }
        if (self.dataService) {
            self.dataService.delegate = nil;
            [self.dataService stop];
        }
        [rl runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    }
}

- (void)stop {
    atomic_store_explicit(&_stopped, YES, memory_order_release);
    if (_powerNotifier) {
        IODeregisterForSystemPower(&_powerNotifier);
        _powerNotifier = 0;
    }
    if (_powerNotifyPort) {
        IONotificationPortDestroy(_powerNotifyPort);
        _powerNotifyPort = NULL;
    }
    // Drain powerQueue BEFORE closing _powerPort so any in-flight callback sees a valid port.
    if (self.powerQueue) {
        dispatch_sync(self.powerQueue, ^{});
    }
    if (_powerPort) {
        IOServiceClose(_powerPort);
        _powerPort = 0;
    }
}
@end

void *id_macos_bonjour_start(const char *service_name, uint16_t telemetry_port, uint16_t data_port) {
    @autoreleasepool {
        IDBonjourRunner *runner = [IDBonjourRunner new];
        NSString *name = service_name ? [NSString stringWithUTF8String:service_name] : @"Mac";
        [runner startWithName:name telemetryPort:telemetry_port dataPort:data_port];
        return (__bridge_retained void *)runner;
    }
}

void id_macos_bonjour_stop(void *handle) {
    @autoreleasepool {
        if (!handle) return;
        IDBonjourRunner *runner = (__bridge_transfer IDBonjourRunner *)handle;
        [runner stop];
    }
}

// ============================================================================
// Subprocess display-mode helper (bypasses macOS CoreGraphics creator-process
// cache bug where CGDisplayCopyAllDisplayModes returns NULL for virtual displays
// created in a process that already initialized CoreGraphics).
// ============================================================================

int32_t id_macos_helper_set_display_mode(
    uint32_t display_id,
    uint32_t logical_w,
    uint32_t logical_h,
    uint32_t pixel_w,
    uint32_t pixel_h
) {
    @autoreleasepool {
        if (display_id == kCGNullDirectDisplay || logical_w < 320 || logical_h < 240) {
            printf("invalid_args\n");
            fflush(stdout);
            return 1;
        }
        NSDictionary *opts = @{ (__bridge NSString *)kCGDisplayShowDuplicateLowResolutionModes: @YES };
        CFArrayRef modes = NULL;
        for (int attempt = 0; attempt < 8; attempt++) {
            modes = CGDisplayCopyAllDisplayModes((CGDirectDisplayID)display_id, (__bridge CFDictionaryRef)opts);
            if (modes && CFArrayGetCount(modes) > 0) {
                break;
            }
            if (modes) {
                CFRelease(modes);
                modes = NULL;
            }
            usleep(40000);
        }
        if (!modes) {
            printf("modes_null\n");
            fflush(stdout);
            return 1;
        }

        CGDisplayModeRef exactMatch = NULL;
        CGDisplayModeRef pixelHiDPIMatch = NULL;
        CGDisplayModeRef logicalMatch = NULL;
        CFIndex count = CFArrayGetCount(modes);
        for (CFIndex i = 0; i < count; i++) {
            CGDisplayModeRef m = (CGDisplayModeRef)CFArrayGetValueAtIndex(modes, i);
            size_t lw = CGDisplayModeGetWidth(m);
            size_t lh = CGDisplayModeGetHeight(m);
            size_t pw = CGDisplayModeGetPixelWidth(m);
            size_t ph = CGDisplayModeGetPixelHeight(m);
            if (lw == logical_w && lh == logical_h && pw == pixel_w && ph == pixel_h) {
                exactMatch = m;
                break;
            }
            if (!pixelHiDPIMatch && pixel_w > logical_w && pw == pixel_w && ph == pixel_h && lw < pw) {
                pixelHiDPIMatch = m;
            }
            if (!logicalMatch && lw == logical_w && lh == logical_h) {
                logicalMatch = m;
            }
        }

        CGDisplayModeRef chosen = exactMatch ?: (pixelHiDPIMatch ?: logicalMatch);
        int32_t rc = 1;
        if (chosen) {
            CGError err = CGDisplaySetDisplayMode((CGDirectDisplayID)display_id, chosen, NULL);
            printf(
                "%s chosen=%zux%zu(%zux%zu) err=%d count=%ld\n",
                exactMatch ? "exact" : (pixelHiDPIMatch ? "hidpi_pix" : "logical"),
                CGDisplayModeGetWidth(chosen),
                CGDisplayModeGetHeight(chosen),
                CGDisplayModeGetPixelWidth(chosen),
                CGDisplayModeGetPixelHeight(chosen),
                (int)err,
                (long)count
            );
            if (err == kCGErrorSuccess) {
                rc = exactMatch ? 0 : 2;
            }
        } else {
            NSMutableString *avail = [NSMutableString string];
            for (CFIndex i = 0; i < count && i < 16; i++) {
                CGDisplayModeRef m = (CGDisplayModeRef)CFArrayGetValueAtIndex(modes, i);
                [avail appendFormat:@"%zux%zu(%zux%zu) ",
                    CGDisplayModeGetWidth(m),
                    CGDisplayModeGetHeight(m),
                    CGDisplayModeGetPixelWidth(m),
                    CGDisplayModeGetPixelHeight(m)];
            }
            printf("miss count=%ld avail=[%s]\n", (long)count, avail.UTF8String ?: "");
        }
        fflush(stdout);
        CFRelease(modes);
        return rc;
    }
}

static BOOL id_spawn_set_display_mode_helper(
    CGDirectDisplayID displayID,
    uint32_t logicalW,
    uint32_t logicalH,
    uint32_t wantPixW,
    uint32_t wantPixH
) {
    char rawPath[4096];
    uint32_t pathSize = sizeof(rawPath);
    if (_NSGetExecutablePath(rawPath, &pathSize) != 0) {
        return NO;
    }
    char resolvedPath[PATH_MAX];
    const char *exePath = realpath(rawPath, resolvedPath) ? resolvedPath : rawPath;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return NO;
    }
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    char idBuf[32], lwBuf[32], lhBuf[32], pwBuf[32], phBuf[32];
    snprintf(idBuf, sizeof(idBuf), "%u", (unsigned)displayID);
    snprintf(lwBuf, sizeof(lwBuf), "%u", logicalW);
    snprintf(lhBuf, sizeof(lhBuf), "%u", logicalH);
    snprintf(pwBuf, sizeof(pwBuf), "%u", wantPixW);
    snprintf(phBuf, sizeof(phBuf), "%u", wantPixH);

    char *argv[] = {
        (char *)exePath,
        (char *)"--internal-macos-set-display-mode",
        idBuf,
        lwBuf,
        lhBuf,
        pwBuf,
        phBuf,
        NULL
    };

    pid_t pid = -1;
    int spawnRc = posix_spawn(&pid, exePath, &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);
    if (spawnRc != 0 || pid <= 0) {
        close(pipefd[0]);
        id_diag_log("vd_set_mode_helper_err", @"spawnRc=%d", spawnRc);
        return NO;
    }

    char outBuf[512];
    size_t outLen = 0;
    int status = 0;
    BOOL exited = NO;
    for (int i = 0; i < 125; i++) {
        struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
        if (poll(&pfd, 1, 20) > 0 && outLen + 1 < sizeof(outBuf)) {
            ssize_t n = read(pipefd[0], outBuf + outLen, sizeof(outBuf) - 1 - outLen);
            if (n > 0) outLen += (size_t)n;
        }
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            exited = YES;
            break;
        }
    }
    if (!exited) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    while (outLen + 1 < sizeof(outBuf)) {
        ssize_t n = read(pipefd[0], outBuf + outLen, sizeof(outBuf) - 1 - outLen);
        if (n <= 0) break;
        outLen += (size_t)n;
    }
    close(pipefd[0]);
    while (outLen > 0 && (outBuf[outLen - 1] == '\n' || outBuf[outLen - 1] == '\r')) {
        outLen--;
    }
    outBuf[outLen] = '\0';

    int exitCode = (exited && WIFEXITED(status)) ? WEXITSTATUS(status) : -1;
    id_diag_log(
        "vd_set_mode_helper",
        @"displayID=%u req=%ux%u wantPix=%ux%u rc=%d out=%s",
        (unsigned)displayID,
        logicalW,
        logicalH,
        wantPixW,
        wantPixH,
        exitCode,
        outBuf[0] ? outBuf : "<empty>"
    );
    return (exitCode == 0);
}

// ============================================================================
// Runtime CGVirtualDisplay wrapper
// ============================================================================

@interface IDVirtualDisplayWrapper : NSObject
@property (nonatomic, strong) id displayObj;
@property (nonatomic, assign) CGDirectDisplayID displayID;
@property (nonatomic, assign) uint32_t hiDPI;
@property (nonatomic, assign) BOOL lastModeMatchedExact;
@end

@implementation IDVirtualDisplayWrapper

+ (BOOL)isAvailable {
    return NSClassFromString(@"CGVirtualDisplay") != nil &&
           NSClassFromString(@"CGVirtualDisplayDescriptor") != nil &&
           NSClassFromString(@"CGVirtualDisplaySettings") != nil &&
           NSClassFromString(@"CGVirtualDisplayMode") != nil;
}

- (nullable instancetype)initWithWidth:(uint32_t)width
                                height:(uint32_t)height
                                 hiDPI:(uint32_t)hiDPI
                             serialNum:(uint32_t)serialNum
                                  name:(NSString *)name
                    terminationHandler:(nullable void (^)(id display, NSError * _Nullable error))termHandler {
    self = [super init];
    if (!self) return nil;
    if (![IDVirtualDisplayWrapper isAvailable]) return nil;

    self.hiDPI = hiDPI >= 2 ? 2 : 1;
    // Keep maxPixels, sizeInMillimeters, vendorID, productID, and serialNum deterministic across
    // reconnects so macOS WindowServer recognizes the same monitor and preserves arrangement & windows.
    // 7680x4320 supports up to 4K 2x HiDPI modes without WindowServer clamping away requested modes.
    uint32_t maxW = 7680;
    uint32_t maxH = 4320;
    uint32_t stableSerial = serialNum != 0 ? serialNum : 0x49440001u;

    Class descCls = NSClassFromString(@"CGVirtualDisplayDescriptor");
    id desc = [descCls new];
    [desc setValue:(name ?: @"idis") forKey:@"name"];
    [desc setValue:@(maxW) forKey:@"maxPixelsWide"];
    [desc setValue:@(maxH) forKey:@"maxPixelsHigh"];
    // Match physical panel aspect ratio (~132 pt/inch / ~264 PPI iPad Retina) so WindowServer
    // recognizes portrait vs landscape orientation accurately (e.g. 197x148mm landscape, 148x197mm portrait).
    double mmW = MAX(80.0, MIN(600.0, (double)width * 25.4 / 132.0));
    double mmH = MAX(80.0, MIN(600.0, (double)height * 25.4 / 132.0));
    CGSize sizeMM = CGSizeMake(mmW, mmH);
    [desc setValue:[NSValue valueWithSize:sizeMM] forKey:@"sizeInMillimeters"];
    [desc setValue:@(0x1E6D) forKey:@"vendorID"];
    [desc setValue:@(0x5B11) forKey:@"productID"];
    [desc setValue:@(stableSerial) forKey:@"serialNum"];
    [desc setValue:dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0) forKey:@"queue"];
    if (termHandler && [desc respondsToSelector:NSSelectorFromString(@"setTerminationHandler:")]) {
        [desc setValue:termHandler forKey:@"terminationHandler"];
    }

    Class dispCls = NSClassFromString(@"CGVirtualDisplay");
    if (![dispCls instancesRespondToSelector:@selector(initWithDescriptor:)]) return nil;
    id allocDisp = [dispCls alloc];
    id disp = [(id<IDCGVirtualDisplayProto>)allocDisp initWithDescriptor:desc];
    if (!disp) return nil;
    self.displayObj = disp;
    NSNumber *didNum = [disp valueForKey:@"displayID"];
    self.displayID = didNum ? didNum.unsignedIntValue : kCGNullDirectDisplay;

    if (![self applyWidth:width height:height]) {
        self.displayObj = nil;
        self.displayID = kCGNullDirectDisplay;
        return nil;
    }

    if (self.displayID == kCGNullDirectDisplay) {
        didNum = [disp valueForKey:@"displayID"];
        self.displayID = didNum ? didNum.unsignedIntValue : kCGNullDirectDisplay;
    }
    if (self.displayID == kCGNullDirectDisplay) {
        self.displayObj = nil;
        return nil;
    }
    return self;
}

- (BOOL)selectMatchingCGDisplayModeLogicalW:(uint32_t)logicalW logicalH:(uint32_t)logicalH {
    if (self.displayID == kCGNullDirectDisplay) return NO;
    uint32_t wantPixW = logicalW * (self.hiDPI >= 2 ? 2 : 1);
    uint32_t wantPixH = logicalH * (self.hiDPI >= 2 ? 2 : 1);
    NSDictionary *opts = @{ (__bridge NSString *)kCGDisplayShowDuplicateLowResolutionModes: @YES };
    CFArrayRef modes = CGDisplayCopyAllDisplayModes(self.displayID, (__bridge CFDictionaryRef)opts);
    if (!modes || CFArrayGetCount(modes) == 0) {
        if (modes) CFRelease(modes);
        // CoreGraphics returns NULL for virtual displays created after CG init in the same process;
        // invoke our lightweight child helper which sees the full WindowServer mode table cleanly.
        return id_spawn_set_display_mode_helper(self.displayID, logicalW, logicalH, wantPixW, wantPixH);
    }

    CGDisplayModeRef exactMatch = NULL;
    CGDisplayModeRef pixelHiDPIMatch = NULL;
    CGDisplayModeRef logicalMatch = NULL;
    CFIndex count = CFArrayGetCount(modes);
    for (CFIndex i = 0; i < count; i++) {
        CGDisplayModeRef m = (CGDisplayModeRef)CFArrayGetValueAtIndex(modes, i);
        size_t lw = CGDisplayModeGetWidth(m);
        size_t lh = CGDisplayModeGetHeight(m);
        size_t pw = CGDisplayModeGetPixelWidth(m);
        size_t ph = CGDisplayModeGetPixelHeight(m);
        if (lw == logicalW && lh == logicalH && pw == wantPixW && ph == wantPixH) {
            exactMatch = m;
            break;
        }
        if (!pixelHiDPIMatch && wantPixW > logicalW && pw == wantPixW && ph == wantPixH && lw < pw) {
            pixelHiDPIMatch = m;
        }
        if (!logicalMatch && lw == logicalW && lh == logicalH) {
            logicalMatch = m;
        }
    }
    CGDisplayModeRef chosen = exactMatch ?: (pixelHiDPIMatch ?: logicalMatch);
    BOOL exactOk = NO;
    if (chosen) {
        CGError err = CGDisplaySetDisplayMode(self.displayID, chosen, NULL);
        exactOk = (exactMatch != NULL && err == kCGErrorSuccess);
        id_diag_log(
            "vd_set_mode",
            @"displayID=%u req=%ux%u wantPix=%ux%u chosen=%zux%zu(%zux%zu) err=%d",
            self.displayID,
            logicalW,
            logicalH,
            wantPixW,
            wantPixH,
            CGDisplayModeGetWidth(chosen),
            CGDisplayModeGetHeight(chosen),
            CGDisplayModeGetPixelWidth(chosen),
            CGDisplayModeGetPixelHeight(chosen),
            (int)err
        );
    } else {
        NSMutableString *avail = [NSMutableString string];
        for (CFIndex i = 0; i < count && i < 12; i++) {
            CGDisplayModeRef m = (CGDisplayModeRef)CFArrayGetValueAtIndex(modes, i);
            [avail appendFormat:@"%zux%zu(%zux%zu) ",
                CGDisplayModeGetWidth(m),
                CGDisplayModeGetHeight(m),
                CGDisplayModeGetPixelWidth(m),
                CGDisplayModeGetPixelHeight(m)];
        }
        id_diag_log(
            "vd_set_mode_miss",
            @"displayID=%u req=%ux%u wantPix=%ux%u count=%ld avail=[%@]",
            self.displayID,
            logicalW,
            logicalH,
            wantPixW,
            wantPixH,
            (long)count,
            avail
        );
    }
    CFRelease(modes);
    return exactOk;
}

- (BOOL)applyWidth:(uint32_t)width height:(uint32_t)height {
    if (!self.displayObj) return NO;
    Class modeCls = NSClassFromString(@"CGVirtualDisplayMode");
    if (![modeCls instancesRespondToSelector:@selector(initWithWidth:height:refreshRate:)]) return NO;

    NSMutableArray *modeList = [NSMutableArray array];
    // When HiDPI is requested, explicitly publish BOTH the 2x backing pixel mode (2w x 2h) AND
    // the 1x logical mode (w x h) so WindowServer reliably exposes `w x h @ 2x` even for non-16-
    // aligned resolutions like 1440x1080 (2880x2160) on macOS 12-15+.
    if (self.hiDPI >= 2 && (width * 2) <= 7680 && (height * 2) <= 4320) {
        id pixMode = [(id<IDCGVirtualDisplayModeProto>)[modeCls alloc] initWithWidth:(NSUInteger)(width * 2)
                                                                              height:(NSUInteger)(height * 2)
                                                                         refreshRate:60.0];
        if (pixMode) [modeList addObject:pixMode];
    }
    id logMode = [(id<IDCGVirtualDisplayModeProto>)[modeCls alloc] initWithWidth:(NSUInteger)width
                                                                          height:(NSUInteger)height
                                                                     refreshRate:60.0];
    if (logMode) [modeList addObject:logMode];
    if (modeList.count == 0) return NO;

    Class settingsCls = NSClassFromString(@"CGVirtualDisplaySettings");
    id settings = [settingsCls new];
    [settings setValue:@(self.hiDPI >= 2 ? 1 : 0) forKey:@"hiDPI"];
    [settings setValue:modeList forKey:@"modes"];

    if (![self.displayObj respondsToSelector:@selector(applySettings:)]) return NO;
    BOOL ok = [(id<IDCGVirtualDisplayProto>)self.displayObj applySettings:settings];
    id_diag_log("vd_apply", @"req=%ux%u hiDPI=%u modes=%lu ok=%d displayID=%u", width, height, self.hiDPI, (unsigned long)modeList.count, ok ? 1 : 0, self.displayID);
    if (ok) {
        self.lastModeMatchedExact = [self selectMatchingCGDisplayModeLogicalW:width logicalH:height];
    } else {
        self.lastModeMatchedExact = NO;
    }
    return ok;
}
@end

// ============================================================================
// VideoToolbox H.264 Annex-B Encoder + ScreenCaptureKit
// ============================================================================

static const uint8_t kAnnexBStartCode[4] = {0x00, 0x00, 0x00, 0x01};

static void clamp_encoded_dimensions(uint32_t *w, uint32_t *h, uint32_t maxEdge) {
    uint32_t tw = *w;
    uint32_t th = *h;
    uint32_t cap = (maxEdge >= 320 ? maxEdge : 2048) & ~1u;
    if (tw > cap) {
        th = (uint32_t)((((uint64_t)th * cap + tw / 2) / tw));
        tw = cap;
    }
    if (th > cap) {
        tw = (uint32_t)((((uint64_t)tw * cap + th / 2) / th));
        th = cap;
    }
    if (tw < 320) tw = 320;
    if (th < 240) th = 240;
    uint32_t ew = (tw + 1u) & ~1u;
    uint32_t eh = (th + 1u) & ~1u;
    *w = ew <= cap ? ew : cap;
    *h = eh <= cap ? eh : cap;
}

@interface IDCaptureController : NSObject <SCStreamOutput, SCStreamDelegate> {
@public
    _Atomic BOOL _stopped;
    _Atomic BOOL _sleeping;
    _Atomic BOOL _paused;
    _Atomic BOOL _lowPower;
    _Atomic BOOL _forceNextKeyframe;
    _Atomic BOOL _hasPendingEncode;
    _Atomic BOOL _loggedFirstPb;
    _Atomic uint64_t _generation;
    _Atomic uint32_t _atomicDisplayID;
    // Packed `(width << 32) | height` for torn-free atomic reads from input/cursor threads.
    _Atomic uint64_t _atomicSize;
    // Cached global display bounds populated from `SCDisplay.frame` / `CGDisplayBounds` so mouse
    // injection & cursor polling never drop to 0x0 if CoreGraphics's local cache lags behind WindowServer.
    os_unfair_lock _boundsLock;
    CGRect _scDisplayFrame;
    // Per-capture input state (avoids cross-display data races & state leakage with multiple screens).
    _Atomic BOOL _suppressRightClickTail;
    double _lastInputLocalX;
    double _lastInputLocalY;
    BOOL _hasLastInputPoint;
    double _scrollRemX;
    double _scrollRemY;
    io_connect_t _powerPort;
    IONotificationPortRef _powerNotifyPort;
    io_object_t _powerNotifier;
    _Atomic uint32_t _vtErrorStreak;
    _Atomic uint64_t _lastVtRebuildNs;
    _Atomic uint64_t _lastEncodeNs;
    // Per-capture client-cursor hotspot (in rendered PNG video-pixel coordinates) & diag dedup.
    _Atomic int32_t _cursorHotX;
    _Atomic int32_t _cursorHotY;
    _Atomic uint64_t _lastCursorDiagKey;
    _Atomic BOOL _atomicShowCursor;
    _Atomic uint64_t _lastScaleHealNs;
}
@property (nonatomic, strong) IDVirtualDisplayWrapper *virtualDisplay;
@property (nonatomic, assign) BOOL useVirtualDisplay;
@property (nonatomic, assign) uint32_t requestedLogicalW;
@property (nonatomic, assign) uint32_t requestedLogicalH;
@property (nonatomic, assign) uint32_t displaySerial;
@property (nonatomic, copy) NSString *displayName;
@property (nonatomic, assign) CGDirectDisplayID displayID;
// Actual encoded video pixel dimensions (sent in H.264 stream & used for touch/cursor scaling).
@property (nonatomic, assign) uint32_t encWidth;
@property (nonatomic, assign) uint32_t encHeight;
@property (nonatomic, assign) uint32_t lastModePixW;
@property (nonatomic, assign) uint32_t lastModePixH;
@property (nonatomic, assign) uint32_t modeCheckCounter;
@property (nonatomic, assign) uint32_t hiDPI;
@property (nonatomic, assign) uint32_t maxPixelEdge;
@property (nonatomic, assign) uint32_t fps;
@property (nonatomic, assign) uint32_t bitrateMbps;
@property (nonatomic, assign) BOOL showCursor;
@property (nonatomic, assign) BOOL allIntra;
@property (nonatomic, assign) IDFrameCallback callback;
@property (nonatomic, assign) void *callbackCtx;
// Serial queue for ScreenCaptureKit sample buffers, VT encoding, and flush/refine timers.
@property (nonatomic, strong) dispatch_queue_t queue;
// Separate serial queue for SCStream start/stop/reconfigure lifecycle (never deadlocks self.queue).
@property (nonatomic, strong) dispatch_queue_t lifecycleQueue;
@property (nonatomic, assign) VTCompressionSessionRef vtSession;
@property (nonatomic, assign) VTCompressionSessionRef refineVtSession;
@property (nonatomic, assign) CVPixelBufferRef lastPixelBuffer;
@property (nonatomic, strong) SCStream *scStream API_AVAILABLE(macos(12.3));
@property (nonatomic, assign) int64_t frameIndex;
@property (nonatomic, assign) int64_t lastPts90k;
@property (nonatomic, assign) BOOL needsRefine;
@property (nonatomic, assign) IOPMAssertionID sleepAssertionID;
@property (nonatomic, strong) dispatch_source_t flushTimer;
@property (nonatomic, strong) dispatch_source_t refineTimer;
@property (nonatomic, strong) NSThread *unlockObserverThread;
@property (nonatomic, assign) CFRunLoopRef unlockRunLoop;
- (void)handleVTEncodeFailure:(OSStatus)status isRefine:(BOOL)isRefine;
- (void)scheduleCaptureRestartAfterMs:(int64_t)delayMs targetW:(uint32_t)targetW targetH:(uint32_t)targetH attempt:(int)attempt;
@end

static BOOL id_is_screen_locked(void) {
    CFDictionaryRef dict = CGSessionCopyCurrentDictionary();
    if (!dict) return NO;
    BOOL locked = NO;
    CFTypeRef val = CFDictionaryGetValue(dict, CFSTR("CGSSessionScreenIsLocked"));
    if (val && CFGetTypeID(val) == CFBooleanGetTypeID()) {
        locked = CFBooleanGetValue((CFBooleanRef)val);
    }
    CFRelease(dict);
    return locked;
}

static void vt_output_callback(
    void *outputCallbackRefCon,
    void *sourceFrameRefCon,
    OSStatus status,
    VTEncodeInfoFlags infoFlags,
    CMSampleBufferRef sampleBuffer
) {
    @autoreleasepool {
        (void)infoFlags;
        BOOL isRefineFrame = (sourceFrameRefCon != NULL);
        IDCaptureController *ctrl = (__bridge IDCaptureController *)outputCallbackRefCon;
        if (status != noErr || !sampleBuffer || !CMSampleBufferDataIsReady(sampleBuffer)) {
            id_diag_log("vt_drop", @"reason=status status=%d refine=%d ready=%d", (int)status, isRefineFrame ? 1 : 0, sampleBuffer ? (int)CMSampleBufferDataIsReady(sampleBuffer) : 0);
            if (ctrl && status != noErr) {
                [ctrl handleVTEncodeFailure:status isRefine:isRefineFrame];
            }
            return;
        }
        if (!ctrl || atomic_load_explicit(&ctrl->_stopped, memory_order_acquire) || !ctrl.callback) return;
        atomic_store_explicit(&ctrl->_vtErrorStreak, 0, memory_order_release);
        if (!isRefineFrame) {
            atomic_store_explicit(&ctrl->_hasPendingEncode, NO, memory_order_release);
        }

        CMBlockBufferRef dataBuf = CMSampleBufferGetDataBuffer(sampleBuffer);
        if (!dataBuf) return;

        // Safely obtain a contiguous view of the CMBlockBuffer.
        // VideoToolbox frequently returns multi-segment (non-contiguous) CMBlockBuffers for large
        // high-detail desktop I-frames; passing NULL for lengthAtOffsetOut and reading up to totalLen
        // would read past the first segment into unrelated memory and corrupt the H.264 bitstream.
        size_t lengthAtOffset = 0;
        size_t totalLen = 0;
        char *rawPtr = NULL;
        NSMutableData *contiguousCopy = nil;
        if (CMBlockBufferGetDataPointer(dataBuf, 0, &lengthAtOffset, &totalLen, &rawPtr) != kCMBlockBufferNoErr || !rawPtr || totalLen == 0) {
            return;
        }
        if (lengthAtOffset < totalLen) {
            contiguousCopy = [NSMutableData dataWithLength:totalLen];
            if (!contiguousCopy || CMBlockBufferCopyDataBytes(dataBuf, 0, totalLen, contiguousCopy.mutableBytes) != kCMBlockBufferNoErr) {
                return;
            }
            rawPtr = (char *)contiguousCopy.mutableBytes;
        }

        // Single-pass scan: count VCL bytes (allowing NAL type 5 IDR and NAL type 1 P-slice in IPPP mode)
        // and verify whether this frame is an IDR keyframe before allocating a single output buffer.
        BOOL hasIDR = NO;
        BOOL hasP = NO;
        size_t vclOutLen = 0;
        size_t offset = 0;
        while (offset + 4 <= totalLen) {
            uint32_t nalLen = 0;
            memcpy(&nalLen, rawPtr + offset, 4);
            nalLen = CFSwapInt32BigToHost(nalLen);
            offset += 4;
            if (nalLen == 0 || offset + nalLen > totalLen) {
                id_diag_log("vt_drop", @"reason=bad_nal_len refine=%d offset=%zu nalLen=%u totalLen=%zu", isRefineFrame ? 1 : 0, offset, nalLen, totalLen);
                return;
            }
            uint8_t nalType = ((uint8_t)rawPtr[offset]) & 0x1F;
            if (nalType == 5) {
                hasIDR = YES;
                vclOutLen += 4 + nalLen;
            } else if (nalType == 1 && !ctrl.allIntra) {
                hasP = YES;
                vclOutLen += 4 + nalLen;
            }
            offset += nalLen;
        }

        if ((!hasIDR && !hasP) || vclOutLen == 0) {
            id_diag_log("vt_drop", @"reason=no_vcl refine=%d totalLen=%zu", isRefineFrame ? 1 : 0, totalLen);
            return;
        }

        CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sampleBuffer);
        size_t psOutLen = 0;
        BOOL hasSPS = NO;
        BOOL hasPPS = NO;
        size_t psCount = 0;
        if (hasIDR && fmt) {
            CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, 0, NULL, NULL, &psCount, NULL);
            for (size_t i = 0; i < psCount; i++) {
                const uint8_t *psPtr = NULL;
                size_t psLen = 0;
                if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, i, &psPtr, &psLen, NULL, NULL) == noErr && psPtr && psLen > 0) {
                    uint8_t psType = psPtr[0] & 0x1F;
                    if (psType == 7) hasSPS = YES;
                    if (psType == 8) hasPPS = YES;
                    psOutLen += 4 + psLen;
                }
            }
        }
        if (hasIDR && (!hasSPS || !hasPPS)) {
            id_diag_log("vt_drop", @"reason=missing_ps refine=%d sps=%d pps=%d", isRefineFrame ? 1 : 0, hasSPS ? 1 : 0, hasPPS ? 1 : 0);
            return;
        }

        // Single allocation & single write pass for SPS + PPS (on IDR) + VCL slices.
        NSMutableData *annexB = [NSMutableData dataWithCapacity:psOutLen + vclOutLen];
        if (hasIDR && fmt) {
            for (size_t i = 0; i < psCount; i++) {
                const uint8_t *psPtr = NULL;
                size_t psLen = 0;
                if (CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, i, &psPtr, &psLen, NULL, NULL) == noErr && psPtr && psLen > 0) {
                    [annexB appendBytes:kAnnexBStartCode length:4];
                    [annexB appendBytes:psPtr length:psLen];
                }
            }
        }
        offset = 0;
        while (offset + 4 <= totalLen) {
            uint32_t nalLen = 0;
            memcpy(&nalLen, rawPtr + offset, 4);
            nalLen = CFSwapInt32BigToHost(nalLen);
            offset += 4;
            uint8_t nalType = ((uint8_t)rawPtr[offset]) & 0x1F;
            if (nalType == 5 || (nalType == 1 && !ctrl.allIntra)) {
                [annexB appendBytes:kAnnexBStartCode length:4];
                [annexB appendBytes:(rawPtr + offset) length:nalLen];
            }
            offset += nalLen;
        }

        if (annexB.length > 0) {
            uint64_t packed = atomic_load_explicit(&ctrl->_atomicSize, memory_order_acquire);
            uint32_t w = (uint32_t)(packed >> 32);
            uint32_t h = (uint32_t)(packed & 0xFFFFFFFFu);
            if (fmt) {
                CMVideoDimensions dims = CMVideoFormatDescriptionGetDimensions(fmt);
                if (dims.width > 0 && dims.height > 0) {
                    w = (uint32_t)dims.width;
                    h = (uint32_t)dims.height;
                    uint64_t nextPacked = (((uint64_t)w) << 32) | (uint64_t)h;
                    atomic_store_explicit(&ctrl->_atomicSize, nextPacked, memory_order_release);
                }
            }
            if (isRefineFrame) {
                id_diag_log("vt_refine_emitted", @"dims=%ux%u bytes=%zu nonContig=%d", w, h, (size_t)annexB.length, contiguousCopy != nil ? 1 : 0);
            }
            IDFrameCallback cb = ctrl.callback;
            void *ctx = ctrl.callbackCtx;
            if (cb && !atomic_load_explicit(&ctrl->_stopped, memory_order_acquire)) {
                cb(ctx, w, h, w * 4, hasIDR ? 1 : 0, (const uint8_t *)annexB.bytes, (size_t)annexB.length);
            }
        }
    }
}

static void capture_power_callback(void *refCon, io_service_t service, natural_t messageType, void *messageArgument);

@implementation IDCaptureController

- (void)queryDisplayLogicalWidth:(uint32_t *)outLogW
                   logicalHeight:(uint32_t *)outLogH
                      pixelWidth:(uint32_t *)outPixW
                     pixelHeight:(uint32_t *)outPixH {
    uint32_t lw = 0, lh = 0, pw = 0, ph = 0;
    CGDisplayModeRef mode = CGDisplayCopyDisplayMode(self.displayID);
    if (mode) {
        lw = (uint32_t)CGDisplayModeGetWidth(mode);
        lh = (uint32_t)CGDisplayModeGetHeight(mode);
        pw = (uint32_t)CGDisplayModeGetPixelWidth(mode);
        ph = (uint32_t)CGDisplayModeGetPixelHeight(mode);
        CGDisplayModeRelease(mode);
    }
    if (outLogW) *outLogW = lw & ~1u;
    if (outLogH) *outLogH = lh & ~1u;
    if (outPixW) *outPixW = pw & ~1u;
    if (outPixH) *outPixH = ph & ~1u;
}

- (void)computeCapturePixelWidth:(uint32_t *)outW
                          height:(uint32_t *)outH
                    logicalWidth:(uint32_t)logicalW
                   logicalHeight:(uint32_t)logicalH {
    uint32_t modeLogW = 0, modeLogH = 0, modeW = 0, modeH = 0;
    [self queryDisplayLogicalWidth:&modeLogW logicalHeight:&modeLogH pixelWidth:&modeW pixelHeight:&modeH];

    uint32_t scale = self.hiDPI >= 2 ? 2 : 1;
    uint32_t targetW = (logicalW * scale) & ~1u;
    uint32_t targetH = (logicalH * scale) & ~1u;

    if (self.virtualDisplay && modeW >= 320 && modeH >= 240) {
        // Use WindowServer's backing pixel size ONLY when it matches the requested logical geometry;
        // otherwise keep the explicitly requested backing size so a slow WindowServer transition
        // never locks us onto stale pre-switch dimensions.
        if (modeLogW == logicalW && modeLogH == logicalH) {
            targetW = modeW;
            targetH = modeH;
        }
    } else if (!self.virtualDisplay && modeW >= 320 && modeH >= 240) {
        // In mirror/main mode, ALWAYS preserve the physical display's native aspect ratio
        // while fitting inside targetW x targetH (and never exceeding physical modeW x modeH).
        uint32_t boundW = MIN(targetW, modeW);
        uint32_t boundH = MIN(targetH, modeH);
        double rx = (double)boundW / (double)modeW;
        double ry = (double)boundH / (double)modeH;
        double r = MIN(rx, ry);
        targetW = ((uint32_t)llround((double)modeW * r)) & ~1u;
        targetH = ((uint32_t)llround((double)modeH * r)) & ~1u;
        if (targetW < 320) targetW = 320;
        if (targetH < 240) targetH = 240;
    }

    clamp_encoded_dimensions(&targetW, &targetH, self.maxPixelEdge);

    self.lastModePixW = modeW;
    self.lastModePixH = modeH;
    if (outW) *outW = targetW;
    if (outH) *outH = targetH;
}

- (void)releaseLastPixelBuffer {
    if (self.lastPixelBuffer) {
        CVPixelBufferRelease(self.lastPixelBuffer);
        self.lastPixelBuffer = NULL;
    }
    self.needsRefine = NO;
}

- (void)destroyEncoders {
    [self releaseLastPixelBuffer];
    if (self.vtSession) {
        VTCompressionSessionCompleteFrames(self.vtSession, kCMTimeInvalid);
        VTCompressionSessionInvalidate(self.vtSession);
        CFRelease(self.vtSession);
        self.vtSession = NULL;
    }
    if (self.refineVtSession) {
        VTCompressionSessionCompleteFrames(self.refineVtSession, kCMTimeInvalid);
        VTCompressionSessionInvalidate(self.refineVtSession);
        CFRelease(self.refineVtSession);
        self.refineVtSession = NULL;
    }
}

- (VTCompressionSessionRef)buildVTSessionWidth:(uint32_t)w height:(uint32_t)h highQualityRefine:(BOOL)isRefine {
    // Do NOT enable EnableLowLatencyRateControl here: on Apple Silicon VideoToolbox it can
    // conflict with AllowTemporalCompression=false and emit non-IDR P-frames, causing permanent
    // corruption whenever a frame is overwritten.
    NSDictionary *encoderSpec = @{
        (__bridge NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @YES,
    };
    VTCompressionSessionRef session = NULL;
    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault,
        (int32_t)w,
        (int32_t)h,
        kCMVideoCodecType_H264,
        (__bridge CFDictionaryRef)encoderSpec,
        NULL,
        NULL,
        vt_output_callback,
        (__bridge void *)self,
        &session
    );
    if (st != noErr || !session) {
        return NULL;
    }

    // Main Profile + CABAC gives ~15-25% higher sharpness/efficiency than Baseline CAVLC at the
    // same intra-only bitrate while remaining universally supported by iOS 12 A7 VTDecompressionSession
    // and all desktop/mobile MSE browsers.
    OSStatus profSt = VTSessionSetProperty(session, kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_Main_AutoLevel);
    if (profSt == noErr) {
        VTSessionSetProperty(session, kVTCompressionPropertyKey_H264EntropyMode, kVTH264EntropyMode_CABAC);
    } else {
        VTSessionSetProperty(session, kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_Baseline_AutoLevel);
        VTSessionSetProperty(session, kVTCompressionPropertyKey_H264EntropyMode, kVTH264EntropyMode_CAVLC);
    }
    BOOL temporal = !self.allIntra && !isRefine;
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowTemporalCompression, temporal ? kCFBooleanTrue : kCFBooleanFalse);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    // CRITICAL: On Apple Silicon, RealTime=true overrides Quality with VT's real-time rate controller.
    // Keep RealTime=true for the motion encoder, and RealTime=false for the idle settle-refine encoder
    // (only used in legacy all-intra mode).
    VTSessionSetProperty(session, kVTCompressionPropertyKey_RealTime, isRefine ? kCFBooleanFalse : kCFBooleanTrue);

    // Stamp explicit BT.709 / sRGB VUI color metadata so iPad and browsers reproduce desktop colors accurately.
    VTSessionSetProperty(session, kVTCompressionPropertyKey_ColorPrimaries, kCVImageBufferColorPrimaries_ITU_R_709_2);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_TransferFunction, kCVImageBufferTransferFunction_ITU_R_709_2);
    VTSessionSetProperty(session, kVTCompressionPropertyKey_YCbCrMatrix, kCVImageBufferYCbCrMatrix_ITU_R_709_2);

    int32_t fpsVal = (int32_t)(self.fps > 0 ? self.fps : 30);
    int32_t maxKeyInterval = temporal ? (fpsVal * 2) : 1;
    OSStatus kiSt = noErr;
    CFNumberRef kiNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &maxKeyInterval);
    if (kiNum) {
        kiSt = VTSessionSetProperty(session, kVTCompressionPropertyKey_MaxKeyFrameInterval, kiNum);
        CFRelease(kiNum);
    }

    // Use identical ExpectedFrameRate so Main_AutoLevel emits a stable SPS level_idc.
    CFNumberRef fpsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &fpsVal);
    if (fpsNum) {
        VTSessionSetProperty(session, kVTCompressionPropertyKey_ExpectedFrameRate, fpsNum);
        CFRelease(fpsNum);
    }

    OSStatus qSt = noErr;
    OSStatus qpSt = noErr;
    OSStatus brSt = noErr;
    OSStatus limitSt = noErr;
    if (isRefine) {
        // Progressive settle-sharpening encoder: encode a single crisp high-quality IDR frame once
        // the screen stops changing (~180ms idle) so small desktop text becomes sharp without
        // emitting 1.7MB+ single-frame bursts on high-res 2560x1920+ wallpapers.
        float qVal = 0.84f;
        CFNumberRef qNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberFloat32Type, &qVal);
        qSt = -1;
        if (qNum) {
            qSt = VTSessionSetProperty(session, kVTCompressionPropertyKey_Quality, qNum);
            CFRelease(qNum);
        }
        int32_t maxQp = 20;
        CFNumberRef qpNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &maxQp);
        if (qpNum) {
            qpSt = VTSessionSetProperty(session, CFSTR("MaxAllowedFrameQP"), qpNum);
            CFRelease(qpNum);
        }
        int64_t refinePeakBytes = 600 * 1024;
        NSArray *refineLimits = @[@(refinePeakBytes), @(1.0)];
        limitSt = VTSessionSetProperty(session, kVTCompressionPropertyKey_DataRateLimits, (__bridge CFArrayRef)refineLimits);
        if (qSt != noErr) {
            int32_t hiBitrate = 36 * 1000000;
            CFNumberRef brNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &hiBitrate);
            if (brNum) {
                brSt = VTSessionSetProperty(session, kVTCompressionPropertyKey_AverageBitRate, brNum);
                CFRelease(brNum);
            }
        }
    } else {
        // Motion encoder: responsive low-latency bitrate with bounded QP so UI text stays legible
        // even during continuous scrolling.
        int32_t bitrate = (int32_t)((self.bitrateMbps > 0 ? self.bitrateMbps : 16) * 1000000);
        CFNumberRef brNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bitrate);
        if (brNum) {
            brSt = VTSessionSetProperty(session, kVTCompressionPropertyKey_AverageBitRate, brNum);
            CFRelease(brNum);
        }
        int64_t peakBytesPerSec = ((int64_t)bitrate / 8) * 3;
        NSArray *dataRateLimits = @[@(peakBytesPerSec), @(1.0)];
        limitSt = VTSessionSetProperty(session, kVTCompressionPropertyKey_DataRateLimits, (__bridge CFArrayRef)dataRateLimits);

        int32_t motionMaxQp = (self.bitrateMbps >= 28) ? 23
                            : (self.bitrateMbps >= 20) ? 25
                            : (self.bitrateMbps >= 12) ? 28
                            : 32;
        CFNumberRef qpNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &motionMaxQp);
        if (qpNum) {
            qpSt = VTSessionSetProperty(session, CFSTR("MaxAllowedFrameQP"), qpNum);
            CFRelease(qpNum);
        }
    }

    OSStatus prepSt = VTCompressionSessionPrepareToEncodeFrames(session);
    id_diag_log(
        "vt_create",
        @"kind=%s dims=%ux%u fps=%d br=%uM profSt=%d kiSt=%d qSt=%d qpSt=%d brSt=%d limitSt=%d prepSt=%d",
        isRefine ? "refine" : "motion",
        w,
        h,
        fpsVal,
        self.bitrateMbps,
        (int)profSt,
        (int)kiSt,
        (int)qSt,
        (int)qpSt,
        (int)brSt,
        (int)limitSt,
        (int)prepSt
    );
    return session;
}

- (BOOL)createEncoderWidth:(uint32_t)w height:(uint32_t)h {
    w = (w & ~1u);
    h = (h & ~1u);
    if (w < 320 || h < 240) return NO;

    [self destroyEncoders];

    VTCompressionSessionRef session = [self buildVTSessionWidth:w height:h highQualityRefine:NO];
    if (!session) {
        return NO;
    }
    self.vtSession = session;
    // Only create a secondary offline refine encoder in legacy all-intra mode when not in low-power mode.
    // In IPPP temporal mode, mixing a second independent VT session's IDR would corrupt the motion
    // session's DPB reference frames; instead the single session emits an on-demand keyframe.
    if (self.allIntra && !atomic_load_explicit(&_lowPower, memory_order_acquire)) {
        self.refineVtSession = [self buildVTSessionWidth:w height:h highQualityRefine:YES];
    } else {
        self.refineVtSession = NULL;
    }
    atomic_store_explicit(&_forceNextKeyframe, YES, memory_order_release);
    self.encWidth = w;
    self.encHeight = h;
    // Only seed `_atomicSize` on initial encoder creation; subsequent ABR/reconfigure updates are
    // published atomically by `vt_output_callback` when the first new-size frame actually emits.
    if (atomic_load_explicit(&_atomicSize, memory_order_acquire) == 0) {
        uint64_t packed = (((uint64_t)w) << 32) | (uint64_t)h;
        atomic_store_explicit(&_atomicSize, packed, memory_order_release);
    }
    return YES;
}

- (void)armIdleFlushTimer {
    if (!self.flushTimer || atomic_load_explicit(&_stopped, memory_order_acquire)) return;
    dispatch_source_set_timer(
        self.flushTimer,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(35 * NSEC_PER_MSEC)),
        DISPATCH_TIME_FOREVER,
        (uint64_t)(5 * NSEC_PER_MSEC)
    );
}

- (void)armRefineTimer {
    if (!self.refineTimer || atomic_load_explicit(&_stopped, memory_order_acquire)) return;
    dispatch_source_set_timer(
        self.refineTimer,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(180 * NSEC_PER_MSEC)),
        DISPATCH_TIME_FOREVER,
        (uint64_t)(20 * NSEC_PER_MSEC)
    );
}

- (void)handleVTEncodeFailure:(OSStatus)status isRefine:(BOOL)isRefine {
    if (atomic_load_explicit(&_stopped, memory_order_acquire)
        || atomic_load_explicit(&_sleeping, memory_order_acquire)) {
        return;
    }
    BOOL fatal = (status == kVTInvalidSessionErr
                  || status == kVTVideoEncoderMalfunctionErr
                  || status == kVTVideoEncoderNotAvailableNowErr);
    uint32_t streak = atomic_fetch_add_explicit(&_vtErrorStreak, 1, memory_order_acq_rel) + 1;
    if (!fatal && streak < 3) {
        return;
    }
    uint64_t now = id_monotonic_ns();
    uint64_t prev = atomic_load_explicit(&_lastVtRebuildNs, memory_order_acquire);
    if (now < prev + (uint64_t)(500ULL * NSEC_PER_MSEC)) {
        return;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &_lastVtRebuildNs, &prev, now, memory_order_acq_rel, memory_order_acquire)) {
        return;
    }
    atomic_store_explicit(&_vtErrorStreak, 0, memory_order_release);
    id_diag_log("vt_rebuild_trigger", @"status=%d refine=%d streak=%u", (int)status, isRefine ? 1 : 0, streak);
    __weak typeof(self) weakSelf = self;
    dispatch_async(self.queue, ^{
        @autoreleasepool {
            IDCaptureController *strongSelf = weakSelf;
            if (!strongSelf
                || atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)) {
                return;
            }
            uint64_t packed = atomic_load_explicit(&strongSelf->_atomicSize, memory_order_acquire);
            uint32_t aw = (uint32_t)(packed >> 32);
            uint32_t ah = (uint32_t)(packed & 0xFFFFFFFFu);
            uint32_t w = strongSelf.encWidth >= 320 ? strongSelf.encWidth : aw;
            uint32_t h = strongSelf.encHeight >= 240 ? strongSelf.encHeight : ah;
            if (![strongSelf createEncoderWidth:w height:h]) {
                id_diag_log("vt_rebuild_failed", @"dims=%ux%u", w, h);
                [strongSelf scheduleCaptureRestartAfterMs:1000 targetW:w targetH:h attempt:1];
            }
        }
    });
}

- (void)encodePixelBuffer:(CVPixelBufferRef)pixelBuffer {
    if (atomic_load_explicit(&_stopped, memory_order_acquire)
        || atomic_load_explicit(&_sleeping, memory_order_acquire)
        || atomic_load_explicit(&_paused, memory_order_acquire)
        || !self.vtSession || !pixelBuffer) return;

    static NSDictionary *kForceKeyFrameProps = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        kForceKeyFrameProps = @{
            (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES,
        };
    });

    BOOL needKeyframe = self.allIntra
        || atomic_exchange_explicit(&_forceNextKeyframe, NO, memory_order_acq_rel);

    // Retain the latest pixel buffer (released on pause/stop) so both legacy all-intra refine
    // and IPPP on-demand `request_keyframe()` can emit an instant IDR on a static desktop!
    if (self.lastPixelBuffer != pixelBuffer) {
        CVPixelBufferRetain(pixelBuffer);
        if (self.lastPixelBuffer) {
            CVPixelBufferRelease(self.lastPixelBuffer);
        }
        self.lastPixelBuffer = pixelBuffer;
    }
    if (self.refineVtSession && !atomic_load_explicit(&_lowPower, memory_order_acquire)) {
        self.needsRefine = YES;
        [self armRefineTimer];
    }

    int32_t effFps = (int32_t)(self.fps > 0 ? self.fps : 30);
    int64_t step90k = 90000 / effFps;
    if (step90k < 1) step90k = 1;
    self.frameIndex++;
    self.lastPts90k += step90k;
    CMTime pts = CMTimeMake(self.lastPts90k, 90000);
    CMTime dur = CMTimeMake(step90k, 90000);
    atomic_store_explicit(&_hasPendingEncode, YES, memory_order_release);
    atomic_store_explicit(&_lastEncodeNs, id_monotonic_ns(), memory_order_release);
    OSStatus encSt = VTCompressionSessionEncodeFrame(
        self.vtSession,
        pixelBuffer,
        pts,
        dur,
        needKeyframe ? (__bridge CFDictionaryRef)kForceKeyFrameProps : NULL,
        NULL,
        NULL
    );
    if (encSt != noErr) {
        id_diag_log("vt_encode_err", @"status=%d", (int)encSt);
        [self handleVTEncodeFailure:encSt isRefine:NO];
        return;
    }
    [self armIdleFlushTimer];
}

// Must only be called on `self.lifecycleQueue`.
- (void)stopScreenCaptureKitLocked {
    if (@available(macOS 12.3, *)) {
        if (self.scStream) {
            SCStream *stream = self.scStream;
            self.scStream = nil;
            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            [stream stopCaptureWithCompletionHandler:^(NSError *err) {
                (void)err;
                dispatch_semaphore_signal(sem);
            }];
            dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)));
        }
    }
}

// Must only be called on `self.lifecycleQueue`.
- (BOOL)startScreenCaptureKitLockedWithWidth:(uint32_t)w height:(uint32_t)h {
    if (@available(macOS 12.3, *)) {
        CGDirectDisplayID targetID = self.displayID;
        uint32_t fps = self.fps > 0 ? self.fps : 30;
        BOOL hasVirtual = (self.virtualDisplay != nil);
        int maxAttempts = hasVirtual ? 8 : 2;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            if (atomic_load_explicit(&_stopped, memory_order_acquire)
                || atomic_load_explicit(&_sleeping, memory_order_acquire)
                || atomic_load_explicit(&_paused, memory_order_acquire)) {
                return NO;
            }
            if (attempt > 0) {
                usleep((useconds_t)(120000 + attempt * 60000));
            }

            dispatch_semaphore_t sem = dispatch_semaphore_create(0);
            uint64_t startGen = atomic_load_explicit(&_generation, memory_order_acquire);
            __block BOOL ok = NO;
            __block BOOL displayMissing = NO;
            __block _Atomic BOOL timedOut = NO;

            [SCShareableContent getShareableContentExcludingDesktopWindows:NO
                                                       onScreenWindowsOnly:YES
                                                         completionHandler:^(SCShareableContent *content, NSError *error) {
                @autoreleasepool {
                    if (atomic_load_explicit(&timedOut, memory_order_acquire)
                        || atomic_load_explicit(&self->_stopped, memory_order_acquire)
                        || atomic_load_explicit(&self->_generation, memory_order_acquire) != startGen) {
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    if (error || !content) {
                        id_diag_log("sc_content_err", @"attempt=%d err=%@", attempt, error ? error.localizedDescription : @"nil");
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    SCDisplay *found = nil;
                    for (SCDisplay *d in content.displays) {
                        if (d.displayID == targetID) {
                            found = d;
                            break;
                        }
                    }
                    if (!found) {
                        if (hasVirtual) {
                            // NEVER fall back to content.displays.firstObject (Mac built-in screen)
                            // when a CGVirtualDisplay was created — retry until SCShareableContent sees it!
                            displayMissing = YES;
                            id_diag_log("sc_virtual_display_missing", @"attempt=%d targetID=%u count=%lu", attempt, targetID, (unsigned long)content.displays.count);
                            dispatch_semaphore_signal(sem);
                            return;
                        }
                        found = content.displays.firstObject;
                    }
                    if (!found) {
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    CGRect scFrame = found.frame;
                    if (scFrame.size.width > 0.0 && scFrame.size.height > 0.0) {
                        os_unfair_lock_lock(&self->_boundsLock);
                        self->_scDisplayFrame = scFrame;
                        os_unfair_lock_unlock(&self->_boundsLock);
                    }

                    SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:found excludingWindows:@[]];
                    SCStreamConfiguration *cfg = [SCStreamConfiguration new];
                    cfg.width = w;
                    cfg.height = h;
                    cfg.scalesToFit = YES;
                    // On macOS 14+, request full Retina backing capture resolution (SCCaptureResolutionBest = 1).
                    if ([cfg respondsToSelector:NSSelectorFromString(@"setCaptureResolution:")]) {
                        [cfg setValue:@(1) forKey:@"captureResolution"];
                    }
                    // Native NV12 (4:2:0 video range) cuts framebuffer bandwidth by 62.5% vs 32BGRA and
                    // feeds VideoToolbox directly without a BGRA->YUV color-space conversion pass.
                    cfg.pixelFormat = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;
                    cfg.colorSpaceName = kCGColorSpaceSRGB;
                    cfg.colorMatrix = kCVImageBufferYCbCrMatrix_ITU_R_709_2;
                    cfg.minimumFrameInterval = CMTimeMake(1, (int32_t)fps);
                    cfg.queueDepth = 4;
                    BOOL wantCursor = atomic_load_explicit(&self->_atomicShowCursor, memory_order_acquire);
                    cfg.showsCursor = wantCursor;

                    SCStream *stream = [[SCStream alloc] initWithFilter:filter configuration:cfg delegate:self];
                    NSError *addErr = nil;
                    if (![stream addStreamOutput:self type:SCStreamOutputTypeScreen sampleHandlerQueue:self.queue error:&addErr]) {
                        id_diag_log("sc_add_output_err", @"err=%@", addErr ? addErr.localizedDescription : @"nil");
                        dispatch_semaphore_signal(sem);
                        return;
                    }
                    [stream startCaptureWithCompletionHandler:^(NSError *startErr) {
                        @autoreleasepool {
                            BOOL stale = atomic_load_explicit(&timedOut, memory_order_acquire)
                                || atomic_load_explicit(&self->_stopped, memory_order_acquire)
                                || atomic_load_explicit(&self->_generation, memory_order_acquire) != startGen;
                            if (!startErr && !stale) {
                                self.scStream = stream;
                                atomic_store_explicit(&self->_loggedFirstPb, NO, memory_order_release);
                                ok = YES;
                            } else if (!startErr) {
                                // Controller stopped, timed out, or superseded mid-start: tear down orphan immediately.
                                [stream stopCaptureWithCompletionHandler:^(NSError *e) { (void)e; }];
                            }
                            id_diag_log(
                                "sc_start",
                                @"attempt=%d targetID=%u foundID=%u scFrame=(%.0f,%.0f %.0fx%.0f) cfg=%ux%u fps=%u showsCursor=%d ok=%d err=%@",
                                attempt,
                                targetID,
                                found.displayID,
                                scFrame.origin.x,
                                scFrame.origin.y,
                                scFrame.size.width,
                                scFrame.size.height,
                                w,
                                h,
                                fps,
                                wantCursor ? 1 : 0,
                                ok ? 1 : 0,
                                startErr ? startErr.localizedDescription : @"none"
                            );
                            dispatch_semaphore_signal(sem);
                        }
                    }];
                }
            }];

            long waitRes = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)));
            if (waitRes != 0) {
                atomic_store_explicit(&timedOut, YES, memory_order_release);
                id_diag_log("sc_start_timeout", @"attempt=%d targetID=%u", attempt, targetID);
            }
            if (ok) return YES;
            if (!displayMissing && attempt >= 1) break;
        }
        return NO;
    }
    return NO;
}

- (BOOL)ensureVirtualDisplayOnlineForceRecreate:(BOOL)forceRecreate {
    if (!self.useVirtualDisplay) return YES;
    uint32_t logW = self.requestedLogicalW >= 320 ? self.requestedLogicalW : 1024;
    uint32_t logH = self.requestedLogicalH >= 240 ? self.requestedLogicalH : 768;

    BOOL online = (self.virtualDisplay != nil
                   && self.displayID != kCGNullDirectDisplay
                   && CGDisplayIsOnline(self.displayID));
    if (online && !forceRecreate) {
        self.virtualDisplay.hiDPI = self.hiDPI;
        [self.virtualDisplay applyWidth:logW height:logH];
        return YES;
    }

    id_diag_log("vd_recreate", @"oldID=%u online=%d force=%d req=%ux%u hiDPI=%u",
                self.displayID, online ? 1 : 0, forceRecreate ? 1 : 0, logW, logH, self.hiDPI);
    os_unfair_lock_lock(&self->_boundsLock);
    self->_scDisplayFrame = CGRectZero;
    os_unfair_lock_unlock(&self->_boundsLock);
    @autoreleasepool {
        self.virtualDisplay = nil;
    }
    if (online) {
        // Give WindowServer a brief settle window to finalize old CGVirtualDisplay teardown
        // before creating the replacement with the same serialNum (avoids displayID churn).
        usleep(100000);
    }
    __weak typeof(self) weakSelf = self;
    IDVirtualDisplayWrapper *vd = [[IDVirtualDisplayWrapper alloc]
        initWithWidth:logW
               height:logH
                hiDPI:self.hiDPI
            serialNum:self.displaySerial
                 name:(self.displayName ?: @"idis")
   terminationHandler:^(id display, NSError * _Nullable error) {
        id_diag_log("vd_terminated", @"err=%@", error ? error.localizedDescription : @"none");
        IDCaptureController *strongSelf = weakSelf;
        if (!strongSelf
            || atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
            || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
            || atomic_load_explicit(&strongSelf->_paused, memory_order_acquire)) {
            return;
        }
        dispatch_async(strongSelf.queue, ^{
            if (atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
                || atomic_load_explicit(&strongSelf->_paused, memory_order_acquire)) {
                return;
            }
            if (!strongSelf.virtualDisplay || (display && strongSelf.virtualDisplay.displayObj != display)) {
                return;
            }
            [strongSelf scheduleCaptureRestartAfterMs:600 targetW:0 targetH:0 attempt:2];
        });
    }];
    if (!vd || vd.displayID == kCGNullDirectDisplay) {
        return NO;
    }
    self.virtualDisplay = vd;
    self.displayID = vd.displayID;
    atomic_store_explicit(&_atomicDisplayID, (uint32_t)vd.displayID, memory_order_release);
    uint32_t expectedW = (logW * self.hiDPI) & ~1u;
    uint32_t expectedH = (logH * self.hiDPI) & ~1u;
    BOOL modeSelected = vd.lastModeMatchedExact;
    for (int i = 0; i < 12; i++) {
        if (atomic_load_explicit(&_stopped, memory_order_acquire)) return NO;
        if (!modeSelected && (i == 0 || i == 2 || i == 5)) {
            modeSelected = [vd selectMatchingCGDisplayModeLogicalW:logW logicalH:logH];
        }
        usleep(40000);
        uint32_t mlw = 0, mlh = 0, mpw = 0, mph = 0;
        [self queryDisplayLogicalWidth:&mlw logicalHeight:&mlh pixelWidth:&mpw pixelHeight:&mph];
        CGRect curBounds = CGDisplayBounds(self.displayID);
        uint32_t bw = (uint32_t)llround(curBounds.size.width);
        uint32_t bh = (uint32_t)llround(curBounds.size.height);
        if ((mlw == logW && mlh == logH && mpw == expectedW && mph == expectedH)
            || (modeSelected && bw == logW && bh == logH)) {
            break;
        }
    }
    return YES;
}

- (void)scheduleCaptureRestartAfterMs:(int64_t)delayMs targetW:(uint32_t)targetW targetH:(uint32_t)targetH attempt:(int)attempt {
    uint64_t myGen = atomic_fetch_add_explicit(&_generation, 1, memory_order_acq_rel) + 1;
    __weak typeof(self) weakSelf = self;
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, delayMs * NSEC_PER_MSEC),
        self.lifecycleQueue,
        ^{
            @autoreleasepool {
                IDCaptureController *strongSelf = weakSelf;
                if (!strongSelf) return;
                if (atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                    || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
                    || atomic_load_explicit(&strongSelf->_paused, memory_order_acquire)) {
                    return;
                }
                if (atomic_load_explicit(&strongSelf->_generation, memory_order_acquire) != myGen) {
                    return;
                }
                if (id_is_screen_locked()) {
                    // Screen is locked: avoid thrashing SCShareableContent; unlock observer will trigger immediately on unlock.
                    id_diag_log("sc_restart_deferred_locked", @"attempt=%d", attempt);
                    [strongSelf scheduleCaptureRestartAfterMs:2500 targetW:targetW targetH:targetH attempt:attempt];
                    return;
                }
                [strongSelf stopScreenCaptureKitLocked];

                __block uint32_t w = targetW;
                __block uint32_t h = targetH;
                __block BOOL vdOk = YES;
                __block BOOL encOk = NO;
                dispatch_sync(strongSelf.queue, ^{
                    if (atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                        || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)) {
                        return;
                    }
                    if (strongSelf.useVirtualDisplay) {
                        vdOk = [strongSelf ensureVirtualDisplayOnlineForceRecreate:(attempt >= 2)];
                        if (!vdOk) return;
                    }
                    if (w < 320 || h < 240) {
                        uint32_t logW = strongSelf.requestedLogicalW >= 320 ? strongSelf.requestedLogicalW : 1024;
                        uint32_t logH = strongSelf.requestedLogicalH >= 240 ? strongSelf.requestedLogicalH : 768;
                        [strongSelf computeCapturePixelWidth:&w height:&h logicalWidth:logW logicalHeight:logH];
                    }
                    encOk = [strongSelf createEncoderWidth:w height:h];
                });

                BOOL ok = NO;
                if (vdOk && encOk
                    && !atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                    && !atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
                    && atomic_load_explicit(&strongSelf->_generation, memory_order_acquire) == myGen) {
                    ok = [strongSelf startScreenCaptureKitLockedWithWidth:w height:h];
                }
                if (!ok
                    && !atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                    && !atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
                    && atomic_load_explicit(&strongSelf->_generation, memory_order_acquire) == myGen) {
                    // Capped exponential backoff (0.5s -> 1s -> 2s -> 4s -> 5s) repeating until unlocked/recovered or stopped.
                    int nextAttempt = attempt < 10 ? (attempt + 1) : 10;
                    int64_t nextDelay = (int64_t)MIN(5000, 500 * (1 << MIN(attempt, 3)));
                    id_diag_log("sc_restart_retry", @"attempt=%d nextDelayMs=%lld vdOk=%d encOk=%d", attempt, (long long)nextDelay, vdOk ? 1 : 0, encOk ? 1 : 0);
                    [strongSelf scheduleCaptureRestartAfterMs:nextDelay targetW:targetW targetH:targetH attempt:nextAttempt];
                }
            }
        }
    );
}

- (void)scheduleCaptureRestartAfterMs:(int64_t)delayMs targetW:(uint32_t)targetW targetH:(uint32_t)targetH {
    [self scheduleCaptureRestartAfterMs:delayMs targetW:targetW targetH:targetH attempt:0];
}

static void capture_screen_unlocked_cb(
    CFNotificationCenterRef center,
    void *observer,
    CFNotificationName name,
    const void *object,
    CFDictionaryRef userInfo
) {
    (void)center; (void)name; (void)object; (void)userInfo;
    IDCaptureController *ctrl = (__bridge IDCaptureController *)observer;
    if (!ctrl || atomic_load_explicit(&ctrl->_stopped, memory_order_acquire)) return;
    id_diag_log("screen_unlocked", @"displayID=%u", atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire));
    atomic_store_explicit(&ctrl->_sleeping, NO, memory_order_release);
    if (!atomic_load_explicit(&ctrl->_paused, memory_order_acquire)) {
        [ctrl scheduleCaptureRestartAfterMs:350 targetW:0 targetH:0 attempt:0];
    }
}

static void id_unlock_keepalive_timer_cb(CFRunLoopTimerRef timer, void *info) {
    (void)timer;
    (void)info;
}

- (void)unlockObserverMain {
    @autoreleasepool {
        CFRunLoopRef rl = CFRunLoopGetCurrent();
        if (rl) {
            CFRetain(rl);
            @synchronized(self) {
                self.unlockRunLoop = rl;
            }
        }
        // Attach a lightweight keepalive timer to this thread's CFRunLoop so CFRunLoopRunInMode
        // genuinely blocks in mach_msg instead of returning kCFRunLoopRunFinished immediately
        // and spinning 100% of one CPU core!
        CFRunLoopTimerRef keepAlive = CFRunLoopTimerCreate(
            kCFAllocatorDefault,
            CFAbsoluteTimeGetCurrent() + 60.0,
            60.0,
            0,
            0,
            id_unlock_keepalive_timer_cb,
            NULL
        );
        if (rl && keepAlive) {
            CFRunLoopAddTimer(rl, keepAlive, kCFRunLoopDefaultMode);
        }
        CFNotificationCenterRef dist = CFNotificationCenterGetDistributedCenter();
        if (dist) {
            CFNotificationCenterAddObserver(
                dist,
                (__bridge const void *)self,
                capture_screen_unlocked_cb,
                CFSTR("com.apple.screenIsUnlocked"),
                NULL,
                CFNotificationSuspensionBehaviorDeliverImmediately
            );
        }
        while (!atomic_load_explicit(&_stopped, memory_order_acquire)) {
            CFRunLoopRunResult res = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.5, true);
            if (res == kCFRunLoopRunFinished && !atomic_load_explicit(&_stopped, memory_order_acquire)) {
                usleep(250000);
            }
        }
        if (dist) {
            CFNotificationCenterRemoveObserver(
                dist,
                (__bridge const void *)self,
                CFSTR("com.apple.screenIsUnlocked"),
                NULL
            );
        }
        if (keepAlive) {
            CFRunLoopTimerInvalidate(keepAlive);
            CFRelease(keepAlive);
        }
        @synchronized(self) {
            if (self.unlockRunLoop == rl) {
                self.unlockRunLoop = NULL;
            }
        }
        if (rl) {
            CFRelease(rl);
        }
    }
}

- (void)installLifecycleObservers {
    __weak typeof(self) weakSelf = self;

    // Register IOKit power notifications on lifecycleQueue (works in headless CLI without NSApplication RunLoop!).
    _powerPort = IORegisterForSystemPower((__bridge void *)self, &_powerNotifyPort, capture_power_callback, &_powerNotifier);
    if (_powerPort && _powerNotifyPort) {
        IONotificationPortSetDispatchQueue(_powerNotifyPort, self.lifecycleQueue);
    }

    // Run a lightweight CFRunLoop thread for `com.apple.screenIsUnlocked` distributed notifications
    // so headless CLI sessions immediately recover SCStream/VT after Lock Screen or Dark Wake!
    self.unlockObserverThread = [[NSThread alloc] initWithTarget:self selector:@selector(unlockObserverMain) object:nil];
    self.unlockObserverThread.name = @"idis-mac-unlock";
    [self.unlockObserverThread start];

    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.queue);
    if (timer) {
        dispatch_source_set_event_handler(timer, ^{
            @autoreleasepool {
                IDCaptureController *strongSelf = weakSelf;
                if (!strongSelf
                    || atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                    || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
                    || !strongSelf.vtSession) return;
                if (atomic_exchange_explicit(&strongSelf->_hasPendingEncode, NO, memory_order_acq_rel)) {
                    OSStatus compSt = VTCompressionSessionCompleteFrames(strongSelf.vtSession, kCMTimeInvalid);
                    if (compSt != noErr) {
                        [strongSelf handleVTEncodeFailure:compSt isRefine:NO];
                    }
                }
            }
        });
        dispatch_source_set_timer(timer, DISPATCH_TIME_FOREVER, DISPATCH_TIME_FOREVER, 0);
        dispatch_resume(timer);
        self.flushTimer = timer;
    }

    dispatch_source_t refine = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.queue);
    if (refine) {
        dispatch_source_set_event_handler(refine, ^{
            @autoreleasepool {
                IDCaptureController *strongSelf = weakSelf;
                if (!strongSelf
                    || atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                    || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
                    || !strongSelf.refineVtSession) return;
                if (!strongSelf.needsRefine || !strongSelf.lastPixelBuffer) return;

                CVPixelBufferRef pb = strongSelf.lastPixelBuffer;
                strongSelf.lastPixelBuffer = NULL;
                strongSelf.needsRefine = NO;

                static NSDictionary *kRefineKeyProps = nil;
                static dispatch_once_t refineOnce;
                dispatch_once(&refineOnce, ^{
                    kRefineKeyProps = @{
                        (__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES,
                    };
                });
                int32_t effFps = (int32_t)(strongSelf.fps > 0 ? strongSelf.fps : 30);
                int64_t step90k = 90000 / effFps;
                if (step90k < 1) step90k = 1;
                strongSelf.frameIndex++;
                strongSelf.lastPts90k += step90k;
                CMTime pts = CMTimeMake(strongSelf.lastPts90k, 90000);
                CMTime dur = CMTimeMake(step90k, 90000);
                OSStatus encSt = VTCompressionSessionEncodeFrame(
                    strongSelf.refineVtSession,
                    pb,
                    pts,
                    dur,
                    (__bridge CFDictionaryRef)kRefineKeyProps,
                    (void *)(uintptr_t)1,
                    NULL
                );
                OSStatus compSt = VTCompressionSessionCompleteFrames(strongSelf.refineVtSession, kCMTimeInvalid);
                id_diag_log(
                    "vt_refine_trigger",
                    @"pb=%zux%zu encSt=%d compSt=%d",
                    CVPixelBufferGetWidth(pb),
                    CVPixelBufferGetHeight(pb),
                    (int)encSt,
                    (int)compSt
                );
                if (encSt != noErr) {
                    [strongSelf handleVTEncodeFailure:encSt isRefine:YES];
                } else if (compSt != noErr) {
                    [strongSelf handleVTEncodeFailure:compSt isRefine:YES];
                }
                CVPixelBufferRelease(pb);
            }
        });
        dispatch_source_set_timer(refine, DISPATCH_TIME_FOREVER, DISPATCH_TIME_FOREVER, 0);
        dispatch_resume(refine);
        self.refineTimer = refine;
    }
}

- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error API_AVAILABLE(macos(12.3)) {
    id_diag_log("sc_error", @"didStopWithError=%@", error ? error.localizedDescription : @"<nil>");
    if (atomic_load_explicit(&_stopped, memory_order_acquire)
        || atomic_load_explicit(&_sleeping, memory_order_acquire)
        || atomic_load_explicit(&_paused, memory_order_acquire)) return;
    // Dispatch onto lifecycleQueue so self.scStream comparison is strictly synchronized with start/stop.
    __weak IDCaptureController *weakSelf = self;
    dispatch_async(self.lifecycleQueue, ^{
        IDCaptureController *strongSelf = weakSelf;
        if (!strongSelf) return;
        if (atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
            || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
            || atomic_load_explicit(&strongSelf->_paused, memory_order_acquire)) return;
        if (stream != strongSelf.scStream) return;
        [strongSelf scheduleCaptureRestartAfterMs:500 targetW:0 targetH:0];
    });
}

- (void)stream:(SCStream *)stream didOutputSampleBuffer:(CMSampleBufferRef)sampleBuffer ofType:(SCStreamOutputType)type API_AVAILABLE(macos(12.3)) {
    (void)stream;
    if (atomic_load_explicit(&_stopped, memory_order_acquire)
        || atomic_load_explicit(&_sleeping, memory_order_acquire)
        || type != SCStreamOutputTypeScreen) return;
    CVPixelBufferRef pb = CMSampleBufferGetImageBuffer(sampleBuffer);
    if (!pb) return;

    // Periodically check if the user changed the virtual display's resolution in macOS System Settings.
    self.modeCheckCounter++;
    if (self.virtualDisplay && (self.modeCheckCounter % 15 == 0)) {
        uint32_t modeLogW = 0, modeLogH = 0, modeW = 0, modeH = 0;
        [self queryDisplayLogicalWidth:&modeLogW logicalHeight:&modeLogH pixelWidth:&modeW pixelHeight:&modeH];
        if (modeW >= 320 && modeH >= 240 && (modeW != self.lastModePixW || modeH != self.lastModePixH)) {
            // If WindowServer silently dropped a 2x HiDPI virtual display back to 1x at the same logical
            // geometry after wake/clamshell, re-assert HiDPI instead of adopting degraded 1x!
            if (self.hiDPI >= 2
                && modeLogW == self.requestedLogicalW
                && modeLogH == self.requestedLogicalH
                && modeW == modeLogW
                && modeH == modeLogH) {
                id_diag_log("mode_hidpi_restore", @"modeLog=%ux%u modePix=%ux%u -> reassert 2x", modeLogW, modeLogH, modeW, modeH);
                [self.virtualDisplay selectMatchingCGDisplayModeLogicalW:self.requestedLogicalW logicalH:self.requestedLogicalH];
                [self scheduleCaptureRestartAfterMs:120 targetW:0 targetH:0];
                return;
            }
            uint32_t targetW = modeW;
            uint32_t targetH = modeH;
            clamp_encoded_dimensions(&targetW, &targetH, self.maxPixelEdge);
            if (modeLogW >= 320 && modeLogH >= 240) {
                self.requestedLogicalW = modeLogW;
                self.requestedLogicalH = modeLogH;
            }
            self.lastModePixW = modeW;
            self.lastModePixH = modeH;
            id_diag_log("mode_autosync", @"modePix=%ux%u -> target=%ux%u", modeW, modeH, targetW, targetH);
            // Do NOT mutate encWidth/encHeight yet; pass 0x0 so restart queries live post-mode-apply
            // display dimensions without double-restarting if another mode change lands in 60ms.
            [self scheduleCaptureRestartAfterMs:60 targetW:0 targetH:0];
            return;
        }
    }

    uint32_t pbW = (uint32_t)CVPixelBufferGetWidth(pb) & ~1u;
    uint32_t pbH = (uint32_t)CVPixelBufferGetHeight(pb) & ~1u;
    double scScaleFactor = 0.0;
    if (@available(macOS 12.3, *)) {
        CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, false);
        if (attachments && CFArrayGetCount(attachments) > 0) {
            NSDictionary *att = (__bridge NSDictionary *)CFArrayGetValueAtIndex(attachments, 0);
            NSNumber *sf = att[SCStreamFrameInfoScaleFactor];
            if (sf) scScaleFactor = sf.doubleValue;
        }
    }
    BOOL firstPb = !atomic_exchange_explicit(&_loggedFirstPb, YES, memory_order_acq_rel);
    if (firstPb || pbW != self.encWidth || pbH != self.encHeight) {
        CGRect bounds = CGDisplayBounds(self.displayID);
        os_unfair_lock_lock(&self->_boundsLock);
        CGRect scFrame = self->_scDisplayFrame;
        os_unfair_lock_unlock(&self->_boundsLock);
        uint32_t logW = 0, logH = 0, pixW = 0, pixH = 0;
        [self queryDisplayLogicalWidth:&logW logicalHeight:&logH pixelWidth:&pixW pixelHeight:&pixH];
        id_diag_log(
            "sc_frame_geometry",
            @"displayID=%u pb=%ux%u fmt=0x%08x enc=%ux%u modeLog=%ux%u modePix=%ux%u bounds=%.0fx%.0f scFrame=(%.0f,%.0f %.0fx%.0f) scaleFactor=%.2f hiDPI=%u",
            self.displayID,
            pbW,
            pbH,
            (unsigned int)CVPixelBufferGetPixelFormatType(pb),
            self.encWidth,
            self.encHeight,
            logW,
            logH,
            pixW,
            pixH,
            bounds.size.width,
            bounds.size.height,
            scFrame.origin.x,
            scFrame.origin.y,
            scFrame.size.width,
            scFrame.size.height,
            scScaleFactor,
            self.hiDPI
        );
        // Self-heal if macOS WindowServer defaulted the virtual display onto a non-integer or 1x mode
        // (e.g. 800x1066 instead of 768x1024@2x in portrait) after SCStream started.
        if (firstPb && self.virtualDisplay && self.hiDPI >= 2) {
            uint32_t reqW = self.requestedLogicalW;
            uint32_t reqH = self.requestedLogicalH;
            uint32_t bw = (uint32_t)llround(bounds.size.width);
            uint32_t bh = (uint32_t)llround(bounds.size.height);
            BOOL scaleTooLow = (scScaleFactor > 0.0 && scScaleFactor < 1.5);
            BOOL boundsMismatch = (bw >= 320 && bh >= 240 && reqW >= 320 && reqH >= 240 && (bw != reqW || bh != reqH));
            if (scaleTooLow || boundsMismatch) {
                uint64_t nowNs = id_monotonic_ns();
                uint64_t prevHeal = atomic_load_explicit(&_lastScaleHealNs, memory_order_relaxed);
                if (nowNs - prevHeal > 5000000000ULL
                    && atomic_compare_exchange_strong_explicit(&_lastScaleHealNs, &prevHeal, nowNs, memory_order_acq_rel, memory_order_relaxed)) {
                    id_diag_log("vd_scale_mismatch", @"displayID=%u req=%ux%u bounds=%ux%u scaleFactor=%.2f -> reasserting HiDPI", self.displayID, reqW, reqH, bw, bh, scScaleFactor);
                    __weak typeof(self) weakSelf = self;
                    dispatch_async(self.lifecycleQueue, ^{
                        IDCaptureController *strongSelf = weakSelf;
                        if (!strongSelf
                            || atomic_load_explicit(&strongSelf->_stopped, memory_order_acquire)
                            || atomic_load_explicit(&strongSelf->_sleeping, memory_order_acquire)
                            || atomic_load_explicit(&strongSelf->_paused, memory_order_acquire)) {
                            return;
                        }
                        if (strongSelf.virtualDisplay && [strongSelf.virtualDisplay selectMatchingCGDisplayModeLogicalW:reqW logicalH:reqH]) {
                            [strongSelf scheduleCaptureRestartAfterMs:120 targetW:0 targetH:0 attempt:0];
                        }
                    });
                }
            }
        }
    }
    if (pbW >= 320 && pbH >= 240 && (pbW != self.encWidth || pbH != self.encHeight || !self.vtSession)) {
        if (![self createEncoderWidth:pbW height:pbH]) {
            [self scheduleCaptureRestartAfterMs:1000 targetW:pbW targetH:pbH attempt:1];
            return;
        }
    }

    [self encodePixelBuffer:pb];
}

- (BOOL)reconfigureWidth:(uint32_t)w height:(uint32_t)h fps:(uint32_t)fps bitrateMbps:(uint32_t)bitrateMbps hiDPI:(uint32_t)hiDPI maxPixelEdge:(uint32_t)maxPixelEdge {
    w &= ~1u;
    h &= ~1u;
    if (w < 320 || h < 240) return NO;
    if (atomic_load_explicit(&_stopped, memory_order_acquire)) return NO;

    // Fast path: when logical resolution & HiDPI scale are unchanged and the virtual display is
    // already online, update FPS/bitrate/maxPixelEdge in-place without mutating or recreating
    // CGVirtualDisplay (eliminates unnecessary displayID churn and desktop flicker).
    __block BOOL sameGeometryAndOnline = NO;
    __block uint32_t curHiDPI = self.hiDPI;
    dispatch_sync(self.queue, ^{
        if (atomic_load_explicit(&self->_stopped, memory_order_acquire)) return;
        uint32_t normHiDPI = hiDPI >= 2 ? 2 : (hiDPI == 1 ? 1 : self.hiDPI);
        curHiDPI = normHiDPI;
        if (self.virtualDisplay != nil
            && self.displayID != kCGNullDirectDisplay
            && CGDisplayIsOnline(self.displayID)
            && w == self.requestedLogicalW
            && h == self.requestedLogicalH
            && normHiDPI == self.hiDPI) {
            sameGeometryAndOnline = YES;
        }
    });
    if (sameGeometryAndOnline
        && [self updateStreamFps:fps bitrateMbps:bitrateMbps maxPixelEdge:maxPixelEdge]) {
        id_diag_log("reconfigure_fast_path", @"displayID=%u req=%ux%u hiDPI=%u fps=%u br=%uM maxEdge=%u",
                    self.displayID, w, h, curHiDPI, fps, bitrateMbps, maxPixelEdge);
        return YES;
    }

    uint64_t myGen = atomic_fetch_add_explicit(&_generation, 1, memory_order_acq_rel) + 1;
    __block BOOL ok = NO;
    dispatch_sync(self.lifecycleQueue, ^{
        @autoreleasepool {
            if (atomic_load_explicit(&self->_stopped, memory_order_acquire)) return;

            // Stop the old SCStream before mutating CGVirtualDisplay mode/HiDPI, then rebuild
            // SCContentFilter + SCStream afterwards so macOS HiDPI scale changes never clip to 1/4.
            [self stopScreenCaptureKitLocked];

            __block uint32_t pixW = w, pixH = h;
            __block BOOL encOk = NO;
            dispatch_sync(self.queue, ^{
                if (atomic_load_explicit(&self->_stopped, memory_order_acquire)) return;
                BOOL orientationChanged = (self.requestedLogicalW >= 320 && self.requestedLogicalH >= 240)
                    && ((self.requestedLogicalW > self.requestedLogicalH) != (w > h));
                self.requestedLogicalW = w;
                self.requestedLogicalH = h;
                if (fps > 0) self.fps = fps;
                if (bitrateMbps > 0) self.bitrateMbps = bitrateMbps;
                if (hiDPI >= 1) self.hiDPI = hiDPI >= 2 ? 2 : 1;
                if (maxPixelEdge >= 320) self.maxPixelEdge = maxPixelEdge;

                if (self.virtualDisplay) {
                    self.virtualDisplay.hiDPI = self.hiDPI;
                    if (orientationChanged) {
                        // Recreate immediately on portrait<->landscape flips so CGVirtualDisplayDescriptor's
                        // physical `sizeInMillimeters` matches the new orientation cleanly (avoids WindowServer
                        // defaulting portrait displays to non-integer 800x1066 scaled modes).
                        id_diag_log("vd_reconfigure_orientation_recreate", @"req=%ux%u hiDPI=%u", w, h, self.hiDPI);
                        [self ensureVirtualDisplayOnlineForceRecreate:YES];
                    } else {
                        [self.virtualDisplay applyWidth:w height:h];
                        // Wait up to 640ms for WindowServer to commit the EXACT new pixel & logical dimensions.
                        // Re-select CGDisplayMode during polling (falling back to child helper when in-process
                        // CGDisplayCopyAllDisplayModes returns NULL), and verify both mode & bounds.
                        uint32_t expectedW = (w * self.hiDPI) & ~1u;
                        uint32_t expectedH = (h * self.hiDPI) & ~1u;
                        BOOL matchedMode = NO;
                        BOOL modeSelected = self.virtualDisplay.lastModeMatchedExact;
                        for (int attempt = 0; attempt < 16; attempt++) {
                            if (atomic_load_explicit(&self->_stopped, memory_order_acquire)
                                || atomic_load_explicit(&self->_generation, memory_order_acquire) != myGen) {
                                return;
                            }
                            if (!modeSelected && (attempt == 0 || attempt == 2 || attempt == 5)) {
                                modeSelected = [self.virtualDisplay selectMatchingCGDisplayModeLogicalW:w logicalH:h];
                            }
                            usleep(40000);
                            uint32_t mlw = 0, mlh = 0, mpw = 0, mph = 0;
                            [self queryDisplayLogicalWidth:&mlw logicalHeight:&mlh pixelWidth:&mpw pixelHeight:&mph];
                            CGRect curBounds = CGDisplayBounds(self.displayID);
                            uint32_t bw = (uint32_t)llround(curBounds.size.width);
                            uint32_t bh = (uint32_t)llround(curBounds.size.height);
                            if ((mlw == w && mlh == h && mpw == expectedW && mph == expectedH)
                                || (modeSelected && bw == w && bh == h)) {
                                matchedMode = YES;
                                break;
                            }
                        }
                        if (!matchedMode && !atomic_load_explicit(&self->_stopped, memory_order_acquire)) {
                            id_diag_log("vd_reconfigure_fallback_recreate", @"req=%ux%u hiDPI=%u expectedPix=%ux%u", w, h, self.hiDPI, expectedW, expectedH);
                            [self ensureVirtualDisplayOnlineForceRecreate:YES];
                        }
                    }
                }

                [self computeCapturePixelWidth:&pixW height:&pixH logicalWidth:w logicalHeight:h];
                id_diag_log(
                    "reconfigure_computed",
                    @"req=%ux%u fps=%u br=%uM hiDPI=%u modePix=%ux%u targetPix=%ux%u maxEdge=%u",
                    w,
                    h,
                    self.fps,
                    self.bitrateMbps,
                    self.hiDPI,
                    self.lastModePixW,
                    self.lastModePixH,
                    pixW,
                    pixH,
                    self.maxPixelEdge
                );
                encOk = [self createEncoderWidth:pixW height:pixH];
                if (encOk && atomic_load_explicit(&self->_paused, memory_order_acquire)) {
                    uint64_t packed = ((uint64_t)pixW << 32) | (uint64_t)pixH;
                    atomic_store_explicit(&self->_atomicSize, packed, memory_order_release);
                }
            });

            if (atomic_load_explicit(&self->_paused, memory_order_acquire)) {
                // Keep SCStream stopped while paused; new encoder & virtual display mode will take
                // effect cleanly when `id_macos_capture_set_paused(0)` resumes capture.
                ok = encOk;
            } else {
                if (encOk
                    && !atomic_load_explicit(&self->_stopped, memory_order_acquire)
                    && !atomic_load_explicit(&self->_sleeping, memory_order_acquire)
                    && atomic_load_explicit(&self->_generation, memory_order_acquire) == myGen) {
                    ok = [self startScreenCaptureKitLockedWithWidth:pixW height:pixH];
                }
                if (!ok
                    && !atomic_load_explicit(&self->_stopped, memory_order_acquire)
                    && !atomic_load_explicit(&self->_sleeping, memory_order_acquire)
                    && atomic_load_explicit(&self->_generation, memory_order_acquire) == myGen) {
                    [self scheduleCaptureRestartAfterMs:800 targetW:pixW targetH:pixH attempt:1];
                }
            }
            id_diag_log("reconfigure_done", @"req=%ux%u hiDPI=%u targetPix=%ux%u ok=%d", w, h, self.hiDPI, pixW, pixH, ok ? 1 : 0);
        }
    });
    return ok;
}

- (void)applyMotionEncoderBitratePropsLocked {
    if (!self.vtSession) return;
    // Keep `ExpectedFrameRate` pinned to the session's creation value so `Main_AutoLevel`
    // never alters H.264 SPS `level_idc` / VUI timing mid-stream during ABR or unfocused FPS
    // transitions (which would otherwise force legacy iDisplay to reset its decoder and flash).
    int32_t fpsVal = (int32_t)(self.fps > 0 ? self.fps : 30);
    if (!self.allIntra) {
        int32_t keyInterval = fpsVal * 2;
        if (keyInterval < 10) keyInterval = 10;
        CFNumberRef kfNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &keyInterval);
        if (kfNum) {
            VTSessionSetProperty(self.vtSession, kVTCompressionPropertyKey_MaxKeyFrameInterval, kfNum);
            CFRelease(kfNum);
        }
    }
    int32_t bitrate = (int32_t)((self.bitrateMbps > 0 ? self.bitrateMbps : 16) * 1000000);
    CFNumberRef brNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &bitrate);
    if (brNum) {
        VTSessionSetProperty(self.vtSession, kVTCompressionPropertyKey_AverageBitRate, brNum);
        CFRelease(brNum);
    }
    int64_t peakBytesPerSec = ((int64_t)bitrate / 8) * 3;
    NSArray *dataRateLimits = @[@(peakBytesPerSec), @(1.0)];
    VTSessionSetProperty(self.vtSession, kVTCompressionPropertyKey_DataRateLimits, (__bridge CFArrayRef)dataRateLimits);

    int32_t motionMaxQp = (self.bitrateMbps >= 28) ? 23
                        : (self.bitrateMbps >= 20) ? 25
                        : (self.bitrateMbps >= 12) ? 28
                        : (self.bitrateMbps >= 6)  ? 32
                        : (self.bitrateMbps >= 4)  ? 36
                        : 40;
    CFNumberRef qpNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &motionMaxQp);
    if (qpNum) {
        VTSessionSetProperty(self.vtSession, CFSTR("MaxAllowedFrameQP"), qpNum);
        CFRelease(qpNum);
    }
}

// Lightweight ABR fast-path: dynamically updates bitrate/QP in-place (zero flicker) or scales
// SCStream capture pixel dimensions & FPS via `updateConfiguration:` WITHOUT touching CGVirtualDisplay!
- (BOOL)updateStreamFps:(uint32_t)fps bitrateMbps:(uint32_t)bitrateMbps maxPixelEdge:(uint32_t)maxPixelEdge {
    if (atomic_load_explicit(&_stopped, memory_order_acquire)
        || atomic_load_explicit(&_sleeping, memory_order_acquire)) {
        return NO;
    }
    __block uint32_t newPixW = 0, newPixH = 0;
    __block BOOL needStreamUpdate = NO;
    __block uint32_t effFps = 30;
    __block uint32_t savedPrevFps = 30;
    __block uint32_t savedPrevBitrate = 16;
    __block uint32_t savedPrevMaxEdge = 0;
    dispatch_sync(self.queue, ^{
        if (atomic_load_explicit(&self->_stopped, memory_order_acquire)) return;
        uint32_t prevFps = self.fps;
        uint32_t prevEncW = self.encWidth;
        uint32_t prevEncH = self.encHeight;
        savedPrevFps = self.fps;
        savedPrevBitrate = self.bitrateMbps;
        savedPrevMaxEdge = self.maxPixelEdge;
        if (fps > 0) self.fps = fps;
        if (bitrateMbps > 0) self.bitrateMbps = bitrateMbps;
        if (maxPixelEdge >= 320) self.maxPixelEdge = maxPixelEdge;
        effFps = self.fps > 0 ? self.fps : 30;

        uint32_t logW = self.requestedLogicalW >= 320 ? self.requestedLogicalW : 1024;
        uint32_t logH = self.requestedLogicalH >= 240 ? self.requestedLogicalH : 768;
        [self computeCapturePixelWidth:&newPixW height:&newPixH logicalWidth:logW logicalHeight:logH];
        needStreamUpdate = (newPixW != prevEncW || newPixH != prevEncH || effFps != prevFps);
        // Apply bitrate/QP immediately on existing encoder so even before SCStream switches, bitrate drops cleanly.
        [self applyMotionEncoderBitratePropsLocked];
    });

    id_diag_log(
        "abr_stream_update",
        @"fps=%u br=%uM maxEdge=%u targetPix=%ux%u scUpdate=%d",
        effFps,
        self.bitrateMbps,
        self.maxPixelEdge,
        newPixW,
        newPixH,
        needStreamUpdate ? 1 : 0
    );

    if (!needStreamUpdate) {
        return YES;
    }
    if (newPixW < 320 || newPixH < 240) {
        dispatch_sync(self.queue, ^{
            if (atomic_load_explicit(&self->_stopped, memory_order_acquire)) return;
            self.fps = savedPrevFps;
            self.bitrateMbps = savedPrevBitrate;
            self.maxPixelEdge = savedPrevMaxEdge;
            [self applyMotionEncoderBitratePropsLocked];
        });
        return NO;
    }

    __block BOOL ok = YES;
    if (@available(macOS 12.3, *)) {
        dispatch_sync(self.lifecycleQueue, ^{
            @autoreleasepool {
                if (atomic_load_explicit(&self->_stopped, memory_order_acquire)
                    || atomic_load_explicit(&self->_sleeping, memory_order_acquire)) {
                    ok = NO;
                    return;
                }
                if (atomic_load_explicit(&self->_paused, memory_order_acquire)) {
                    // Stream is intentionally paused; new fps/bitrate/maxPixelEdge were saved on
                    // `self.queue` and will be applied cleanly when `set_paused(0)` resumes capture.
                    uint64_t packed = ((uint64_t)newPixW << 32) | (uint64_t)newPixH;
                    atomic_store_explicit(&self->_atomicSize, packed, memory_order_release);
                    ok = YES;
                    return;
                }
                if (!self.scStream) {
                    ok = NO;
                    return;
                }
                SCStreamConfiguration *cfg = [SCStreamConfiguration new];
                cfg.width = newPixW;
                cfg.height = newPixH;
                cfg.scalesToFit = YES;
                if ([cfg respondsToSelector:NSSelectorFromString(@"setCaptureResolution:")]) {
                    [cfg setValue:@(1) forKey:@"captureResolution"];
                }
                cfg.pixelFormat = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;
                cfg.colorSpaceName = kCGColorSpaceSRGB;
                cfg.colorMatrix = kCVImageBufferYCbCrMatrix_ITU_R_709_2;
                cfg.minimumFrameInterval = CMTimeMake(1, (int32_t)effFps);
                cfg.queueDepth = 4;
                cfg.showsCursor = atomic_load_explicit(&self->_atomicShowCursor, memory_order_acquire);

                dispatch_semaphore_t sem = dispatch_semaphore_create(0);
                __block NSError *updErr = nil;
                [self.scStream updateConfiguration:cfg completionHandler:^(NSError * _Nullable error) {
                    updErr = error;
                    dispatch_semaphore_signal(sem);
                }];
                long waitRes = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)));
                if (waitRes != 0 || updErr != nil) {
                    id_diag_log("abr_sc_update_err", @"timeout=%d err=%@", waitRes != 0 ? 1 : 0, updErr ? updErr.localizedDescription : @"none");
                    ok = NO;
                    [self scheduleCaptureRestartAfterMs:200 targetW:newPixW targetH:newPixH attempt:0];
                }
            }
        });
    }
    if (!ok) {
        // Roll back cached stream parameters so caller retries do not short-circuit `needStreamUpdate == NO`.
        dispatch_sync(self.queue, ^{
            if (atomic_load_explicit(&self->_stopped, memory_order_acquire)) return;
            self.fps = savedPrevFps;
            self.bitrateMbps = savedPrevBitrate;
            self.maxPixelEdge = savedPrevMaxEdge;
            [self applyMotionEncoderBitratePropsLocked];
        });
    }
    return ok;
}

- (BOOL)updateShowCursor:(BOOL)show {
    if (atomic_load_explicit(&_stopped, memory_order_acquire)) return NO;
    __block BOOL ok = YES;
    dispatch_sync(self.lifecycleQueue, ^{
        @autoreleasepool {
            if (atomic_load_explicit(&self->_stopped, memory_order_acquire)) {
                ok = NO;
                return;
            }
            BOOL prevShow = atomic_exchange_explicit(&self->_atomicShowCursor, show, memory_order_acq_rel);
            BOOL changed = (prevShow != show);
            __block uint32_t curPixW = 0, curPixH = 0;
            dispatch_sync(self.queue, ^{
                self.showCursor = show;
                uint32_t logW = self.requestedLogicalW >= 320 ? self.requestedLogicalW : 1024;
                uint32_t logH = self.requestedLogicalH >= 240 ? self.requestedLogicalH : 768;
                [self computeCapturePixelWidth:&curPixW height:&curPixH logicalWidth:logW logicalHeight:logH];
            });
            if (!changed || curPixW < 320 || curPixH < 240) {
                id_diag_log("cursor_show_update", @"show=%d changed=%d restarted=0 ok=1", show ? 1 : 0, changed ? 1 : 0);
                return;
            }
            if (@available(macOS 12.3, *)) {
                if (atomic_load_explicit(&self->_sleeping, memory_order_acquire)
                    || atomic_load_explicit(&self->_paused, memory_order_acquire)
                    || !self.scStream) {
                    id_diag_log("cursor_show_update", @"show=%d changed=1 restarted=0 deferred=1 ok=1", show ? 1 : 0);
                    return;
                }
                // ScreenCaptureKit's `updateConfiguration:` silently ignores `showsCursor` toggles
                // after `startCapture` on macOS 13-15+ (leaving `showsCursor=NO` when toggling
                // `client_cursor: true -> false`, or double cursors on `false -> true`).
                // Recreate only `SCStream` (keeping `CGVirtualDisplay` and `vtSession` intact, so
                // there is zero monitor churn or resolution flicker) to reliably apply `showsCursor`.
                [self stopScreenCaptureKitLocked];
                atomic_store_explicit(&self->_forceNextKeyframe, YES, memory_order_release);
                ok = [self startScreenCaptureKitLockedWithWidth:curPixW height:curPixH];
                id_diag_log("cursor_show_update", @"show=%d changed=1 restarted=1 pix=%ux%u ok=%d", show ? 1 : 0, curPixW, curPixH, ok ? 1 : 0);
                if (!ok
                    && !atomic_load_explicit(&self->_stopped, memory_order_acquire)
                    && !atomic_load_explicit(&self->_sleeping, memory_order_acquire)
                    && !atomic_load_explicit(&self->_paused, memory_order_acquire)) {
                    [self scheduleCaptureRestartAfterMs:200 targetW:curPixW targetH:curPixH attempt:0];
                }
            }
        }
    });
    return ok;
}

- (BOOL)resizeWidth:(uint32_t)w height:(uint32_t)h {
    return [self reconfigureWidth:w height:h fps:self.fps bitrateMbps:self.bitrateMbps hiDPI:self.hiDPI maxPixelEdge:self.maxPixelEdge];
}

- (void)stop {
    atomic_store_explicit(&_stopped, YES, memory_order_release);
    atomic_fetch_add_explicit(&_generation, 1, memory_order_acq_rel);

    if (_powerNotifier) {
        IODeregisterForSystemPower(&_powerNotifier);
        _powerNotifier = 0;
    }
    if (_powerNotifyPort) {
        IONotificationPortDestroy(_powerNotifyPort);
        _powerNotifyPort = NULL;
    }

    if (self.flushTimer) {
        dispatch_source_cancel(self.flushTimer);
        self.flushTimer = nil;
    }
    if (self.refineTimer) {
        dispatch_source_cancel(self.refineTimer);
        self.refineTimer = nil;
    }

    // Serialize teardown on lifecycleQueue BEFORE closing _powerPort so any in-flight power
    // callback completes cleanly and calls IOAllowPowerChange on a valid port.
    if (self.lifecycleQueue) {
        dispatch_sync(self.lifecycleQueue, ^{
            [self stopScreenCaptureKitLocked];
        });
    } else {
        [self stopScreenCaptureKitLocked];
    }

    if (_powerPort) {
        IOServiceClose(_powerPort);
        _powerPort = 0;
    }

    // Drain self.queue and invalidate both VideoToolbox sessions BEFORE clearing callbackCtx
    // so Rust can safely free `tx_box` with zero UAF risk.
    if (self.queue) {
        dispatch_sync(self.queue, ^{
            [self destroyEncoders];
        });
    } else {
        [self destroyEncoders];
    }

    self.callback = NULL;
    self.callbackCtx = NULL;

    if (self.sleepAssertionID != 0) {
        IOPMAssertionRelease(self.sleepAssertionID);
        self.sleepAssertionID = 0;
    }
    self.virtualDisplay = nil;
    @synchronized(self) {
        if (self.unlockRunLoop) {
            CFRunLoopStop(self.unlockRunLoop);
        }
    }
    self.unlockObserverThread = nil;
}
@end

static void capture_power_callback(void *refCon, io_service_t service, natural_t messageType, void *messageArgument) {
    (void)service;
    IDCaptureController *ctrl = (__bridge IDCaptureController *)refCon;
    if (!ctrl) return;
    switch (messageType) {
        case kIOMessageCanSystemSleep:
            if (ctrl->_powerPort) {
                IOAllowPowerChange(ctrl->_powerPort, (long)messageArgument);
            }
            break;
        case kIOMessageSystemWillSleep:
            // Already dispatched on `ctrl.lifecycleQueue` via `IONotificationPortSetDispatchQueue` (Invariant CON-1).
            atomic_store_explicit(&ctrl->_sleeping, YES, memory_order_release);
            id_diag_log("power_sleep", @"displayID=%u", atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire));
            if (!atomic_load_explicit(&ctrl->_stopped, memory_order_acquire)) {
                [ctrl stopScreenCaptureKitLocked];
                if (ctrl.queue) {
                    dispatch_sync(ctrl.queue, ^{
                        [ctrl destroyEncoders];
                    });
                }
            }
            if (ctrl->_powerPort) {
                IOAllowPowerChange(ctrl->_powerPort, (long)messageArgument);
            }
            break;
        case kIOMessageSystemHasPoweredOn:
            atomic_store_explicit(&ctrl->_sleeping, NO, memory_order_release);
            id_diag_log("power_wake", @"displayID=%u", atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire));
            if (!atomic_load_explicit(&ctrl->_stopped, memory_order_acquire)
                && !atomic_load_explicit(&ctrl->_paused, memory_order_acquire)) {
                [ctrl scheduleCaptureRestartAfterMs:600 targetW:0 targetH:0 attempt:0];
            }
            break;
        default:
            break;
    }
}

void *id_macos_capture_start(
    int32_t use_virtual_display,
    uint32_t display_id,
    uint32_t width,
    uint32_t height,
    uint32_t hidpi,
    uint32_t max_pixel_edge,
    uint32_t fps,
    uint32_t bitrate_mbps,
    int32_t show_cursor,
    int32_t all_intra,
    uint32_t display_serial,
    const char *display_name,
    IDFrameCallback cb,
    void *ctx
) {
    @autoreleasepool {
        width = (width & ~1u);
        height = (height & ~1u);
        if (width < 320) width = 1024;
        if (height < 240) height = 768;

        IDCaptureController *ctrl = [IDCaptureController new];
        ctrl->_boundsLock = OS_UNFAIR_LOCK_INIT;
        ctrl->_scDisplayFrame = CGRectZero;
        atomic_store_explicit(&ctrl->_stopped, NO, memory_order_release);
        atomic_store_explicit(&ctrl->_sleeping, NO, memory_order_release);
        atomic_store_explicit(&ctrl->_paused, NO, memory_order_release);
        atomic_store_explicit(&ctrl->_lowPower, NO, memory_order_release);
        atomic_store_explicit(&ctrl->_forceNextKeyframe, YES, memory_order_release);
        atomic_store_explicit(&ctrl->_hasPendingEncode, NO, memory_order_release);
        atomic_store_explicit(&ctrl->_loggedFirstPb, NO, memory_order_release);
        atomic_store_explicit(&ctrl->_generation, 1, memory_order_release);
        atomic_store_explicit(&ctrl->_vtErrorStreak, 0, memory_order_release);
        atomic_store_explicit(&ctrl->_lastVtRebuildNs, 0, memory_order_release);
        // Must start at 0 so `createEncoderWidth:height:` seeds the true encoded pixel dimensions (e.g. 2x HiDPI).
        atomic_store_explicit(&ctrl->_atomicSize, 0, memory_order_release);
        ctrl.useVirtualDisplay = (use_virtual_display != 0);
        ctrl.requestedLogicalW = width;
        ctrl.requestedLogicalH = height;
        ctrl.displaySerial = display_serial;
        ctrl.displayName = display_name ? [NSString stringWithUTF8String:display_name] : @"idis";
        ctrl.hiDPI = hidpi >= 2 ? 2 : 1;
        ctrl.maxPixelEdge = max_pixel_edge >= 320 ? max_pixel_edge : 2048;
        ctrl.fps = fps > 0 ? fps : 30;
        ctrl.bitrateMbps = bitrate_mbps > 0 ? bitrate_mbps : 16;
        ctrl.showCursor = show_cursor != 0;
        atomic_store_explicit(&ctrl->_atomicShowCursor, show_cursor != 0, memory_order_release);
        ctrl.allIntra = all_intra != 0;
        ctrl.callback = cb;
        ctrl.callbackCtx = ctx;

        dispatch_queue_attr_t qAttr = dispatch_queue_attr_make_with_autorelease_frequency(
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INTERACTIVE, 0),
            DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM
        );
        ctrl.queue = dispatch_queue_create("idis.mac.capture", qAttr);

        dispatch_queue_attr_t lcAttr = dispatch_queue_attr_make_with_autorelease_frequency(
            dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL, QOS_CLASS_USER_INITIATED, 0),
            DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM
        );
        ctrl.lifecycleQueue = dispatch_queue_create("idis.mac.lifecycle", lcAttr);

        if (use_virtual_display) {
            NSString *name = ctrl.displayName;
            __weak IDCaptureController *weakCtrl = ctrl;
            IDVirtualDisplayWrapper *vd = [[IDVirtualDisplayWrapper alloc]
                initWithWidth:width
                       height:height
                        hiDPI:ctrl.hiDPI
                    serialNum:display_serial
                         name:name
           terminationHandler:^(id display, NSError * _Nullable error) {
                id_diag_log("vd_terminated", @"err=%@", error ? error.localizedDescription : @"none");
                IDCaptureController *strongCtrl = weakCtrl;
                if (!strongCtrl
                    || atomic_load_explicit(&strongCtrl->_stopped, memory_order_acquire)
                    || atomic_load_explicit(&strongCtrl->_sleeping, memory_order_acquire)
                    || atomic_load_explicit(&strongCtrl->_paused, memory_order_acquire)) {
                    return;
                }
                dispatch_async(strongCtrl.queue, ^{
                    if (atomic_load_explicit(&strongCtrl->_stopped, memory_order_acquire)
                        || atomic_load_explicit(&strongCtrl->_sleeping, memory_order_acquire)
                        || atomic_load_explicit(&strongCtrl->_paused, memory_order_acquire)) {
                        return;
                    }
                    if (!strongCtrl.virtualDisplay || (display && strongCtrl.virtualDisplay.displayObj != display)) {
                        return;
                    }
                    [strongCtrl scheduleCaptureRestartAfterMs:600 targetW:0 targetH:0 attempt:2];
                });
            }];
            if (vd && vd.displayID != kCGNullDirectDisplay) {
                ctrl.virtualDisplay = vd;
                ctrl.displayID = vd.displayID;
                atomic_store_explicit(&ctrl->_atomicDisplayID, (uint32_t)vd.displayID, memory_order_release);
                // Wait up to 480ms for WindowServer to register the new virtual display mode cleanly.
                uint32_t expectedW = (width * ctrl.hiDPI) & ~1u;
                uint32_t expectedH = (height * ctrl.hiDPI) & ~1u;
                BOOL modeSelected = vd.lastModeMatchedExact;
                for (int attempt = 0; attempt < 12; attempt++) {
                    if (!modeSelected && (attempt == 0 || attempt == 2 || attempt == 5)) {
                        modeSelected = [vd selectMatchingCGDisplayModeLogicalW:width logicalH:height];
                    }
                    usleep(40000);
                    uint32_t mlw = 0, mlh = 0, mpw = 0, mph = 0;
                    [ctrl queryDisplayLogicalWidth:&mlw logicalHeight:&mlh pixelWidth:&mpw pixelHeight:&mph];
                    CGRect curBounds = CGDisplayBounds(ctrl.displayID);
                    uint32_t bw = (uint32_t)llround(curBounds.size.width);
                    uint32_t bh = (uint32_t)llround(curBounds.size.height);
                    if ((mlw == width && mlh == height && mpw == expectedW && mph == expectedH)
                        || (modeSelected && bw == width && bh == height)) {
                        break;
                    }
                }
            } else {
                // Never silently fall back to CGMainDisplayID() when a virtual display was requested:
                // that would leak the primary Mac desktop to Web/iPad viewers instead of failing cleanly.
                id_diag_log("vd_create_failed", @"name=%@ req=%ux%u hidpi=%u", name, width, height, ctrl.hiDPI);
                [ctrl stop];
                return NULL;
            }
        } else {
            ctrl.displayID = display_id != 0 ? display_id : CGMainDisplayID();
            atomic_store_explicit(&ctrl->_atomicDisplayID, (uint32_t)ctrl.displayID, memory_order_release);
        }

        uint32_t pixW = width, pixH = height;
        [ctrl computeCapturePixelWidth:&pixW height:&pixH logicalWidth:width logicalHeight:height];

        if (![ctrl createEncoderWidth:pixW height:pixH]) {
            [ctrl stop];
            return NULL;
        }

        [ctrl installLifecycleObservers];

        __block BOOL started = NO;
        dispatch_sync(ctrl.lifecycleQueue, ^{
            started = [ctrl startScreenCaptureKitLockedWithWidth:pixW height:pixH];
        });
        if (!started) {
            [ctrl stop];
            return NULL;
        }

        IOPMAssertionID assertionID = 0;
        if (IOPMAssertionCreateWithName(
                kIOPMAssertionTypePreventUserIdleDisplaySleep,
                kIOPMAssertionLevelOn,
                CFSTR("idis active extended display session"),
                &assertionID) == kIOReturnSuccess) {
            ctrl.sleepAssertionID = assertionID;
        }
        return (__bridge_retained void *)ctrl;
    }
}

int32_t id_macos_capture_resize(void *handle, uint32_t width, uint32_t height) {
    @autoreleasepool {
        if (!handle) return -1;
        IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
        return [ctrl resizeWidth:width height:height] ? 0 : -1;
    }
}

int32_t id_macos_capture_reconfigure(
    void *handle,
    uint32_t width,
    uint32_t height,
    uint32_t fps,
    uint32_t bitrate_mbps,
    uint32_t hidpi,
    uint32_t max_pixel_edge
) {
    @autoreleasepool {
        if (!handle) return -1;
        IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
        return [ctrl reconfigureWidth:width height:height fps:fps bitrateMbps:bitrate_mbps hiDPI:hidpi maxPixelEdge:max_pixel_edge] ? 0 : -1;
    }
}

int32_t id_macos_capture_update_stream_quality(
    void *handle,
    uint32_t fps,
    uint32_t bitrate_mbps,
    uint32_t max_pixel_edge
) {
    @autoreleasepool {
        if (!handle) return -1;
        IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
        return [ctrl updateStreamFps:fps bitrateMbps:bitrate_mbps maxPixelEdge:max_pixel_edge] ? 0 : -1;
    }
}

int32_t id_macos_capture_set_show_cursor(void *handle, int32_t show_cursor) {
    @autoreleasepool {
        if (!handle) return -1;
        IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
        return [ctrl updateShowCursor:(show_cursor != 0)] ? 0 : -1;
    }
}

uint32_t id_macos_capture_display_id(void *handle) {
    if (!handle) return CGMainDisplayID();
    IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
    return atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire);
}

void id_macos_capture_size(void *handle, uint32_t *out_w, uint32_t *out_h) {
    if (!handle) {
        if (out_w) *out_w = 0;
        if (out_h) *out_h = 0;
        return;
    }
    IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
    uint64_t packed = atomic_load_explicit(&ctrl->_atomicSize, memory_order_acquire);
    if (out_w) *out_w = (uint32_t)(packed >> 32);
    if (out_h) *out_h = (uint32_t)(packed & 0xFFFFFFFFu);
}

void id_macos_capture_request_keyframe(void *handle) {
    if (!handle) return;
    IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
    atomic_store_explicit(&ctrl->_forceNextKeyframe, YES, memory_order_release);
    if (!ctrl.queue) return;
    __weak typeof(ctrl) weakCtrl = ctrl;
    dispatch_async(ctrl.queue, ^{
        @autoreleasepool {
            IDCaptureController *strongCtrl = weakCtrl;
            if (!strongCtrl
                || atomic_load_explicit(&strongCtrl->_stopped, memory_order_acquire)
                || atomic_load_explicit(&strongCtrl->_sleeping, memory_order_acquire)
                || atomic_load_explicit(&strongCtrl->_paused, memory_order_acquire)
                || !strongCtrl.vtSession
                || !strongCtrl.lastPixelBuffer) {
                return;
            }
            // ScreenCaptureKit is damage-driven: if the desktop is static (>80ms since last frame),
            // re-encode the retained pixel buffer with ForceKeyFrame immediately. If a frame was
            // encoded <80ms ago (user just stopped moving), schedule a 90ms fallback check so static
            // desktops never starve waiting IPPP clients!
            uint64_t now = id_monotonic_ns();
            uint64_t last = atomic_load_explicit(&strongCtrl->_lastEncodeNs, memory_order_acquire);
            if (now >= last + (uint64_t)(80ULL * NSEC_PER_MSEC)) {
                [strongCtrl encodePixelBuffer:strongCtrl.lastPixelBuffer];
            } else {
                dispatch_after(
                    dispatch_time(DISPATCH_TIME_NOW, (int64_t)(90ULL * NSEC_PER_MSEC)),
                    strongCtrl.queue,
                    ^{
                        @autoreleasepool {
                            IDCaptureController *laterCtrl = weakCtrl;
                            if (!laterCtrl
                                || !atomic_load_explicit(&laterCtrl->_forceNextKeyframe, memory_order_acquire)
                                || atomic_load_explicit(&laterCtrl->_stopped, memory_order_acquire)
                                || atomic_load_explicit(&laterCtrl->_sleeping, memory_order_acquire)
                                || atomic_load_explicit(&laterCtrl->_paused, memory_order_acquire)
                                || !laterCtrl.vtSession
                                || !laterCtrl.lastPixelBuffer) {
                                return;
                            }
                            [laterCtrl encodePixelBuffer:laterCtrl.lastPixelBuffer];
                        }
                    }
                );
            }
        }
    });
}

int32_t id_macos_capture_set_paused(void *handle, int32_t paused) {
    @autoreleasepool {
        if (!handle) return -1;
        IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
        BOOL wantPaused = (paused != 0);
        BOOL prev = atomic_exchange_explicit(&ctrl->_paused, wantPaused, memory_order_acq_rel);
        if (prev == wantPaused) return 0;
        if (!ctrl.lifecycleQueue) return 0;
        dispatch_sync(ctrl.lifecycleQueue, ^{
            if (atomic_load_explicit(&ctrl->_stopped, memory_order_acquire)) return;
            if (wantPaused) {
                // Keep CGVirtualDisplay alive (preserves window layout), but stop SCStream,
                // release retained pixel buffer, and release display-sleep assertion so Mac can sleep.
                atomic_fetch_add_explicit(&ctrl->_generation, 1, memory_order_acq_rel);
                [ctrl stopScreenCaptureKitLocked];
                if (ctrl.queue) {
                    dispatch_sync(ctrl.queue, ^{
                        if (ctrl.lastPixelBuffer) {
                            CVPixelBufferRelease(ctrl.lastPixelBuffer);
                            ctrl.lastPixelBuffer = NULL;
                        }
                        ctrl.needsRefine = NO;
                    });
                }
                if (ctrl.sleepAssertionID != 0) {
                    IOPMAssertionRelease(ctrl.sleepAssertionID);
                    ctrl.sleepAssertionID = 0;
                }
                id_diag_log("capture_paused", @"displayID=%u", atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire));
            } else {
                atomic_store_explicit(&ctrl->_forceNextKeyframe, YES, memory_order_release);
                if (ctrl.sleepAssertionID == 0) {
                    IOPMAssertionID assertionID = 0;
                    if (IOPMAssertionCreateWithName(
                            kIOPMAssertionTypePreventUserIdleDisplaySleep,
                            kIOPMAssertionLevelOn,
                            CFSTR("idis active extended display session"),
                            &assertionID) == kIOReturnSuccess) {
                        ctrl.sleepAssertionID = assertionID;
                    }
                }
                if (!atomic_load_explicit(&ctrl->_sleeping, memory_order_acquire)) {
                    __block uint32_t pw = 0;
                    __block uint32_t ph = 0;
                    if (ctrl.queue) {
                        dispatch_sync(ctrl.queue, ^{
                            uint32_t logW = ctrl.requestedLogicalW >= 320 ? ctrl.requestedLogicalW : 1024;
                            uint32_t logH = ctrl.requestedLogicalH >= 240 ? ctrl.requestedLogicalH : 768;
                            [ctrl computeCapturePixelWidth:&pw height:&ph logicalWidth:logW logicalHeight:logH];
                            if (pw < 320 || ph < 240) {
                                pw = ctrl.encWidth >= 320 ? ctrl.encWidth : logW;
                                ph = ctrl.encHeight >= 240 ? ctrl.encHeight : logH;
                            }
                            if (pw >= 320 && ph >= 240) {
                                if (pw != ctrl.encWidth || ph != ctrl.encHeight || !ctrl.vtSession) {
                                    [ctrl createEncoderWidth:pw height:ph];
                                }
                                uint64_t packed = ((uint64_t)pw << 32) | (uint64_t)ph;
                                atomic_store_explicit(&ctrl->_atomicSize, packed, memory_order_release);
                            }
                        });
                    }
                    if (pw < 320 || ph < 240) {
                        uint64_t packed = atomic_load_explicit(&ctrl->_atomicSize, memory_order_acquire);
                        pw = (uint32_t)(packed >> 32);
                        ph = (uint32_t)(packed & 0xFFFFFFFFu);
                    }
                    if (![ctrl startScreenCaptureKitLockedWithWidth:pw height:ph]) {
                        [ctrl scheduleCaptureRestartAfterMs:300 targetW:pw targetH:ph attempt:0];
                    }
                }
                id_diag_log("capture_resumed", @"displayID=%u", atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire));
            }
        });
        return 0;
    }
}

int32_t id_macos_capture_set_low_power(void *handle, int32_t enabled) {
    @autoreleasepool {
        if (!handle) return -1;
        IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
        BOOL wantLp = (enabled != 0);
        atomic_store_explicit(&ctrl->_lowPower, wantLp, memory_order_release);
        if (ctrl.queue) {
            dispatch_async(ctrl.queue, ^{
                if (atomic_load_explicit(&ctrl->_stopped, memory_order_acquire)) return;
                if (wantLp) {
                    if (ctrl.refineVtSession) {
                        VTCompressionSessionInvalidate(ctrl.refineVtSession);
                        CFRelease(ctrl.refineVtSession);
                        ctrl.refineVtSession = NULL;
                    }
                    ctrl.needsRefine = NO;
                } else if (ctrl.allIntra && !ctrl.refineVtSession && ctrl.encWidth >= 320 && ctrl.encHeight >= 240) {
                    ctrl.refineVtSession = [ctrl buildVTSessionWidth:ctrl.encWidth height:ctrl.encHeight highQualityRefine:YES];
                }
            });
        }
        return 0;
    }
}

void id_macos_capture_stop(void *handle) {
    @autoreleasepool {
        if (!handle) return;
        IDCaptureController *ctrl = (__bridge_transfer IDCaptureController *)handle;
        [ctrl stop];
    }
}

// ============================================================================
// CoreGraphics Input Injection & Cursor Polling
// ============================================================================

int32_t id_macos_is_accessibility_trusted(void) {
    return AXIsProcessTrusted() ? 1 : 0;
}

int32_t id_macos_is_screen_locked(void) {
    return id_is_screen_locked() ? 1 : 0;
}

void id_macos_pump_main_runloop(void) {
    @autoreleasepool {
        // Non-blocking drain (0.0s timeout) of pending CoreGraphics / SkyLight display
        // reconfiguration Mach messages on the main CFRunLoop so `CGDisplayBounds` and
        // `CGDisplayCopyDisplayMode` stay fresh across virtual display reconnects/recreates.
        for (int i = 0; i < 32; i++) {
            CFRunLoopRunResult res = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.0, true);
            if (res != kCFRunLoopRunHandledSource) {
                break;
            }
        }
    }
}

int32_t id_macos_resolve_iface_ip(const char *iface_name, uint8_t out_addr[16], int32_t *out_is_v6) {
    if (!iface_name || !iface_name[0] || !out_addr || !out_is_v6) return 0;
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0 || !ifap) return 0;

    int32_t found = 0;
    int have_v6 = 0;
    int have_global_v6 = 0;
    uint8_t v6_buf[16];
    memset(v6_buf, 0, sizeof(v6_buf));

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, iface_name) != 0) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)ifa->ifa_addr;
            memcpy(out_addr, &sin->sin_addr, 4);
            *out_is_v6 = 0;
            found = 1;
            break;
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
            const uint8_t *b = (const uint8_t *)&sin6->sin6_addr;
            int is_ll = (b[0] == 0xfe && (b[1] & 0xc0) == 0x80);
            if (!have_v6 || (!is_ll && !have_global_v6)) {
                memcpy(v6_buf, b, 16);
                have_v6 = 1;
                if (!is_ll) have_global_v6 = 1;
            }
        }
    }
    freeifaddrs(ifap);
    if (!found && have_v6) {
        memcpy(out_addr, v6_buf, 16);
        *out_is_v6 = 1;
        found = 1;
    }
    return found;
}

static CGRect id_resolve_display_bounds(
    IDCaptureController *ctrl,
    CGDirectDisplayID targetDisplay,
    BOOL *outUsedFallback
) {
    CGRect cgBounds = CGDisplayBounds(targetDisplay);
    if (cgBounds.size.width > 0.0 && cgBounds.size.height > 0.0) {
        if (ctrl) {
            os_unfair_lock_lock(&ctrl->_boundsLock);
            ctrl->_scDisplayFrame = cgBounds;
            os_unfair_lock_unlock(&ctrl->_boundsLock);
        }
        if (outUsedFallback) *outUsedFallback = NO;
        return cgBounds;
    }
    if (ctrl) {
        os_unfair_lock_lock(&ctrl->_boundsLock);
        CGRect cached = ctrl->_scDisplayFrame;
        os_unfair_lock_unlock(&ctrl->_boundsLock);
        if (cached.size.width > 0.0 && cached.size.height > 0.0) {
            if (outUsedFallback) *outUsedFallback = YES;
            return cached;
        }
    }
    if (outUsedFallback) *outUsedFallback = NO;
    return CGRectZero;
}

static void id_warp_cursor_to_display(
    CGDirectDisplayID targetDisplay,
    CGPoint localPt,
    CGPoint globalPt,
    BOOL usedFallback
) {
    if (!usedFallback) {
        CGDisplayMoveCursorToPoint(targetDisplay, localPt);
    } else {
        // CoreGraphics's local display cache has not yet refreshed `targetDisplay`; warp using
        // authoritative global coordinates from `SCDisplay.frame` directly.
        CGWarpMouseCursorPosition(globalPt);
    }
    CGAssociateMouseAndMouseCursorPosition(true);
}

void id_macos_inject_mouse(void *handle, uint32_t video_w, uint32_t video_h, int32_t kind, double x, double y) {
    if (!handle || !isfinite(x) || !isfinite(y)) {
        return;
    }
    IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
    uint32_t display_id = atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire);
    CGDirectDisplayID targetDisplay = (display_id != 0) ? display_id : CGMainDisplayID();
    BOOL usedFallback = NO;
    CGRect bounds = id_resolve_display_bounds(ctrl, targetDisplay, &usedFallback);
    if (bounds.size.width <= 0.0 || bounds.size.height <= 0.0) {
        static _Atomic uint32_t gZeroBoundsDiag = 0;
        if (atomic_fetch_add_explicit(&gZeroBoundsDiag, 1, memory_order_relaxed) < 8) {
            id_diag_log(
                "inject_mouse_zero_bounds",
                @"displayID=%u video=%ux%u raw=(%.1f,%.1f) kind=%d",
                targetDisplay, video_w, video_h, x, y, kind
            );
        }
        return;
    }
    double maxX = (video_w > 0) ? (double)video_w : bounds.size.width;
    double maxY = (video_h > 0) ? (double)video_h : bounds.size.height;
    double cx = x < 0.0 ? 0.0 : (x > maxX ? maxX : x);
    double cy = y < 0.0 ? 0.0 : (y > maxY ? maxY : y);
    double scaleX = (video_w > 0) ? (bounds.size.width / (double)video_w) : 1.0;
    double scaleY = (video_h > 0) ? (bounds.size.height / (double)video_h) : 1.0;
    double localX = cx * scaleX;
    double localY = cy * scaleY;
    if (localX >= bounds.size.width) localX = bounds.size.width - 1.0;
    if (localY >= bounds.size.height) localY = bounds.size.height - 1.0;
    CGPoint localPt = CGPointMake(localX, localY);
    CGPoint pt = CGPointMake(bounds.origin.x + localX, bounds.origin.y + localY);

    ctrl->_lastInputLocalX = localX;
    ctrl->_lastInputLocalY = localY;
    ctrl->_hasLastInputPoint = YES;

    static _Atomic uint32_t gInjectDiagCount = 0;
    if (atomic_fetch_add_explicit(&gInjectDiagCount, 1, memory_order_relaxed) < 8) {
        id_diag_log(
            "inject_mouse",
            @"displayID=%u fallback=%d bounds=(%.0f,%.0f %.0fx%.0f) video=%ux%u raw=(%.1f,%.1f) local=(%.1f,%.1f) global=(%.1f,%.1f) kind=%d",
            targetDisplay, usedFallback ? 1 : 0, bounds.origin.x, bounds.origin.y, bounds.size.width, bounds.size.height,
            video_w, video_h, x, y, localX, localY, pt.x, pt.y, kind
        );
    }

    // Right-click fires down+up immediately on Began (`kind == 4`). Suppress both micro-drags
    // (`kind == 1`) and the trailing release (`kind == 2`) until the finger lifts so the context
    // menu is never disturbed or dismissed.
    if (kind == 4) {
        atomic_store_explicit(&ctrl->_suppressRightClickTail, YES, memory_order_release);
        id_warp_cursor_to_display(targetDisplay, localPt, pt, usedFallback);
        CGEventRef move = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, pt, kCGMouseButtonLeft);
        if (move) { CGEventPost(kCGSessionEventTap, move); CFRelease(move); }
        CGEventRef down = CGEventCreateMouseEvent(NULL, kCGEventRightMouseDown, pt, kCGMouseButtonRight);
        CGEventRef up = CGEventCreateMouseEvent(NULL, kCGEventRightMouseUp, pt, kCGMouseButtonRight);
        if (down) { CGEventPost(kCGSessionEventTap, down); CFRelease(down); }
        if (up) { CGEventPost(kCGSessionEventTap, up); CFRelease(up); }
        return;
    }
    if (kind == 1 && atomic_load_explicit(&ctrl->_suppressRightClickTail, memory_order_acquire)) {
        return;
    }
    if ((kind == 2 || kind == 3) && atomic_exchange_explicit(&ctrl->_suppressRightClickTail, NO, memory_order_acq_rel)) {
        return;
    }
    if (kind == 0 || kind == 5) {
        atomic_store_explicit(&ctrl->_suppressRightClickTail, NO, memory_order_release);
    }

    // Warp cursor onto target display before mouse-down (`kind == 0` / `5`) so WindowServer never
    // clamps clicks onto the primary Mac display. For drags (`kind == 1`), warp position only
    // without inserting a stray `kCGEventMouseMoved` that would break AppKit drag sessions.
    if (kind == 0 || kind == 5) {
        id_warp_cursor_to_display(targetDisplay, localPt, pt, usedFallback);
        CGEventRef move = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, pt, kCGMouseButtonLeft);
        if (move) {
            CGEventPost(kCGSessionEventTap, move);
            CFRelease(move);
        }
    } else if (kind == 1) {
        CGEventRef curEv = CGEventCreate(NULL);
        if (curEv) {
            CGPoint curLoc = CGEventGetLocation(curEv);
            CFRelease(curEv);
            if (!CGRectContainsPoint(bounds, curLoc)) {
                id_warp_cursor_to_display(targetDisplay, localPt, pt, usedFallback);
            }
        }
    }

    // Exact 2-click sequence for double-tap:
    // Tap 1: kind=0 (Down clickState=1) -> kind=2 (Up clickState=1)
    // Tap 2: kind=5 (Down clickState=2) -> kind=3 (Up clickState=2)
    CGEventType evType = kCGEventLeftMouseDown;
    int64_t clickState = 1;
    if (kind == 1) {
        evType = kCGEventLeftMouseDragged;
    } else if (kind == 2) {
        evType = kCGEventLeftMouseUp;
    } else if (kind == 5) {
        evType = kCGEventLeftMouseDown;
        clickState = 2;
    } else if (kind == 3) {
        evType = kCGEventLeftMouseUp;
        clickState = 2;
    }

    CGEventRef ev = CGEventCreateMouseEvent(NULL, evType, pt, kCGMouseButtonLeft);
    if (ev) {
        if (kind == 0 || kind == 2 || kind == 3 || kind == 5) {
            CGEventSetIntegerValueField(ev, kCGMouseEventClickState, clickState);
        }
        CGEventPost(kCGSessionEventTap, ev);
        CFRelease(ev);
    }
}

void id_macos_inject_scroll(void *handle, double dx, double dy) {
    if (!handle || !isfinite(dx) || !isfinite(dy)) {
        return;
    }
    IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
    uint32_t display_id = atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire);
    CGDirectDisplayID targetDisplay = (display_id != 0) ? display_id : CGMainDisplayID();
    BOOL usedFallback = NO;
    CGRect bounds = id_resolve_display_bounds(ctrl, targetDisplay, &usedFallback);
    if (bounds.size.width > 0.0 && bounds.size.height > 0.0) {
        CGEventRef curEv = CGEventCreate(NULL);
        BOOL inside = NO;
        if (curEv) {
            inside = CGRectContainsPoint(bounds, CGEventGetLocation(curEv));
            CFRelease(curEv);
        }
        if (!inside) {
            double lx = ctrl->_hasLastInputPoint
                ? MIN(ctrl->_lastInputLocalX, bounds.size.width - 1.0)
                : (bounds.size.width * 0.5);
            double ly = ctrl->_hasLastInputPoint
                ? MIN(ctrl->_lastInputLocalY, bounds.size.height - 1.0)
                : (bounds.size.height * 0.5);
            CGPoint pt = CGPointMake(bounds.origin.x + lx, bounds.origin.y + ly);
            id_warp_cursor_to_display(targetDisplay, CGPointMake(lx, ly), pt, usedFallback);
            CGEventRef move = CGEventCreateMouseEvent(NULL, kCGEventMouseMoved, pt, kCGMouseButtonLeft);
            if (move) {
                CGEventPost(kCGSessionEventTap, move);
                CFRelease(move);
            }
        }
    }
    ctrl->_scrollRemX += dx;
    ctrl->_scrollRemY += dy;
    int32_t ix = (int32_t)llround(ctrl->_scrollRemX);
    int32_t iy = (int32_t)llround(ctrl->_scrollRemY);
    if (ix == 0 && iy == 0) {
        return;
    }
    ctrl->_scrollRemX -= (double)ix;
    ctrl->_scrollRemY -= (double)iy;
    CGEventRef ev = CGEventCreateScrollWheelEvent(NULL, kCGScrollEventUnitPixel, 2, iy, ix);
    if (ev) {
        CGEventPost(kCGSessionEventTap, ev);
        CFRelease(ev);
    }
}

void id_macos_inject_key_code(uint16_t key_code) {
    CGEventRef down = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)key_code, true);
    CGEventRef up = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)key_code, false);
    if (down) { CGEventPost(kCGSessionEventTap, down); CFRelease(down); }
    if (up) { CGEventPost(kCGSessionEventTap, up); CFRelease(up); }
}

void id_macos_inject_unicode(uint16_t ch) {
    UniChar uc = (UniChar)ch;
    CGEventRef down = CGEventCreateKeyboardEvent(NULL, 0, true);
    CGEventRef up = CGEventCreateKeyboardEvent(NULL, 0, false);
    if (down) {
        CGEventKeyboardSetUnicodeString(down, 1, &uc);
        CGEventPost(kCGSessionEventTap, down);
        CFRelease(down);
    }
    if (up) {
        CGEventKeyboardSetUnicodeString(up, 1, &uc);
        CGEventPost(kCGSessionEventTap, up);
        CFRelease(up);
    }
}

int32_t id_macos_query_cursor(void *handle, uint32_t video_w, uint32_t video_h, uint32_t *out_x, uint32_t *out_y, int32_t *out_visible) {
    if (!handle) return 0;
    CGEventRef ev = CGEventCreate(NULL);
    if (!ev) return 0;
    CGPoint loc = CGEventGetLocation(ev);
    CFRelease(ev);

    IDCaptureController *ctrl = (__bridge IDCaptureController *)handle;
    uint32_t display_id = atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire);
    CGDirectDisplayID targetDisplay = (display_id != 0) ? display_id : CGMainDisplayID();
    CGRect bounds = id_resolve_display_bounds(ctrl, targetDisplay, NULL);
    BOOL inside = (bounds.size.width > 0.0 && bounds.size.height > 0.0) && CGRectContainsPoint(bounds, loc);
    if (out_visible) *out_visible = inside ? 1 : 0;
    if (inside) {
        double scaleX = (video_w > 0 && bounds.size.width > 0.0) ? ((double)video_w / bounds.size.width) : 1.0;
        double scaleY = (video_h > 0 && bounds.size.height > 0.0) ? ((double)video_h / bounds.size.height) : 1.0;
        double hotX = (double)atomic_load_explicit(&ctrl->_cursorHotX, memory_order_relaxed);
        double hotY = (double)atomic_load_explicit(&ctrl->_cursorHotY, memory_order_relaxed);
        // Compensate for cursor hotspot (stored in rendered video-pixel PNG coordinates so the
        // scaled PNG's hotspot aligns 1:1 with the logical pointer position in video pixel space).
        double vx = (loc.x - bounds.origin.x) * scaleX - hotX;
        double vy = (loc.y - bounds.origin.y) * scaleY - hotY;
        if (out_x) *out_x = (uint32_t)MAX(0.0, vx);
        if (out_y) *out_y = (uint32_t)MAX(0.0, vy);
    } else {
        if (out_x) *out_x = 0;
        if (out_y) *out_y = 0;
    }
    return 1;
}

int32_t id_macos_cursor_png(void *handle, uint32_t video_w, uint32_t video_h, uint8_t **out_ptr, size_t *out_len) {
    @autoreleasepool {
        if (!out_ptr || !out_len) return 0;
        *out_ptr = NULL;
        *out_len = 0;
        NSCursor *cursor = [NSCursor currentSystemCursor];
        NSImage *img = cursor ? cursor.image : nil;
        if (!img) {
            cursor = [NSCursor arrowCursor];
            img = cursor ? cursor.image : nil;
        }
        if (!img) {
            id_diag_log("cursor_png_err", @"stage=no_image");
            return 0;
        }

        // Scale the cursor PNG from logical points into the active video pixel coordinate space
        // (`video_w / bounds.size.width`), because legacy clients draw `ChangeCursorImage` PNGs
        // 1:1 in video pixel space.
        // Without this scaling, 2x HiDPI (2048x1536) renders a 1x cursor at 50% size and ABR
        // resolution tier changes make the cursor shrink and grow erratically.
        double scaleX = 1.0;
        double scaleY = 1.0;
        CGRect bounds = CGRectZero;
        IDCaptureController *ctrl = handle ? (__bridge IDCaptureController *)handle : nil;
        if (ctrl) {
            uint32_t display_id = atomic_load_explicit(&ctrl->_atomicDisplayID, memory_order_acquire);
            CGDirectDisplayID targetDisplay = (display_id != 0) ? display_id : CGMainDisplayID();
            bounds = id_resolve_display_bounds(ctrl, targetDisplay, NULL);
            if (video_w > 0 && bounds.size.width > 0.0) {
                scaleX = (double)video_w / bounds.size.width;
            }
            if (video_h > 0 && bounds.size.height > 0.0) {
                scaleY = (double)video_h / bounds.size.height;
            }
            if (scaleX < 0.25 || scaleX > 4.0) scaleX = 1.0;
            if (scaleY < 0.25 || scaleY > 4.0) scaleY = 1.0;
        }

        // Preserve exact logical aspect ratio (including macOS Accessibility enlarged cursors up
        // to 96pt) and render into video-scaled pixel coordinates using thread-safe CoreGraphics.
        NSSize ptSize = img.size;
        double origW = ptSize.width > 0 ? ptSize.width : 24.0;
        double origH = ptSize.height > 0 ? ptSize.height : 24.0;
        double logicalCap = 1.0;
        if (origW > 96.0 || origH > 96.0) {
            logicalCap = 96.0 / MAX(origW, origH);
        }
        double targetW = origW * logicalCap * scaleX;
        double targetH = origH * logicalCap * scaleY;
        double pixelCap = 1.0;
        if (targetW > 192.0 || targetH > 192.0) {
            pixelCap = 192.0 / MAX(targetW, targetH);
        }
        double effScaleX = logicalCap * scaleX * pixelCap;
        double effScaleY = logicalCap * scaleY * pixelCap;
        size_t w = (size_t)MAX(4, llround(origW * effScaleX));
        size_t h = (size_t)MAX(4, llround(origH * effScaleY));

        NSPoint hot = cursor.hotSpot;
        if (ctrl) {
            atomic_store_explicit(&ctrl->_cursorHotX, (int32_t)llround(hot.x * effScaleX), memory_order_relaxed);
            atomic_store_explicit(&ctrl->_cursorHotY, (int32_t)llround(hot.y * effScaleY), memory_order_relaxed);
            uint64_t diagKey = ((uint64_t)(w & 0xFFFF) << 48)
                             | ((uint64_t)(h & 0xFFFF) << 32)
                             | ((uint64_t)(video_w & 0xFFFF) << 16)
                             | (uint64_t)(video_h & 0xFFFF);
            uint64_t prevKey = atomic_exchange_explicit(&ctrl->_lastCursorDiagKey, diagKey, memory_order_relaxed);
            if (prevKey != diagKey) {
                id_diag_log("cursor_png_scale", @"pt=%.0fx%.0f bounds=%.0fx%.0f video=%ux%u scale=%.2fx%.2f png=%zux%zu hot=%.1f,%.1f",
                            origW, origH, bounds.size.width, bounds.size.height, video_w, video_h, scaleX, scaleY, w, h,
                            hot.x * effScaleX, hot.y * effScaleY);
            }
        }

        NSRect proposed = NSMakeRect(0, 0, (CGFloat)w, (CGFloat)h);
        CGImageRef srcImg = [img CGImageForProposedRect:&proposed context:nil hints:nil];
        if (!srcImg) {
            srcImg = [img CGImageForProposedRect:NULL context:nil hints:nil];
        }
        NSBitmapImageRep *tiffRep = nil;
        if (!srcImg) {
            NSData *tiff = [img TIFFRepresentation];
            if (tiff.length > 0) {
                tiffRep = [NSBitmapImageRep imageRepWithData:tiff];
                srcImg = tiffRep.CGImage;
            }
        }
        if (!srcImg && cursor != [NSCursor arrowCursor]) {
            NSCursor *fallback = [NSCursor arrowCursor];
            NSImage *fbImg = fallback ? fallback.image : nil;
            if (fbImg) {
                srcImg = [fbImg CGImageForProposedRect:&proposed context:nil hints:nil]
                    ?: [fbImg CGImageForProposedRect:NULL context:nil hints:nil];
            }
        }
        if (!srcImg) {
            id_diag_log("cursor_png_err", @"stage=no_cgimage pt=%.0fx%.0f target=%zux%zu", origW, origH, w, h);
            return 0;
        }

        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        if (!cs) return 0;
        CGContextRef cgCtx = CGBitmapContextCreate(
            NULL,
            w,
            h,
            8,
            w * 4,
            cs,
            kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big
        );
        CGColorSpaceRelease(cs);
        if (!cgCtx) return 0;

        CGContextSetInterpolationQuality(cgCtx, kCGInterpolationHigh);
        CGContextClearRect(cgCtx, CGRectMake(0, 0, (CGFloat)w, (CGFloat)h));
        CGContextDrawImage(cgCtx, CGRectMake(0, 0, (CGFloat)w, (CGFloat)h), srcImg);
        CGImageRef scaledImg = CGBitmapContextCreateImage(cgCtx);
        CGContextRelease(cgCtx);
        if (!scaledImg) return 0;

        NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithCGImage:scaledImg];
        CGImageRelease(scaledImg);
        if (!rep) return 0;

        NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
        if (!png || png.length == 0) return 0;
        uint8_t *buf = (uint8_t *)malloc(png.length);
        if (!buf) return 0;
        memcpy(buf, png.bytes, png.length);
        *out_ptr = buf;
        *out_len = png.length;
        return 1;
    }
}

void id_macos_free_bytes(uint8_t *ptr) {
    if (ptr) free(ptr);
}

// ============================================================================
// Standalone Ephemeral Virtual Displays & AX Desktop Window Routing (macOS)
// ============================================================================

uint32_t id_macos_main_display_id(void) {
    return (uint32_t)CGMainDisplayID();
}

int32_t id_macos_display_bounds(
    uint32_t display_id,
    int32_t *out_x,
    int32_t *out_y,
    uint32_t *out_w,
    uint32_t *out_h
) {
    if (display_id == kCGNullDirectDisplay) return 0;
    CGRect b = CGDisplayBounds((CGDirectDisplayID)display_id);
    if (b.size.width < 1.0 || b.size.height < 1.0) return 0;
    if (out_x) *out_x = (int32_t)llround(b.origin.x);
    if (out_y) *out_y = (int32_t)llround(b.origin.y);
    if (out_w) *out_w = (uint32_t)llround(b.size.width);
    if (out_h) *out_h = (uint32_t)llround(b.size.height);
    return 1;
}

void *id_macos_virtual_display_create(
    const char *name,
    uint32_t width,
    uint32_t height,
    uint32_t serial_num
) {
    @autoreleasepool {
        uint32_t w = (width >= 320 && width <= 3840) ? (width & ~1u) : 1280;
        uint32_t h = (height >= 240 && height <= 2160) ? (height & ~1u) : 720;
        NSString *nsName = (name && name[0]) ? [NSString stringWithUTF8String:name] : @"idis Virtual";
        // Headless standalone virtual display: 1x non-HiDPI, zero SCStream / VideoToolbox overhead.
        IDVirtualDisplayWrapper *vd = [[IDVirtualDisplayWrapper alloc]
            initWithWidth:w
                   height:h
                    hiDPI:1
                serialNum:(serial_num != 0 ? serial_num : 0x49448001u)
                     name:nsName
       terminationHandler:nil];
        if (!vd || vd.displayID == kCGNullDirectDisplay) {
            id_diag_log("standalone_vd_create_failed", @"name=%@ req=%ux%u", nsName, w, h);
            return NULL;
        }
        // Brief settle window so WindowServer registers bounds for immediate window moves.
        for (int i = 0; i < 6; i++) {
            CGRect b = CGDisplayBounds(vd.displayID);
            if (b.size.width >= 320.0 && b.size.height >= 240.0) break;
            usleep(35000);
        }
        id_diag_log("standalone_vd_created", @"name=%@ displayID=%u req=%ux%u", nsName, vd.displayID, w, h);
        return (__bridge_retained void *)vd;
    }
}

uint32_t id_macos_virtual_display_id(void *handle) {
    if (!handle) return 0;
    IDVirtualDisplayWrapper *vd = (__bridge IDVirtualDisplayWrapper *)handle;
    return (uint32_t)vd.displayID;
}

void id_macos_virtual_display_destroy(void *handle) {
    @autoreleasepool {
        if (!handle) return;
        IDVirtualDisplayWrapper *vd = (__bridge_transfer IDVirtualDisplayWrapper *)handle;
        id_diag_log("standalone_vd_destroyed", @"displayID=%u", vd.displayID);
        vd.displayObj = nil;
    }
}

int32_t id_macos_list_windows_json(uint8_t **out_ptr, size_t *out_len) {
    @autoreleasepool {
        if (!out_ptr || !out_len) return 0;
        *out_ptr = NULL;
        *out_len = 0;

        CGDirectDisplayID displays[16];
        CGRect dispBounds[16];
        uint32_t dispCount = 0;
        if (CGGetOnlineDisplayList(16, displays, &dispCount) == kCGErrorSuccess) {
            for (uint32_t i = 0; i < dispCount; i++) {
                dispBounds[i] = CGDisplayBounds(displays[i]);
            }
        }
        CGDirectDisplayID mainID = CGMainDisplayID();

        CFArrayRef rawList = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
            kCGNullWindowID
        );
        if (!rawList) return 0;

        pid_t selfPid = getpid();
        NSMutableDictionary<NSNumber *, NSRunningApplication *> *appCache = [NSMutableDictionary dictionary];
        NSSet<NSString *> *ignoredBundles = [NSSet setWithObjects:
            @"com.apple.dock",
            @"com.apple.controlcenter",
            @"com.apple.notificationcenterui",
            @"com.apple.systemuiserver",
            @"com.apple.WindowManager",
            @"com.apple.Spotlight",
            @"com.apple.loginwindow",
            nil
        ];
        NSMutableArray *result = [NSMutableArray array];
        CFIndex count = CFArrayGetCount(rawList);
        for (CFIndex i = 0; i < count; i++) {
            NSDictionary *info = (__bridge NSDictionary *)CFArrayGetValueAtIndex(rawList, i);
            if (![info isKindOfClass:[NSDictionary class]]) continue;

            NSNumber *pidNum = info[(id)kCGWindowOwnerPID];
            NSNumber *widNum = info[(id)kCGWindowNumber];
            NSNumber *layerNum = info[(id)kCGWindowLayer];
            NSNumber *alphaNum = info[(id)kCGWindowAlpha];
            NSDictionary *boundsDict = info[(id)kCGWindowBounds];
            if (!pidNum || !widNum || !boundsDict) continue;

            pid_t pid = (pid_t)pidNum.intValue;
            if (pid <= 0 || pid == selfPid) continue;

            int32_t layer = layerNum ? layerNum.intValue : 0;
            // Include standard windows (layer == 0) AND floating overlays / widgets (0 < layer <= 100,
            // e.g. Notion AI recording bar at NSFloatingWindowLevel = 3 / NSStatusWindowLevel = 25).
            if (layer < 0 || layer > 100) continue;
            if (alphaNum && alphaNum.doubleValue <= 0.01) continue;

            CGRect bounds = CGRectZero;
            if (!CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)boundsDict, &bounds)) {
                continue;
            }
            if (bounds.size.width < 24.0 || bounds.size.height < 20.0) continue;

            NSString *ownerName = info[(id)kCGWindowOwnerName] ?: @"";
            if ([ownerName isEqualToString:@"Window Server"]
                || [ownerName isEqualToString:@"Dock"]
                || [ownerName isEqualToString:@"Control Center"]
                || [ownerName isEqualToString:@"Notification Center"]
                || [ownerName isEqualToString:@"SystemUIServer"]) {
                continue;
            }

            NSRunningApplication *app = appCache[pidNum];
            if (!app) {
                app = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
                if (app) appCache[pidNum] = app;
            }
            NSString *bundleId = (app && app.bundleIdentifier) ? app.bundleIdentifier : @"";
            if (bundleId.length > 0 && [ignoredBundles containsObject:bundleId]) continue;

            NSString *appName = (app && app.localizedName.length > 0) ? app.localizedName : ownerName;
            NSString *title = info[(id)kCGWindowName] ?: @"";
            if (appName.length == 0 && title.length == 0) continue;

            CGPoint center = CGPointMake(CGRectGetMidX(bounds), CGRectGetMidY(bounds));
            CGDirectDisplayID onDisplay = mainID;
            for (uint32_t d = 0; d < dispCount; d++) {
                if (CGRectContainsPoint(dispBounds[d], center)) {
                    onDisplay = displays[d];
                    break;
                }
            }

            [result addObject:@{
                @"window_id": @((uint32_t)widNum.unsignedIntValue),
                @"pid": @((int32_t)pid),
                @"app_name": appName ?: @"",
                @"bundle_id": bundleId ?: @"",
                @"title": title ?: @"",
                @"x": @((int32_t)llround(bounds.origin.x)),
                @"y": @((int32_t)llround(bounds.origin.y)),
                @"width": @((uint32_t)llround(bounds.size.width)),
                @"height": @((uint32_t)llround(bounds.size.height)),
                @"layer": @(layer),
                @"is_floating": ((layer > 0) ? @YES : @NO),
                @"display_id": @((uint32_t)onDisplay),
            }];
        }
        CFRelease(rawList);

        NSError *jsonErr = nil;
        NSData *jsonData = [NSJSONSerialization dataWithJSONObject:result options:0 error:&jsonErr];
        if (!jsonData || jsonErr || jsonData.length == 0) return 0;
        uint8_t *buf = (uint8_t *)malloc(jsonData.length);
        if (!buf) return 0;
        memcpy(buf, jsonData.bytes, jsonData.length);
        *out_ptr = buf;
        *out_len = jsonData.length;
        return 1;
    }
}

typedef AXError (*IDAXGetWindowFn)(AXUIElementRef, CGWindowID *);

static AXUIElementRef id_match_ax_window_in_array(
    CFArrayRef arr,
    CGWindowID targetWinID,
    BOOL haveBounds,
    CGRect cgBounds,
    IDAXGetWindowFn getWinFn,
    AXUIElementRef *outBoundsFallback
) {
    if (!arr) return NULL;
    CFIndex cnt = CFArrayGetCount(arr);
    for (CFIndex i = 0; i < cnt; i++) {
        AXUIElementRef elem = (AXUIElementRef)CFArrayGetValueAtIndex(arr, i);
        if (!elem) continue;
        if (getWinFn) {
            CGWindowID wid = kCGNullWindowID;
            if (getWinFn(elem, &wid) == kAXErrorSuccess && wid == targetWinID) {
                CFRetain(elem);
                return elem;
            }
        }
        if (haveBounds && outBoundsFallback && !*outBoundsFallback) {
            CFTypeRef roleVal = NULL;
            BOOL isWindowLike = YES;
            if (AXUIElementCopyAttributeValue(elem, kAXRoleAttribute, &roleVal) == kAXErrorSuccess && roleVal) {
                if (CFGetTypeID(roleVal) == CFStringGetTypeID()) {
                    isWindowLike = CFEqual(roleVal, kAXWindowRole);
                }
                CFRelease(roleVal);
            }
            if (!isWindowLike) continue;
            CFTypeRef posVal = NULL;
            CFTypeRef sizeVal = NULL;
            CGPoint axPos = CGPointZero;
            CGSize axSize = CGSizeZero;
            BOOL okPos = (AXUIElementCopyAttributeValue(elem, kAXPositionAttribute, &posVal) == kAXErrorSuccess
                          && posVal && AXValueGetValue((AXValueRef)posVal, kAXValueTypeCGPoint, &axPos));
            BOOL okSize = (AXUIElementCopyAttributeValue(elem, kAXSizeAttribute, &sizeVal) == kAXErrorSuccess
                           && sizeVal && AXValueGetValue((AXValueRef)sizeVal, kAXValueTypeCGSize, &axSize));
            if (posVal) CFRelease(posVal);
            if (sizeVal) CFRelease(sizeVal);
            if (okPos && okSize
                && fabs(axPos.x - cgBounds.origin.x) <= 8.0
                && fabs(axPos.y - cgBounds.origin.y) <= 8.0
                && fabs(axSize.width - cgBounds.size.width) <= 8.0
                && fabs(axSize.height - cgBounds.size.height) <= 8.0) {
                CFRetain(elem);
                *outBoundsFallback = elem;
            }
        }
    }
    return NULL;
}

static AXUIElementRef id_find_ax_window_for_cgid(
    AXUIElementRef appRef,
    CGWindowID targetWinID,
    BOOL haveBounds,
    CGRect cgBounds
) {
    static IDAXGetWindowFn sGetWinFn = NULL;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sGetWinFn = (IDAXGetWindowFn)dlsym(RTLD_DEFAULT, "_AXUIElementGetWindow");
    });

    for (int pass = 0; pass < 2; pass++) {
        if (pass == 1) {
            // Some Electron apps hide floating overlay windows from AX until
            // AXManualAccessibility is enabled on the target application element.
            AXUIElementSetAttributeValue(appRef, CFSTR("AXManualAccessibility"), kCFBooleanTrue);
            usleep(30000);
        }
        AXUIElementRef fallback = NULL;
        CFTypeRef winsVal = NULL;
        if (AXUIElementCopyAttributeValue(appRef, kAXWindowsAttribute, &winsVal) == kAXErrorSuccess && winsVal) {
            if (CFGetTypeID(winsVal) == CFArrayGetTypeID()) {
                AXUIElementRef exact = id_match_ax_window_in_array(
                    (CFArrayRef)winsVal, targetWinID, haveBounds, cgBounds, sGetWinFn, &fallback
                );
                if (exact) {
                    if (fallback) CFRelease(fallback);
                    CFRelease(winsVal);
                    return exact;
                }
            }
            CFRelease(winsVal);
        }
        // Also scan kAXChildrenAttribute for floating NSPanel / Electron overlay windows.
        CFTypeRef childrenVal = NULL;
        if (AXUIElementCopyAttributeValue(appRef, kAXChildrenAttribute, &childrenVal) == kAXErrorSuccess && childrenVal) {
            if (CFGetTypeID(childrenVal) == CFArrayGetTypeID()) {
                AXUIElementRef exact = id_match_ax_window_in_array(
                    (CFArrayRef)childrenVal, targetWinID, haveBounds, cgBounds, sGetWinFn, &fallback
                );
                if (exact) {
                    if (fallback) CFRelease(fallback);
                    CFRelease(childrenVal);
                    return exact;
                }
            }
            CFRelease(childrenVal);
        }
        if (fallback) {
            return fallback;
        }
    }
    return NULL;
}

int32_t id_macos_move_window(
    uint32_t window_id,
    int32_t pid,
    uint32_t target_display_id,
    int32_t fill_screen,
    char *err_buf,
    size_t err_cap
) {
    @autoreleasepool {
        if (err_buf && err_cap > 0) err_buf[0] = '\0';
        if (!AXIsProcessTrusted()) {
            if (err_buf && err_cap > 0) {
                snprintf(err_buf, err_cap, "未授予 macOS 辅助功能权限，请在系统设置 -> 隐私与安全性 -> 辅助功能中允许 idis");
            }
            return -2;
        }
        if (target_display_id == kCGNullDirectDisplay) {
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "目标屏幕 ID 无效");
            return -3;
        }
        CGRect targetBounds = CGDisplayBounds((CGDirectDisplayID)target_display_id);
        if (targetBounds.size.width < 100.0 || targetBounds.size.height < 100.0) {
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "目标屏幕 %u 不可用或已断开", target_display_id);
            return -3;
        }
        if (fill_screen != 0 && (CGDirectDisplayID)target_display_id == CGMainDisplayID() && targetBounds.size.height > 120.0) {
            targetBounds.origin.y += 25.0;
            targetBounds.size.height -= 25.0;
        }

        // Resolve live CGWindow bounds & owner PID strictly from WindowServer (fail-closed;
        // do not trust caller-supplied pid when window_id does not exist).
        (void)pid;
        CGRect cgBounds = CGRectZero;
        BOOL haveBounds = NO;
        pid_t resolvedPid = 0;
        CFArrayRef singleList = CGWindowListCopyWindowInfo(kCGWindowListOptionIncludingWindow, (CGWindowID)window_id);
        if (singleList) {
            if (CFArrayGetCount(singleList) > 0) {
                NSDictionary *info = (__bridge NSDictionary *)CFArrayGetValueAtIndex(singleList, 0);
                if ([info isKindOfClass:[NSDictionary class]]) {
                    NSNumber *p = info[(id)kCGWindowOwnerPID];
                    if (p && p.intValue > 0) resolvedPid = (pid_t)p.intValue;
                    NSDictionary *bd = info[(id)kCGWindowBounds];
                    if (bd && CGRectMakeWithDictionaryRepresentation((__bridge CFDictionaryRef)bd, &cgBounds)) {
                        haveBounds = YES;
                    }
                }
            }
            CFRelease(singleList);
        }
        if (resolvedPid <= 0) {
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "找不到窗口 %u 对应的应用进程", window_id);
            return -4;
        }

        AXUIElementRef appRef = AXUIElementCreateApplication(resolvedPid);
        if (!appRef) {
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "无法访问进程 %d 的辅助功能对象", (int)resolvedPid);
            return -4;
        }
        AXUIElementRef targetWin = id_find_ax_window_for_cgid(appRef, (CGWindowID)window_id, haveBounds, cgBounds);
        CFRelease(appRef);
        if (!targetWin) {
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "未找到窗口 %u 的可控制对象（可能为系统受保护或原生全屏窗口）", window_id);
            return -5;
        }

        CGSize curSize = haveBounds ? cgBounds.size : CGSizeMake(640.0, 480.0);
        CFTypeRef sizeAttr = NULL;
        if (AXUIElementCopyAttributeValue(targetWin, kAXSizeAttribute, &sizeAttr) == kAXErrorSuccess && sizeAttr) {
            CGSize axSize = CGSizeZero;
            if (AXValueGetValue((AXValueRef)sizeAttr, kAXValueTypeCGSize, &axSize) && axSize.width >= 10.0 && axSize.height >= 10.0) {
                curSize = axSize;
            }
            CFRelease(sizeAttr);
        }

        CGPoint destPos;
        CGSize destSize = curSize;
        BOOL needResize = NO;
        if (fill_screen != 0) {
            destPos = targetBounds.origin;
            destSize = targetBounds.size;
            needResize = YES;
        } else {
            if (destSize.width > targetBounds.size.width) {
                destSize.width = targetBounds.size.width;
                needResize = YES;
            }
            if (destSize.height > targetBounds.size.height) {
                destSize.height = targetBounds.size.height;
                needResize = YES;
            }
            destPos.x = targetBounds.origin.x + floor((targetBounds.size.width - destSize.width) * 0.5);
            destPos.y = targetBounds.origin.y + floor((targetBounds.size.height - destSize.height) * 0.5);
        }

        AXValueRef posVal = AXValueCreate(kAXValueTypeCGPoint, &destPos);
        AXError posErr1 = posVal ? AXUIElementSetAttributeValue(targetWin, kAXPositionAttribute, posVal) : kAXErrorFailure;
        if (needResize) {
            AXValueRef sizeVal = AXValueCreate(kAXValueTypeCGSize, &destSize);
            if (sizeVal) {
                AXUIElementSetAttributeValue(targetWin, kAXSizeAttribute, sizeVal);
                CFRelease(sizeVal);
            }
        }
        // Re-apply position after optional resize so macOS does not clamp across monitor boundaries.
        AXError posErr2 = posVal ? AXUIElementSetAttributeValue(targetWin, kAXPositionAttribute, posVal) : kAXErrorFailure;
        if (posVal) CFRelease(posVal);
        CFRelease(targetWin);

        if (posErr1 != kAXErrorSuccess && posErr2 != kAXErrorSuccess) {
            if (err_buf && err_cap > 0) {
                snprintf(err_buf, err_cap, "移动窗口 %u 失败（AXError=%d/%d）", window_id, (int)posErr1, (int)posErr2);
            }
            return -6;
        }
        id_diag_log(
            "ax_window_moved",
            @"wid=%u pid=%d targetDisplay=%u fill=%d dest=(%.0f,%.0f %.0fx%.0f)",
            window_id,
            (int)resolvedPid,
            target_display_id,
            fill_screen,
            destPos.x,
            destPos.y,
            destSize.width,
            destSize.height
        );
        return 0;
    }
}
