#pragma once

/* v11.8b: panic-proof native-side log tee.
 *
 * The app's direct path delivers native logs to ghostlock-direct-*.log.txt
 * via a three-hop chain: __android_log_print -> logcat daemon -> app pipe
 * reader -> MediaStore file. Every hop buffers, and a kernel panic kills the
 * chain mid-flight — the 2026-10-03 13:34 panic left a zero-byte log even
 * though the native had run for ~65s. Bypass all of it: pr_emit writes each
 * line to logcat (live debugging) AND appends to an O_SYNC, _IONBF file the
 * native owns outright. O_SYNC means the line is on storage before the call
 * returns; a panic can no longer eat it. */

#include <android/log.h>
#include <sys/stat.h>
#include <cstdarg>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

namespace ghostlock::support {

inline std::FILE *g_osync_log = nullptr;

/* v11.8c: the app-specific external dir does not exist on this unit
 * (Android/data/com.ghostlock.app/ ENOENT after the panic-reboot cycle), so
 * probe candidate locations and mkdir what is missing. The native runs as
 * root via the KernelSU spawn on success paths and as the app uid otherwise
 * — /data/data/<pkg>/files is app-owned and always reachable, /data/local/tmp
 * is the fallback. */
/* v11.9b: NO O_SYNC here — FUSE (/storage/emulated) silently swallows
 * O_SYNC writes: panic #10 left a 0-byte file despite 56s of runtime.
 * _IONBF alone gives one write(2) per log line through FUSE, so a panic
 * loses at most the line in flight. */
inline std::FILE *osync_try_open(const char *dir) {
    ::mkdir(dir, 0755);
    std::string path = std::string(dir) + "/native-osync.log";
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return nullptr;
    std::FILE *f = ::fdopen(fd, "a");
    if (!f) {
        ::close(fd);
        return nullptr;
    }
    ::setvbuf(f, nullptr, _IONBF, 0);
    return f;
}

inline void osync_log_init(const char *preferred_dir = nullptr) {
    if (g_osync_log) return;
    /* v11.8f: prefer the run's debug-export dir (--dump-kernel-log, the same
     * folder profile.conf lands in). The app created it under its own uid
     * before spawning us, so FUSE lets us append — and adb can pull it
     * directly, unlike filesDir. */
    if (preferred_dir && preferred_dir[0]) {
        std::string path = std::string(preferred_dir) + "/native-osync.log";
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            std::FILE *f = ::fdopen(fd, "a");
            if (f) {
                ::setvbuf(f, nullptr, _IONBF, 0);
                g_osync_log = f;
                return;
            }
            ::close(fd);
        }
    }
    static const char *const kCandidates[] = {
            "/data/data/com.ghostlock.app/files",
            "/storage/emulated/0/Android/data/com.ghostlock.app/files",
            "/data/local/tmp",
    };
    for (const char *dir : kCandidates) {
        g_osync_log = osync_try_open(dir);
        if (g_osync_log) return;
    }
}

inline void pr_emit(const char *fmt, ...) {
    {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(stdout, fmt, ap);
        std::fflush(stdout);
        va_end(ap);
    }
    if (g_osync_log) {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(g_osync_log, fmt, ap);
        va_end(ap);
    }
}

inline void pr_emit_logcat(int prio, const char *fmt, ...) {
    {
        va_list ap;
        va_start(ap, fmt);
        __android_log_vprint(prio, "google_poc_app", fmt, ap);
        va_end(ap);
    }
    if (g_osync_log) {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(g_osync_log, fmt, ap);
        va_end(ap);
    }
}

} // namespace ghostlock::support
