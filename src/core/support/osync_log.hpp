#pragma once

/* v11.8b: panic-proof native-side log tee.
 *
 * The app's direct path delivers native logs to ghostlock-direct-*.log.txt
 * via a three-hop chain: __android_log_print -> logcat daemon -> app pipe
 * reader -> MediaStore file. Every hop buffers, and a kernel panic kills the
 * chain mid-flight — the 2026-10-03 13:34 panic left a zero-byte log even
 * though the native had run for ~65s. Bypass all of it: each line also goes
 * to a file the native owns outright.
 *
 * v11.9b: NO O_SYNC — FUSE (/storage/emulated) silently swallows O_SYNC
 * writes.
 * v11.9c: VERIFY the open actually delivers bytes. The direct-path native
 * runs as the app uid; on the 17:14 run open() on the FUSE export dir
 * succeeded but every write() was silently discarded (0-byte file after a
 * 90s run). Probe-write each candidate and fall through on failure; the
 * filesDir candidate is rescued into the export area by the app itself on
 * the next launch (v11.8e hook). */

#include <android/log.h>
#include <sys/stat.h>
#include <cstdarg>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

namespace ghostlock::support {

inline std::FILE *g_osync_log = nullptr;

inline std::FILE *osync_try_open(const char *dir) {
    ::mkdir(dir, 0755);
    std::string path = std::string(dir) + "/native-osync.log";
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return nullptr;
    const char probe = '\n';
    if (::write(fd, &probe, 1) != 1) {
        ::close(fd);
        return nullptr;
    }
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
     * folder profile.conf lands in). v11.9c: only when the probe write
     * lands; otherwise fall through. */
    if (preferred_dir && preferred_dir[0]) {
        g_osync_log = osync_try_open(preferred_dir);
        if (g_osync_log) return;
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
    if (g_osync_log) {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(g_osync_log, fmt, ap);
        va_end(ap);
    }
    {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(stdout, fmt, ap);
        std::fflush(stdout);
        va_end(ap);
    }
}

inline void pr_emit_logcat(int prio, const char *fmt, ...) {
    if (g_osync_log) {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(g_osync_log, fmt, ap);
        va_end(ap);
    }
    {
        va_list ap;
        va_start(ap, fmt);
        __android_log_vprint(prio, "google_poc_app", fmt, ap);
        va_end(ap);
    }
}

} // namespace ghostlock::support
