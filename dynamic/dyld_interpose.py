#!/usr/bin/env python3
"""
dyld_interpose Tracing
Interpose dyld APIs to trace dynamic library loads, symbol resolution, chained fixups.
Generates Frida scripts for runtime tracing.
"""

import sys
import json
from typing import List, Dict, Optional
from pathlib import Path


DYLD_INTERPOSE_SCRIPT = r"""
// dyld_interpose tracing script for Frida
// Intercepts dyld APIs to trace library loads, symbol resolution, fixups

const modules = new Map();
const symbols = new Map();
const fixups = [];

// dyld_image_path_containing_address
const dyld_image_path_containing_address = Module.findExportByName(null, 'dyld_image_path_containing_address');
if (dyld_image_path_containing_address) {
    Interceptor.attach(dyld_image_path_containing_address, {
        onEnter(args) {
            this.addr = args[0];
        },
        onLeave(retval) {
            const path = retval.readUtf8String();
            if (path && !modules.has(this.addr)) {
                modules.set(this.addr, path);
                console.log(`[dyld] Image loaded: ${path} @ ${this.addr}`);
            }
        }
    });
}

// dyld_get_image_name
const dyld_get_image_name = Module.findExportByName(null, 'dyld_get_image_name');
if (dyld_get_image_name) {
    Interceptor.attach(dyld_get_image_name, {
        onEnter(args) {
            this.index = args[0].toInt32();
        },
        onLeave(retval) {
            const name = retval.readUtf8String();
            if (name) {
                console.log(`[dyld] Image ${this.index}: ${name}`);
            }
        }
    });
}

// dyld_get_image_header
const dyld_get_image_header = Module.findExportByName(null, 'dyld_get_image_header');
if (dyld_get_image_header) {
    Interceptor.attach(dyld_get_image_header, {
        onEnter(args) {
            this.index = args[0].toInt32();
        },
        onLeave(retval) {
            if (!retval.isNull()) {
                console.log(`[dyld] Header for image ${this.index}: ${retval}`);
            }
        }
    });
}

// dyld_register_func_for_add_image / dyld_register_func_for_remove_image
['dyld_register_func_for_add_image', 'dyld_register_func_for_remove_image'].forEach(fn => {
    const addr = Module.findExportByName(null, fn);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) {
                this.callback = args[0];
                console.log(`[dyld] Registered ${fn}: callback=${this.callback}`);
            }
        });
    }
});

// dlopen / dlclose / dlsym / dladdr
['dlopen', 'dlclose', 'dlsym', 'dladdr'].forEach(fn => {
    const addr = Module.findExportByName(null, fn);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) {
                if (fn === 'dlopen') {
                    this.path = args[0].readUtf8String();
                    this.mode = args[1].toInt32();
                    console.log(`[dlopen] path=${this.path} mode=${this.mode}`);
                } else if (fn === 'dlsym') {
                    this.handle = args[0];
                    this.symbol = args[1].readUtf8String();
                    console.log(`[dlsym] handle=${this.handle} symbol=${this.symbol}`);
                } else if (fn === 'dladdr') {
                    this.addr = args[0];
                }
            },
            onLeave(retval) {
                if (fn === 'dlopen') {
                    console.log(`[dlopen] returned ${retval} for ${this.path}`);
                } else if (fn === 'dlsym') {
                    console.log(`[dlsym] ${this.symbol} -> ${retval}`);
                } else if (fn === 'dladdr') {
                    if (!retval.isNull()) {
                        // Dl_info structure
                        const info = retval;
                        const fname = info.add(0).readPointer().readUtf8String();
                        const fbase = info.add(8).readPointer();
                        const sname = info.add(16).readPointer().readUtf8String();
                        const saddr = info.add(24).readPointer();
                        console.log(`[dladdr] ${this.addr} -> ${fname} (${fbase}) ${sname} (${saddr})`);
                    }
                }
            }
        });
    }
});

// Symbol resolution tracing via dyld APIs
const dyld_find_unwind_sections = Module.findExportByName(null, 'dyld_find_unwind_sections');
if (dyld_find_unwind_sections) {
    Interceptor.attach(dyld_find_unwind_sections, {
        onEnter(args) {
            console.log(`[dyld] Find unwind sections`);
        }
    });
}

// Chained fixups tracing (dyld_chained_fixups)
// These are applied at startup, harder to trace dynamically
// But we can trace the dyld functions that apply them

// Output summary on detach
setImmediate(() => {
    // Periodic summary
    setInterval(() => {
        if (modules.size > 0) {
            console.log(`[dyld] Loaded modules: ${modules.size}`);
        }
    }, 5000);
});

// Helper: enumerate all loaded images
function enumerateImages() {
    const count = Module.findExportByName(null, '_dyld_image_count');
    if (count) {
        const n = new NativeFunction(count, 'uint32', [])();
        const getName = Module.findExportByName(null, '_dyld_get_image_name');
        const getHeader = Module.findExportByName(null, '_dyld_get_image_header');
        const getSlide = Module.findExportByName(null, '_dyld_get_image_vmaddr_slide');
        
        for (let i = 0; i < n; i++) {
            const name = getName ? new NativeFunction(getName, 'pointer', ['uint32'])(i) : null;
            const header = getHeader ? new NativeFunction(getHeader, 'pointer', ['uint32'])(i) : null;
            const slide = getSlide ? new NativeFunction(getSlide, 'uint64', ['uint32'])(i) : 0;
            if (name) {
                console.log(`[enum] Image ${i}: ${name.readUtf8String()} header=${header} slide=0x${slide.toString(16)}`);
            }
        }
    }
}

// Run enumeration on load
enumerateImages();
"""


def generate_dyld_trace_script(output_path: str, options: Dict = None) -> bool:
    """Generate Frida script for dyld tracing."""
    opts = options or {}
    
    script = DYLD_INTERPOSE_SCRIPT
    
    # Add custom options
    if opts.get('trace_symbols'):
        script += """
// Trace specific symbol resolutions
const target_symbols = %s;
['dlsym', 'dlvsym'].forEach(fn => {
    const addr = Module.findExportByName(null, fn);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter(args) {
                const sym = args[1].readUtf8String();
                if (target_symbols.includes(sym)) {
                    this.target = sym;
                    console.log(`[TARGET] Resolving ${sym}`);
                }
            },
            onLeave(retval) {
                if (this.target) {
                    console.log(`[TARGET] ${this.target} -> ${retval}`);
                }
            }
        });
    }
});
""" % json.dumps(opts['trace_symbols'])
    
    if opts.get('trace_dlopen'):
        script += """
// Enhanced dlopen tracing with stack
const dlopen = Module.findExportByName(null, 'dlopen');
if (dlopen) {
    Interceptor.attach(dlopen, {
        onEnter(args) {
            this.path = args[0].readUtf8String();
            console.log(`[dlopen] ${this.path}`);
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
        }
    });
}
"""
    
    try:
        with open(output_path, 'w') as f:
            f.write(script)
        print(f"Generated dyld trace script: {output_path}")
        return True
    except Exception as e:
        print(f"Error writing script: {e}")
        return False


def generate_dyld_interpose_c(output_path: str) -> bool:
    """Generate C code for dyld_interpose (for injection via DYLD_INSERT_LIBRARIES)."""
    c_code = r'''
/*
 * dyld_interpose tracing library
 * Compile: clang -shared -o libdyld_trace.dylib dyld_interpose.c
 * Use: DYLD_INSERT_LIBRARIES=/path/libdyld_trace.dylib ./target_app
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <pthread.h>

// Original function pointers
static const char* (*orig_dyld_image_path_containing_address)(void*) = NULL;
static const char* (*orig_dyld_get_image_name)(unsigned int) = NULL;
static const mach_header* (*orig_dyld_get_image_header)(unsigned int) = NULL;
static void (*orig_dyld_register_func_for_add_image)(void(*)(const mach_header*, intptr_t)) = NULL;
static void (*orig_dyld_register_func_for_remove_image)(void(*)(const mach_header*, intptr_t)) = NULL;

static void* (*orig_dlopen)(const char*, int) = NULL;
static int (*orig_dlclose)(void*) = NULL;
static void* (*orig_dlsym)(void*, const char*) = NULL;
static int (*orig_dladdr)(void*, Dl_info*) = NULL;

// Thread-safe logging
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void log_msg(const char* fmt, ...) {
    pthread_mutex_lock(&log_mutex);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    pthread_mutex_unlock(&log_mutex);
}

// Interposed functions
const char* dyld_image_path_containing_address(void* addr) {
    const char* path = orig_dyld_image_path_containing_address(addr);
    if (path) {
        log_msg("[dyld] Image loaded: %s @ %p", path, addr);
    }
    return path;
}

const char* dyld_get_image_name(unsigned int index) {
    const char* name = orig_dyld_get_image_name(index);
    if (name) {
        log_msg("[dyld] Image %u: %s", index, name);
    }
    return name;
}

const mach_header* dyld_get_image_header(unsigned int index) {
    const mach_header* hdr = orig_dyld_get_image_header(index);
    if (hdr) {
        log_msg("[dyld] Header for image %u: %p", index, hdr);
    }
    return hdr;
}

void dyld_register_func_for_add_image(void(*func)(const mach_header*, intptr_t)) {
    log_msg("[dyld] Registered add_image callback: %p", func);
    return orig_dyld_register_func_for_add_image(func);
}

void dyld_register_func_for_remove_image(void(*func)(const mach_header*, intptr_t)) {
    log_msg("[dyld] Registered remove_image callback: %p", func);
    return orig_dyld_register_func_for_remove_image(func);
}

void* dlopen(const char* path, int mode) {
    log_msg("[dlopen] path=%s mode=%d", path ? path : "NULL", mode);
    void* handle = orig_dlopen(path, mode);
    log_msg("[dlopen] returned %p for %s", handle, path ? path : "NULL");
    return handle;
}

int dlclose(void* handle) {
    log_msg("[dlclose] handle=%p", handle);
    return orig_dlclose(handle);
}

void* dlsym(void* handle, const char* symbol) {
    log_msg("[dlsym] handle=%p symbol=%s", handle, symbol ? symbol : "NULL");
    void* addr = orig_dlsym(handle, symbol);
    log_msg("[dlsym] %s -> %p", symbol ? symbol : "NULL", addr);
    return addr;
}

int dladdr(void* addr, Dl_info* info) {
    int ret = orig_dladdr(addr, info);
    if (ret && info) {
        log_msg("[dladdr] %p -> dli_fname=%s dli_fbase=%p dli_sname=%s dli_saddr=%p",
                addr,
                info->dli_fname ? info->dli_fname : "NULL",
                info->dli_fbase,
                info->dli_sname ? info->dli_sname : "NULL",
                info->dli_saddr);
    }
    return ret;
}

// Constructor - resolve original functions
__attribute__((constructor))
static void init() {
    orig_dyld_image_path_containing_address = dlsym(RTLD_NEXT, "dyld_image_path_containing_address");
    orig_dyld_get_image_name = dlsym(RTLD_NEXT, "dyld_get_image_name");
    orig_dyld_get_image_header = dlsym(RTLD_NEXT, "dyld_get_image_header");
    orig_dyld_register_func_for_add_image = dlsym(RTLD_NEXT, "dyld_register_func_for_add_image");
    orig_dyld_register_func_for_remove_image = dlsym(RTLD_NEXT, "dyld_register_func_for_remove_image");
    orig_dlopen = dlsym(RTLD_NEXT, "dlopen");
    orig_dlclose = dlsym(RTLD_NEXT, "dlclose");
    orig_dlsym = dlsym(RTLD_NEXT, "dlsym");
    orig_dladdr = dlsym(RTLD_NEXT, "dladdr");
    
    log_msg("[dyld_trace] Library loaded, interposition active");
    
    // Enumerate existing images
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char* name = _dyld_get_image_name(i);
        const mach_header* hdr = _dyld_get_image_header(i);
        uint64_t slide = _dyld_get_image_vmaddr_slide(i);
        if (name) {
            log_msg("[enum] Image %u: %s header=%p slide=0x%llx", i, name, hdr, slide);
        }
    }
}

// Destructor
__attribute__((destructor))
static void fini() {
    log_msg("[dyld_trace] Library unloaded");
}
'''
    
    try:
        with open(output_path, 'w') as f:
            f.write(c_code)
        print(f"Generated dyld_interpose C code: {output_path}")
        return True
    except Exception as e:
        print(f"Error writing C code: {e}")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description='dyld_interpose tracing generators')
    parser.add_argument('--frida-script', help='Generate Frida JS script', metavar='OUTPUT.js')
    parser.add_argument('--c-code', help='Generate C interpose library', metavar='OUTPUT.c')
    parser.add_argument('--trace-symbols', nargs='+', help='Symbols to trace')
    parser.add_argument('--trace-dlopen', action='store_true', help='Trace dlopen with stack')
    
    args = parser.parse_args()
    
    options = {}
    if args.trace_symbols:
        options['trace_symbols'] = args.trace_symbols
    if args.trace_dlopen:
        options['trace_dlopen'] = True
    
    if args.frida_script:
        generate_dyld_trace_script(args.frida_script, options)
    
    if args.c_code:
        generate_dyld_interpose_c(args.c_code)
    
    if not args.frida_script and not args.c_code:
        # Default: generate both
        generate_dyld_trace_script('dyld_trace.js', options)
        generate_dyld_interpose_c('dyld_interpose.c')


if __name__ == '__main__':
    main()