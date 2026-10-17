/* Native Rust libraries are loaded inside the broker, never spawned as CLIs.
 * Only deployment configuration selects a library path. The Lean entry is
 * private and its callers consume checked plans/reservations. */
#include <lean/lean.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
typedef char *(*paired_call)(const char *);
typedef void (*paired_free)(char *);
typedef struct { void *handle; paired_call call; paired_free release; } adapter;
static adapter signal_adapter, whatsapp_adapter;
static pthread_mutex_t loading = PTHREAD_MUTEX_INITIALIZER;
LEAN_EXPORT lean_obj_res liaison_paired_invoke(b_lean_obj_arg provider, b_lean_obj_arg request, lean_obj_arg world) {
    (void)world;
    const char *name = lean_string_cstr(provider);
    adapter *target = NULL;
    const char *env = NULL;
    if (!strcmp(name, "signal")) { target = &signal_adapter; env = "LIAISON_SIGNAL_LIBRARY"; }
    if (!strcmp(name, "whatsapp")) { target = &whatsapp_adapter; env = "LIAISON_WHATSAPP_LIBRARY"; }
    if (!target) goto failure;
    pthread_mutex_lock(&loading);
    if (!target->handle) {
        const char *path = getenv(env);
        if (path && path[0] == '/') {
            void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
            if (handle) {
                paired_call call = (paired_call)dlsym(handle, "liaison_paired_call");
                paired_free release = (paired_free)dlsym(handle, "liaison_paired_free");
                if (call && release) { target->handle = handle; target->call = call; target->release = release; }
                else dlclose(handle);
            }
        }
    }
    pthread_mutex_unlock(&loading);
    if (!target->call) goto failure;
    if (lean_string_cstr(request)[0] == '\0') {
        const char *root = getenv("LIAISON_PAIRED_DIR");
        struct stat info;
        if (!root || root[0] != '/' || lstat(root, &info) || !S_ISDIR(info.st_mode)) goto failure;
        return lean_io_result_mk_ok(lean_mk_string("available"));
    }
    char *answer = target->call(lean_string_cstr(request));
    if (!answer) goto failure;
    lean_object *value = lean_mk_string(answer);
    target->release(answer);
    return lean_io_result_mk_ok(value);
failure:
    return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("native paired adapter unavailable")));
}
