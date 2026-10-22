/* tsan_dlopen.c — harness para el test TSan del scan strict del proxy.
 *
 * N hilos hacen dlopen() concurrente de la misma libreria. El proxy
 * (LD_PRELOAD) interpone dlopen y, con NEONATOX_STRICT_SYSROOT=1, escanea
 * el link map tras cada dlopen: ese scan mutaba estado global
 * (found_bad/bad_path/verdict_cache) -> data race con dlopen concurrente.
 *
 * Uso: tsan_dlopen [nthreads] [niters] [lib]
 *   por defecto: 8 hilos x 500 dlopen("libm.so.6").
 * Salida: 0 si todos los dlopen ok (1 si algum fallo, 2 si error de uso).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static int nthreads = 8;
static int niters = 500;
static const char *libname = "libm.so.6";

static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < niters; i++) {
        void *h = dlopen(libname, RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            fprintf(stderr, "dlopen(%s) fallo: %s\n", libname, dlerror());
            return (void *)1;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1) nthreads = atoi(argv[1]);
    if (argc > 2) niters = atoi(argv[2]);
    if (argc > 3) libname = argv[3];
    if (nthreads < 1 || niters < 1) {
        fprintf(stderr, "uso: %s [nthreads] [niters] [lib]\n", argv[0]);
        return 2;
    }
    pthread_t *t = calloc((size_t)nthreads, sizeof(pthread_t));
    if (!t) return 2;
    for (int i = 0; i < nthreads; i++)
        if (pthread_create(&t[i], NULL, worker, NULL) != 0) {
            perror("pthread_create");
            return 2;
        }
    int rc = 0;
    for (int i = 0; i < nthreads; i++) {
        void *r = NULL;
        pthread_join(t[i], &r);
        if (r) rc = 1;
    }
    free(t);
    fprintf(stderr, "harness: %d hilos x %d dlopen(%s) -> rc=%d\n",
            nthreads, niters, libname, rc);
    return rc;
}
