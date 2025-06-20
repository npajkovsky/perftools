/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif	/* _WIN32 */
#include <openssl/ssl.h>
#include "perflib/perflib.h"

#define NUM_CALLS_PER_TEST        10000

int err = 0;

static SSL_CTX *sctx = NULL, *cctx = NULL;
static int share_ctx = 1;
static int per_thread_ossl_lib_ctx = 0;
static char *cert = NULL;
static char *privkey = NULL;

OSSL_TIME *times;

static int threadcount;
size_t num_calls;

static void do_handshake(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME start, end;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;

    if (share_ctx == 1) {
        lsctx = sctx;
        lcctx = cctx;
    }

    start = ossl_time_now();

    for (i = 0; i < num_calls / threadcount; i++) {
        if (share_ctx == 0) {
            if (!perflib_create_ssl_ctx_pair(TLS_server_method(),
                                             TLS_client_method(),
                                             0, 0, &lsctx, &lcctx, cert,
                                             privkey)) {
                printf("Failed to create SSL_CTX pair\n");
                break;
            }
        }

        ret = perflib_create_ssl_objects(lsctx, lcctx, &serverssl, &clientssl,
                                         NULL, NULL);
        ret &= perflib_create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE);
        perflib_shutdown_ssl_connection(serverssl, clientssl);
        serverssl = clientssl = NULL;
        if (share_ctx == 0) {
            SSL_CTX_free(lsctx);
            SSL_CTX_free(lcctx);
            lsctx = lcctx = NULL;
        }
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);

    if (!ret)
        err = 1;
}

static void do_handshake_ossl_lib_ctx_per_thread(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1;
    size_t i;
    OSSL_TIME start, end;
    OSSL_LIB_CTX *libctx = NULL;
    SSL_CTX *lsctx = NULL;
    SSL_CTX *lcctx = NULL;

    start = ossl_time_now();

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "%s:%d: Failed to create ossl lib context\n", __FILE__, __LINE__);
        err = 1;
        return;
    }

    for (i = 0; i < num_calls / threadcount; i++) {
        if (!perflib_create_ossl_lib_ctx_pair(libctx,
                                              TLS_server_method(),
                                              TLS_client_method(),
                                              0, 0, &lsctx, &lcctx, cert,
                                              privkey)) {
            fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
            err = 1;
            return;
        }


        ret = perflib_create_ssl_objects(lsctx, lcctx, &serverssl, &clientssl,
                                         NULL, NULL);
        ret &= perflib_create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE);
        perflib_shutdown_ssl_connection(serverssl, clientssl);
        serverssl = clientssl = NULL;
        SSL_CTX_free(lsctx);
        SSL_CTX_free(lcctx);
        lsctx = lcctx = NULL;
    }

    end = ossl_time_now();
    times[num] = ossl_time_subtract(end, start);

    if (!ret)
        err = 1;

    OSSL_LIB_CTX_free(libctx);
}

int main(int argc, char * const argv[])
{
    double persec;
    OSSL_TIME duration, ttime;
    double avcalltime;
    int ret = EXIT_FAILURE;
    int i;
    int terse = 0;
    int opt;

    while ((opt = getopt(argc, argv, "tsp")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 's':
            share_ctx = 0;
            break;
        case 'p':
            per_thread_ossl_lib_ctx = 1;
            break;
        default:
            printf(
                "Usage: %s [-t] [-s] certsdir threadcount\n", basename(argv[0]));
            printf("-t - terse output\n");
            printf("-s - disable context sharing\n");
            printf("-p - use ossl_lib_ctx per thread\n");
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        printf("certsdir is missing\n");
        goto err;
    }
    cert = perflib_mk_file_path(argv[optind], "servercert.pem");
    privkey = perflib_mk_file_path(argv[optind], "serverkey.pem");
    if (cert == NULL || privkey == NULL) {
        printf("Failed to allocate cert/privkey\n");
        goto err;
    }
    optind++;

    if (argv[optind] == NULL) {
        printf("threadcount argument missing\n");
        goto err;
    }
    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        printf("threadcount must be > 0\n");
        goto err;
    }
    times = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (times == NULL) {
        printf("Failed to create times array\n");
        goto err;
    }

    num_calls = NUM_CALLS_PER_TEST;
    if (NUM_CALLS_PER_TEST % threadcount > 0) /* round up */
        num_calls += threadcount - NUM_CALLS_PER_TEST % threadcount;

    if (per_thread_ossl_lib_ctx) {
        int ret;

        ret = perflib_run_multi_thread_test(do_handshake_ossl_lib_ctx_per_thread,
                                            threadcount, &duration);
        if (!ret) {
            printf("Failed to run the test\n");
            goto err;
        }
    }

    if (!per_thread_ossl_lib_ctx) {
        if (share_ctx == 1) {
            if (!perflib_create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                                             0, 0, &sctx, &cctx, cert, privkey)) {
                printf("Failed to create SSL_CTX pair\n");
                goto err;
            }
        }

        if (!perflib_run_multi_thread_test(do_handshake, threadcount, &duration)) {
            printf("Failed to run the test\n");
            goto err;
        }
    }

    if (err) {
        printf("Error during test\n");
        goto err;
    }

    ttime = times[0];
    for (i = 1; i < threadcount; i++)
        ttime = ossl_time_add(ttime, times[i]);

    avcalltime = ((double)ossl_time2ticks(ttime) / num_calls) / (double)OSSL_TIME_US;
    persec = ((num_calls * OSSL_TIME_SECOND)
             / (double)ossl_time2ticks(duration));

    if (terse) {
        printf("%lf\n", avcalltime);
    } else {
        printf("Average time per handshake: %lfus\n", avcalltime);
        printf("Handshakes per second: %lf\n", persec);
    }

    ret = EXIT_SUCCESS;
 err:
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(times);
    if (share_ctx == 1) {
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
    }
    return ret;
}
