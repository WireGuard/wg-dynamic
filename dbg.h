/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2014-2019 WireGuard LLC. All Rights Reserved.
 */

#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


#ifndef _FILENAME
#define _FILENAME __FILE__
#endif

#ifndef NDEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

extern int DBG_LVL;

#define STRINGIFY(x) #x
#define PREFIX(...) PREFIX_HELPER(_FILENAME, __LINE__, __VA_ARGS__)
#define SUFFIX(S, M, ...) M S, __VA_ARGS__

#define log_err(...) fprintf(stderr, PREFIX(__VA_ARGS__))
#define log_warn(...) do { if (DBG_LVL > 1) log_err(__VA_ARGS__); } while (0)
#define log_info(...) do { if (DBG_LVL > 2) log_err(__VA_ARGS__); } while (0)
#define die(...)                                                               \
	do {                                                                   \
		log_err(__VA_ARGS__);                                          \
		exit(EXIT_FAILURE);                                            \
	} while (0)
#define fatal(...) die(SUFFIX(": %s\n", __VA_ARGS__, strerror(errno)))

#ifdef NDEBUG
#define PREFIX_HELPER(f,l,...) __VA_ARGS__
#else
#define PREFIX_HELPER(f,l,...) "(" f ":" STRINGIFY(l) "): " __VA_ARGS__
#endif

#define debug(...) do { if (DEBUG) log_err(__VA_ARGS__); } while (0)
#define BUG() do { __BUG(_FILENAME, __LINE__); abort(); } while (0)
#define __BUG(f,l) fprintf(stderr, "BUG: " f ":" STRINGIFY(l) "\n")
#define BUG_ON(cond) do { if (cond) BUG(); } while (0)

#define assert_str_equal(a,b) ({ \
	if (strcmp(a, b)) { \
		log_err("Assertion error: '%s' == '%s'\n", a, b); \
		abort(); \
	} \
})

#define assert_int_equal(a,b) ({ \
	if (a != b) { \
		log_err("Assertion error: '%d' == '%d'\n", a, b); \
		abort(); \
	} \
})

/* A neat macro that silences unused parameter warnings compiler independant */
#define UNUSED(x) (void)(x)

#endif
