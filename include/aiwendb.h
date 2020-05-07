#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAXMINDDB_H
#define MAXMINDDB_H

/* Request POSIX.1-2008. However, we want to remain compatible with
 * POSIX.1-2001 (since we have been historically and see no reason to drop
 * compatibility). By requesting POSIX.1-2008, we can conditionally use
 * features provided by that standard if the implementation provides it. We can
 * check for what the implementation provides by checking the _POSIX_VERSION
 * macro after including unistd.h. If a feature is in POSIX.1-2008 but not
 * POSIX.1-2001, check that macro before using the feature (or check for the
 * feature directly if possible). */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "aiwendb_config.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define PACKAGE_VERSION "1.4.2"

typedef ADDRESS_FAMILY sa_family_t;

#if defined(_MSC_VER)
/* MSVC doesn't define signed size_t, copy it from configure */
#define ssize_t SSIZE_T

/* MSVC doesn't support restricted pointers */
#define restrict
#endif
#else
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define AWDB_DATA_TYPE_EXTENDED (0)
#define AWDB_DATA_TYPE_POINTER (1)
#define AWDB_DATA_TYPE_UTF8_STRING (2)
#define AWDB_DATA_TYPE_DOUBLE (3)
#define AWDB_DATA_TYPE_BYTES (4)
#define AWDB_DATA_TYPE_UINT16 (5)
#define AWDB_DATA_TYPE_UINT32 (6)
#define AWDB_DATA_TYPE_MAP (7)
#define AWDB_DATA_TYPE_INT32 (8)
#define AWDB_DATA_TYPE_UINT64 (9)
#define AWDB_DATA_TYPE_UINT128 (10)
#define AWDB_DATA_TYPE_ARRAY (11)
#define AWDB_DATA_TYPE_CONTAINER (12)
#define AWDB_DATA_TYPE_END_MARKER (13)
#define AWDB_DATA_TYPE_BOOLEAN (14)
#define AWDB_DATA_TYPE_FLOAT (15)

#define AWDB_RECORD_TYPE_SEARCH_NODE (0)
#define AWDB_RECORD_TYPE_EMPTY (1)
#define AWDB_RECORD_TYPE_DATA (2)
#define AWDB_RECORD_TYPE_INVALID (3)

/* flags for open */
#define AWDB_MODE_MMAP (1)
#define AWDB_MODE_MASK (7)

/* error codes */
#define AWDB_SUCCESS (0)
#define AWDB_FILE_OPEN_ERROR (1)
#define AWDB_CORRUPT_SEARCH_TREE_ERROR (2)
#define AWDB_INVALID_METADATA_ERROR (3)
#define AWDB_IO_ERROR (4)
#define AWDB_OUT_OF_MEMORY_ERROR (5)
#define AWDB_UNKNOWN_DATABASE_FORMAT_ERROR (6)
#define AWDB_INVALID_DATA_ERROR (7)
#define AWDB_INVALID_LOOKUP_PATH_ERROR (8)
#define AWDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR (9)
#define AWDB_INVALID_NODE_NUMBER_ERROR (10)
#define AWDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR (11)

#if !(AWDB_UINT128_IS_BYTE_ARRAY)
#if AWDB_UINT128_USING_MODE
typedef unsigned int awdb_uint128_t __attribute__ ((__mode__(TI)));
#else
typedef unsigned __int128 awdb_uint128_t;
#endif
#endif

/* This is a pointer into the data section for a given IP address lookup */
typedef struct AWDB_entry_s {
    const struct AWDB_s *awdb;
    uint32_t offset;
} AWDB_entry_s;

typedef struct AWDB_lookup_result_s {
    bool found_entry;
    AWDB_entry_s entry;
    uint16_t netmask;
} AWDB_lookup_result_s;

typedef struct AWDB_entry_data_s {
    bool has_data;
    union {
        uint32_t pointer;
        const char *utf8_string;
        double double_value;
        const uint8_t *bytes;
        uint16_t uint16;
        uint32_t uint32;
        int32_t int32;
        uint64_t uint64;
#if AWDB_UINT128_IS_BYTE_ARRAY
        uint8_t uint128[16];
#else
        awdb_uint128_t uint128;
#endif
        bool boolean;
        float float_value;
    };
    /* This is a 0 if a given entry cannot be found. This can only happen
     * when a call to AWDB_(v)get_value() asks for hash keys or array
     * indices that don't exist. */
    uint32_t offset;
    /* This is the next entry in the data section, but it's really only
     * relevant for entries that part of a larger map or array
     * struct. There's no good reason for an end user to look at this
     * directly. */
    uint32_t offset_to_next;
    /* This is only valid for strings, utf8_strings or binary data */
    uint32_t data_size;
    /* This is an AWDB_DATA_TYPE_* constant */
    uint32_t type;
} AWDB_entry_data_s;

/* This is the return type when someone asks for all the entry data in a map or array */
typedef struct AWDB_entry_data_list_s {
    AWDB_entry_data_s entry_data;
    struct AWDB_entry_data_list_s *next;
    void *pool;
} AWDB_entry_data_list_s;

typedef struct AWDB_description_s {
    const char *language;
    const char *description;
} AWDB_description_s;

/* WARNING: do not add new fields to this struct without bumping the SONAME.
 * The struct is allocated by the users of this library and increasing the
 * size will cause existing users to allocate too little space when the shared
 * library is upgraded */
typedef struct AWDB_metadata_s {
    uint32_t node_count;
    uint16_t record_size;
    uint16_t ip_version;
    const char *database_type;
    struct {
        size_t count;
        const char **names;
    } languages;
    uint16_t binary_format_major_version;
    uint16_t binary_format_minor_version;
    uint64_t build_epoch;
    struct {
        size_t count;
        AWDB_description_s **descriptions;
    } description;
    /* See above warning before adding fields */
} AWDB_metadata_s;

/* WARNING: do not add new fields to this struct without bumping the SONAME.
 * The struct is allocated by the users of this library and increasing the
 * size will cause existing users to allocate too little space when the shared
 * library is upgraded */
typedef struct AWDB_ipv4_start_node_s {
    uint16_t netmask;
    uint32_t node_value;
    /* See above warning before adding fields */
} AWDB_ipv4_start_node_s;

/* WARNING: do not add new fields to this struct without bumping the SONAME.
 * The struct is allocated by the users of this library and increasing the
 * size will cause existing users to allocate too little space when the shared
 * library is upgraded */
typedef struct AWDB_s {
    uint32_t flags;
    const char *filename;
    ssize_t file_size;
    const uint8_t *file_content;
    const uint8_t *data_section;
    uint32_t data_section_size;
    const uint8_t *metadata_section;
    uint32_t metadata_section_size;
    uint16_t full_record_byte_size;
    uint16_t depth;
    AWDB_ipv4_start_node_s ipv4_start_node;
    AWDB_metadata_s metadata;
    /* See above warning before adding fields */
} AWDB_s;

typedef struct AWDB_search_node_s {
    uint64_t left_record;
    uint64_t right_record;
    uint8_t left_record_type;
    uint8_t right_record_type;
    AWDB_entry_s left_record_entry;
    AWDB_entry_s right_record_entry;
} AWDB_search_node_s;

extern int AWDB_open(const char *const filename, uint32_t flags,
                     AWDB_s *const awdb);
extern AWDB_lookup_result_s AWDB_lookup_string(const AWDB_s *const awdb,
                                               const char *const ipstr,
                                               int *const gai_error,
                                               int *const awdb_error);
extern AWDB_lookup_result_s AWDB_lookup_sockaddr(
    const AWDB_s *const awdb,
    const struct sockaddr *const sockaddr,
    int *const awdb_error);
extern int AWDB_read_node(const AWDB_s *const awdb,
                          uint32_t node_number,
                          AWDB_search_node_s *const node);
extern int AWDB_get_value(AWDB_entry_s *const start,
                          AWDB_entry_data_s *const entry_data,
                          ...);
extern int AWDB_vget_value(AWDB_entry_s *const start,
                           AWDB_entry_data_s *const entry_data,
                           va_list va_path);
extern int AWDB_aget_value(AWDB_entry_s *const start,
                           AWDB_entry_data_s *const entry_data,
                           const char *const *const path);
extern int AWDB_get_metadata_as_entry_data_list(
    const AWDB_s *const awdb, AWDB_entry_data_list_s **const entry_data_list);
extern int AWDB_get_entry_data_list(
    AWDB_entry_s *start, AWDB_entry_data_list_s **const entry_data_list);
extern void AWDB_free_entry_data_list(
    AWDB_entry_data_list_s *const entry_data_list);
extern void AWDB_close(AWDB_s *const awdb);
extern const char *AWDB_lib_version(void);
extern int AWDB_dump_entry_data_list(FILE *const stream,
                                     AWDB_entry_data_list_s *const entry_data_list,
                                     int indent);
extern const char *AWDB_strerror(int error_code);

#endif                          /* MAXMINDDB_H */

#ifdef __cplusplus
}
#endif
