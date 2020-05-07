#if HAVE_CONFIG_H
#include <config.h>
#endif
#include "data-pool.h"
#include "aiwendb.h"
#include "aiwendb-compat-util.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <ws2ipdef.h>
#else
#include <arpa/inet.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#define AWDB_DATA_SECTION_SEPARATOR (16)
#define MAXIMUM_DATA_STRUCTURE_DEPTH (512)

#ifdef AWDB_DEBUG
#define LOCAL
#define DEBUG_MSG(msg) fprintf(stderr, msg "\n")
#define DEBUG_MSGF(fmt, ...) fprintf(stderr, fmt "\n", __VA_ARGS__)
#define DEBUG_BINARY(fmt, byte)                                 \
    do {                                                        \
        char *binary = byte_to_binary(byte);                    \
        if (NULL == binary) {                                   \
            fprintf(stderr, "Malloc failed in DEBUG_BINARY\n"); \
            abort();                                            \
        }                                                       \
        fprintf(stderr, fmt "\n", binary);                      \
        free(binary);                                           \
    } while (0)
#define DEBUG_NL fprintf(stderr, "\n")
#else
#define LOCAL static
#define DEBUG_MSG(...)
#define DEBUG_MSGF(...)
#define DEBUG_BINARY(...)
#define DEBUG_NL
#endif

#ifdef AWDB_DEBUG
char *byte_to_binary(uint8_t byte)
{
    char *bits = malloc(sizeof(char) * 9);
    if (NULL == bits) {
        return bits;
    }

    for (uint8_t i = 0; i < 8; i++) {
        bits[i] = byte & (128 >> i) ? '1' : '0';
    }
    bits[8] = '\0';

    return bits;
}

char *type_num_to_name(uint8_t num)
{
    switch (num) {
    case 0:
        return "extended";
    case 1:
        return "pointer";
    case 2:
        return "utf8_string";
    case 3:
        return "double";
    case 4:
        return "bytes";
    case 5:
        return "uint16";
    case 6:
        return "uint32";
    case 7:
        return "map";
    case 8:
        return "int32";
    case 9:
        return "uint64";
    case 10:
        return "uint128";
    case 11:
        return "array";
    case 12:
        return "container";
    case 13:
        return "end_marker";
    case 14:
        return "boolean";
    case 15:
        return "float";
    default:
        return "unknown type";
    }
}
#endif

/* None of the values we check on the lhs are bigger than uint32_t, so on
 * platforms where SIZE_MAX is a 64-bit integer, this would be a no-op, and it
 * makes the compiler complain if we do the check anyway. */
#if SIZE_MAX == UINT32_MAX
#define MAYBE_CHECK_SIZE_OVERFLOW(lhs, rhs, error) \
    if ((lhs) > (rhs)) {                           \
        return error;                              \
    }
#else
#define MAYBE_CHECK_SIZE_OVERFLOW(...)
#endif

typedef struct record_info_s {
    uint16_t record_length;
    uint32_t (*left_record_getter)(const uint8_t *);
    uint32_t (*right_record_getter)(const uint8_t *);
    uint8_t right_record_offset;
} record_info_s;

#define METADATA_MARKER "\xab\xcd\xefipplus360.com"
/* This is 128kb */
#define METADATA_BLOCK_MAX_SIZE 131072

// 64 leads us to allocating 4 KiB on a 64bit system.
#define AWDB_POOL_INIT_SIZE 64

LOCAL int map_file(AWDB_s *const awdb);
LOCAL const uint8_t *find_metadata(const uint8_t *file_content,
                                   ssize_t file_size, uint32_t *metadata_size);
LOCAL int read_metadata(AWDB_s *awdb);
LOCAL AWDB_s make_fake_metadata_db(const AWDB_s *const awdb);
LOCAL int value_for_key_as_uint16(AWDB_entry_s *start, char *key,
                                  uint16_t *value);
LOCAL int value_for_key_as_uint32(AWDB_entry_s *start, char *key,
                                  uint32_t *value);
LOCAL int value_for_key_as_uint64(AWDB_entry_s *start, char *key,
                                  uint64_t *value);
LOCAL int value_for_key_as_string(AWDB_entry_s *start, char *key,
                                  char const **value);
LOCAL int populate_languages_metadata(AWDB_s *awdb, AWDB_s *metadata_db,
                                      AWDB_entry_s *metadata_start);
LOCAL int populate_description_metadata(AWDB_s *awdb, AWDB_s *metadata_db,
                                        AWDB_entry_s *metadata_start);
LOCAL int resolve_any_address(const char *ipstr, struct addrinfo **addresses);
LOCAL int find_address_in_search_tree(const AWDB_s *const awdb,
                                      uint8_t *address,
                                      sa_family_t address_family,
                                      AWDB_lookup_result_s *result);
LOCAL record_info_s record_info_for_database(const AWDB_s *const awdb);
LOCAL int find_ipv4_start_node(AWDB_s *const awdb);
LOCAL uint8_t record_type(const AWDB_s *const awdb, uint64_t record);
LOCAL uint32_t get_left_28_bit_record(const uint8_t *record);
LOCAL uint32_t get_right_28_bit_record(const uint8_t *record);
LOCAL uint32_t data_section_offset_for_record(const AWDB_s *const awdb,
                                              uint64_t record);
LOCAL int path_length(va_list va_path);
LOCAL int lookup_path_in_array(const char *path_elem, const AWDB_s *const awdb,
                               AWDB_entry_data_s *entry_data);
LOCAL int lookup_path_in_map(const char *path_elem, const AWDB_s *const awdb,
                             AWDB_entry_data_s *entry_data);
LOCAL int skip_map_or_array(const AWDB_s *const awdb,
                            AWDB_entry_data_s *entry_data);
LOCAL int decode_one_follow(const AWDB_s *const awdb, uint32_t offset,
                            AWDB_entry_data_s *entry_data);
LOCAL int decode_one(const AWDB_s *const awdb, uint32_t offset,
                     AWDB_entry_data_s *entry_data);
LOCAL int get_ext_type(int raw_ext_type);
LOCAL uint32_t get_ptr_from(uint8_t ctrl, uint8_t const *const ptr,
                            int ptr_size);
LOCAL int get_entry_data_list(const AWDB_s *const awdb,
                              uint32_t offset,
                              AWDB_entry_data_list_s *const entry_data_list,
                              AWDB_data_pool_s *const pool,
                              int depth);
LOCAL float get_ieee754_float(const uint8_t *restrict p);
LOCAL double get_ieee754_double(const uint8_t *restrict p);
LOCAL uint32_t get_uint32(const uint8_t *p);
LOCAL uint32_t get_uint24(const uint8_t *p);
LOCAL uint32_t get_uint16(const uint8_t *p);
LOCAL uint64_t get_uintX(const uint8_t *p, int length);
LOCAL int32_t get_sintX(const uint8_t *p, int length);
LOCAL void free_awdb_struct(AWDB_s *const awdb);
LOCAL void free_languages_metadata(AWDB_s *awdb);
LOCAL void free_descriptions_metadata(AWDB_s *awdb);
LOCAL AWDB_entry_data_list_s *dump_entry_data_list(
    FILE *stream, AWDB_entry_data_list_s *entry_data_list, int indent,
    int *status);
LOCAL void print_indentation(FILE *stream, int i);
LOCAL char *bytes_to_hex(uint8_t *bytes, uint32_t size);

#define CHECKED_DECODE_ONE(awdb, offset, entry_data)                        \
    do {                                                                    \
        int status = decode_one(awdb, offset, entry_data);                  \
        if (AWDB_SUCCESS != status) {                                       \
            DEBUG_MSGF("CHECKED_DECODE_ONE failed."                         \
                       " status = %d (%s)", status, AWDB_strerror(status)); \
            return status;                                                  \
        }                                                                   \
    } while (0)

#define CHECKED_DECODE_ONE_FOLLOW(awdb, offset, entry_data)                 \
    do {                                                                    \
        int status = decode_one_follow(awdb, offset, entry_data);           \
        if (AWDB_SUCCESS != status) {                                       \
            DEBUG_MSGF("CHECKED_DECODE_ONE_FOLLOW failed."                  \
                       " status = %d (%s)", status, AWDB_strerror(status)); \
            return status;                                                  \
        }                                                                   \
    } while (0)

#define FREE_AND_SET_NULL(p) { free((void *)(p)); (p) = NULL; }

int AWDB_open(const char *const filename, uint32_t flags, AWDB_s *const awdb)
{
    int status = AWDB_SUCCESS;

    awdb->file_content = NULL;
    awdb->data_section = NULL;
    awdb->metadata.database_type = NULL;
    awdb->metadata.languages.count = 0;
    awdb->metadata.languages.names = NULL;
    awdb->metadata.description.count = 0;

    awdb->filename = awdb_strdup(filename);
    if (NULL == awdb->filename) {
        status = AWDB_OUT_OF_MEMORY_ERROR;
        goto cleanup;
    }

    if ((flags & AWDB_MODE_MASK) == 0) {
        flags |= AWDB_MODE_MMAP;
    }
    awdb->flags = flags;

    if (AWDB_SUCCESS != (status = map_file(awdb))) {
        goto cleanup;
    }

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    uint32_t metadata_size = 0;
    const uint8_t *metadata = find_metadata(awdb->file_content, awdb->file_size,
                                            &metadata_size);
    if (NULL == metadata) {
        status = AWDB_INVALID_METADATA_ERROR;
        goto cleanup;
    }

    awdb->metadata_section = metadata;
    awdb->metadata_section_size = metadata_size;

    status = read_metadata(awdb);
    if (AWDB_SUCCESS != status) {
        goto cleanup;
    }

    if (awdb->metadata.binary_format_major_version != 2) {
        status = AWDB_UNKNOWN_DATABASE_FORMAT_ERROR;
        goto cleanup;
    }

    uint32_t search_tree_size = awdb->metadata.node_count *
                                awdb->full_record_byte_size;

    awdb->data_section = awdb->file_content + search_tree_size
                         + AWDB_DATA_SECTION_SEPARATOR;
    if (search_tree_size + AWDB_DATA_SECTION_SEPARATOR >
        (uint32_t)awdb->file_size) {
        status = AWDB_INVALID_METADATA_ERROR;
        goto cleanup;
    }
    awdb->data_section_size = (uint32_t)awdb->file_size - search_tree_size -
                              AWDB_DATA_SECTION_SEPARATOR;

    // Although it is likely not possible to construct a database with valid
    // valid metadata, as parsed above, and a data_section_size less than 3,
    // we do this check as later we assume it is at least three when doing
    // bound checks.
    if (awdb->data_section_size < 3) {
        status = AWDB_INVALID_DATA_ERROR;
        goto cleanup;
    }

    awdb->metadata_section = metadata;
    awdb->ipv4_start_node.node_value = 0;
    awdb->ipv4_start_node.netmask = 0;

    // We do this immediately as otherwise there is a race to set
    // ipv4_start_node.node_value and ipv4_start_node.netmask.
    if (awdb->metadata.ip_version == 6) {
        status = find_ipv4_start_node(awdb);
        if (status != AWDB_SUCCESS) {
            goto cleanup;
        }
    }

 cleanup:
    if (AWDB_SUCCESS != status) {
        int saved_errno = errno;
        free_awdb_struct(awdb);
        errno = saved_errno;
    }
    return status;
}

#ifdef _WIN32

LOCAL LPWSTR utf8_to_utf16(const char *utf8_str)
{
    int wide_chars = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);
    wchar_t *utf16_str = (wchar_t *)malloc(wide_chars * sizeof(wchar_t));

    if (MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, utf16_str,
                            wide_chars) < 1) {
        free(utf16_str);
        return NULL;
    }

    return utf16_str;
}

LOCAL int map_file(AWDB_s *const awdb)
{
    DWORD size;
    int status = AWDB_SUCCESS;
    HANDLE mmh = NULL;
    HANDLE fd = INVALID_HANDLE_VALUE;
    LPWSTR utf16_filename = utf8_to_utf16(awdb->filename);
    if (!utf16_filename) {
        status = AWDB_FILE_OPEN_ERROR;
        goto cleanup;
    }
    fd = CreateFile(utf16_filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        status = AWDB_FILE_OPEN_ERROR;
        goto cleanup;
    }
    size = GetFileSize(fd, NULL);
    if (size == INVALID_FILE_SIZE) {
        status = AWDB_FILE_OPEN_ERROR;
        goto cleanup;
    }
    mmh = CreateFileMapping(fd, NULL, PAGE_READONLY, 0, size, NULL);
    /* Microsoft documentation for CreateFileMapping indicates this returns
        NULL not INVALID_HANDLE_VALUE on error */
    if (NULL == mmh) {
        status = AWDB_IO_ERROR;
        goto cleanup;
    }
    uint8_t *file_content =
        (uint8_t *)MapViewOfFile(mmh, FILE_MAP_READ, 0, 0, 0);
    if (file_content == NULL) {
        status = AWDB_IO_ERROR;
        goto cleanup;
    }

    awdb->file_size = size;
    awdb->file_content = file_content;

 cleanup:;
    int saved_errno = errno;
    if (INVALID_HANDLE_VALUE != fd) {
        CloseHandle(fd);
    }
    if (NULL != mmh) {
        CloseHandle(mmh);
    }
    errno = saved_errno;
    free(utf16_filename);

    return status;
}

#else // _WIN32

LOCAL int map_file(AWDB_s *const awdb)
{
    ssize_t size;
    int status = AWDB_SUCCESS;

    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(awdb->filename, flags);
    struct stat s;
    if (fd < 0 || fstat(fd, &s)) {
        status = AWDB_FILE_OPEN_ERROR;
        goto cleanup;
    }

    size = s.st_size;
    if (size < 0 || size != s.st_size) {
        status = AWDB_OUT_OF_MEMORY_ERROR;
        goto cleanup;
    }

    uint8_t *file_content =
        (uint8_t *)mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (MAP_FAILED == file_content) {
        if (ENOMEM == errno) {
            status = AWDB_OUT_OF_MEMORY_ERROR;
        } else {
            status = AWDB_IO_ERROR;
        }
        goto cleanup;
    }

    awdb->file_size = size;
    awdb->file_content = file_content;

 cleanup:;
    int saved_errno = errno;
    if (fd >= 0) {
        close(fd);
    }
    errno = saved_errno;

    return status;
}

#endif // _WIN32

LOCAL const uint8_t *find_metadata(const uint8_t *file_content,
                                   ssize_t file_size, uint32_t *metadata_size)
{
    const ssize_t marker_len = sizeof(METADATA_MARKER) - 1;
    ssize_t max_size = file_size >
                       METADATA_BLOCK_MAX_SIZE ? METADATA_BLOCK_MAX_SIZE :
                       file_size;

    uint8_t *search_area = (uint8_t *)(file_content + (file_size - max_size));
    uint8_t *start = search_area;
    uint8_t *tmp;
    do {
        tmp = awdb_memmem(search_area, max_size,
                          METADATA_MARKER, marker_len);

        if (NULL != tmp) {
            max_size -= tmp - search_area;
            search_area = tmp;

            /* Continue searching just after the marker we just read, in case
             * there are multiple markers in the same file. This would be odd
             * but is certainly not impossible. */
            max_size -= marker_len;
            search_area += marker_len;
        }
    } while (NULL != tmp);

    if (search_area == start) {
        return NULL;
    }

    *metadata_size = (uint32_t)max_size;

    return search_area;
}

LOCAL int read_metadata(AWDB_s *awdb)
{
    /* We need to create a fake AWDB_s struct in order to decode values from
       the metadata. The metadata is basically just like the data section, so we
       want to use the same functions we use for the data section to get metadata
       values. */
    AWDB_s metadata_db = make_fake_metadata_db(awdb);

    AWDB_entry_s metadata_start = {
        .awdb   = &metadata_db,
        .offset = 0
    };

    int status =
        value_for_key_as_uint32(&metadata_start, "node_count",
                                &awdb->metadata.node_count);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (!awdb->metadata.node_count) {
        DEBUG_MSG("could not find node_count value in metadata");
        return AWDB_INVALID_METADATA_ERROR;
    }

    status = value_for_key_as_uint16(&metadata_start, "record_size",
                                     &awdb->metadata.record_size);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (!awdb->metadata.record_size) {
        DEBUG_MSG("could not find record_size value in metadata");
        return AWDB_INVALID_METADATA_ERROR;
    }

    if (awdb->metadata.record_size != 24 && awdb->metadata.record_size != 28
        && awdb->metadata.record_size != 32) {
        DEBUG_MSGF("bad record size in metadata: %i",
                   awdb->metadata.record_size);
        return AWDB_UNKNOWN_DATABASE_FORMAT_ERROR;
    }

    status = value_for_key_as_uint16(&metadata_start, "ip_version",
                                     &awdb->metadata.ip_version);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (!awdb->metadata.ip_version) {
        DEBUG_MSG("could not find ip_version value in metadata");
        return AWDB_INVALID_METADATA_ERROR;
    }
    if (!(awdb->metadata.ip_version == 4 || awdb->metadata.ip_version == 6)) {
        DEBUG_MSGF("ip_version value in metadata is not 4 or 6 - it was %i",
                   awdb->metadata.ip_version);
        return AWDB_INVALID_METADATA_ERROR;
    }

    status = value_for_key_as_string(&metadata_start, "database_type",
                                     &awdb->metadata.database_type);
    if (AWDB_SUCCESS != status) {
        DEBUG_MSG("error finding database_type value in metadata");
        return status;
    }

    status =
        populate_languages_metadata(awdb, &metadata_db, &metadata_start);
    if (AWDB_SUCCESS != status) {
        DEBUG_MSG("could not populate languages from metadata");
        return status;
    }

    status = value_for_key_as_uint16(
        &metadata_start, "binary_format_major_version",
        &awdb->metadata.binary_format_major_version);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (!awdb->metadata.binary_format_major_version) {
        DEBUG_MSG(
            "could not find binary_format_major_version value in metadata");
        return AWDB_INVALID_METADATA_ERROR;
    }

    status = value_for_key_as_uint16(
        &metadata_start, "binary_format_minor_version",
        &awdb->metadata.binary_format_minor_version);
    if (AWDB_SUCCESS != status) {
        return status;
    }

    status = value_for_key_as_uint64(&metadata_start, "build_epoch",
                                     &awdb->metadata.build_epoch);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (!awdb->metadata.build_epoch) {
        DEBUG_MSG("could not find build_epoch value in metadata");
        return AWDB_INVALID_METADATA_ERROR;
    }

    status = populate_description_metadata(awdb, &metadata_db, &metadata_start);
    if (AWDB_SUCCESS != status) {
        DEBUG_MSG("could not populate description from metadata");
        return status;
    }

    awdb->full_record_byte_size = awdb->metadata.record_size * 2 / 8U;

    awdb->depth = awdb->metadata.ip_version == 4 ? 32 : 128;

    return AWDB_SUCCESS;
}

LOCAL AWDB_s make_fake_metadata_db(const AWDB_s *const awdb)
{
    AWDB_s fake_metadata_db = {
        .data_section      = awdb->metadata_section,
        .data_section_size = awdb->metadata_section_size
    };

    return fake_metadata_db;
}

LOCAL int value_for_key_as_uint16(AWDB_entry_s *start, char *key,
                                  uint16_t *value)
{
    AWDB_entry_data_s entry_data;
    const char *path[] = { key, NULL };
    int status = AWDB_aget_value(start, &entry_data, path);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (AWDB_DATA_TYPE_UINT16 != entry_data.type) {
        DEBUG_MSGF("expect uint16 for %s but received %s", key,
                   type_num_to_name(
                       entry_data.type));
        return AWDB_INVALID_METADATA_ERROR;
    }
    *value = entry_data.uint16;
    return AWDB_SUCCESS;
}

LOCAL int value_for_key_as_uint32(AWDB_entry_s *start, char *key,
                                  uint32_t *value)
{
    AWDB_entry_data_s entry_data;
    const char *path[] = { key, NULL };
    int status = AWDB_aget_value(start, &entry_data, path);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (AWDB_DATA_TYPE_UINT32 != entry_data.type) {
        DEBUG_MSGF("expect uint32 for %s but received %s", key,
                   type_num_to_name(
                       entry_data.type));
        return AWDB_INVALID_METADATA_ERROR;
    }
    *value = entry_data.uint32;
    return AWDB_SUCCESS;
}

LOCAL int value_for_key_as_uint64(AWDB_entry_s *start, char *key,
                                  uint64_t *value)
{
    AWDB_entry_data_s entry_data;
    const char *path[] = { key, NULL };
    int status = AWDB_aget_value(start, &entry_data, path);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (AWDB_DATA_TYPE_UINT64 != entry_data.type) {
        DEBUG_MSGF("expect uint64 for %s but received %s", key,
                   type_num_to_name(
                       entry_data.type));
        return AWDB_INVALID_METADATA_ERROR;
    }
    *value = entry_data.uint64;
    return AWDB_SUCCESS;
}

LOCAL int value_for_key_as_string(AWDB_entry_s *start, char *key,
                                  char const **value)
{
    AWDB_entry_data_s entry_data;
    const char *path[] = { key, NULL };
    int status = AWDB_aget_value(start, &entry_data, path);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (AWDB_DATA_TYPE_UTF8_STRING != entry_data.type) {
        DEBUG_MSGF("expect string for %s but received %s", key,
                   type_num_to_name(
                       entry_data.type));
        return AWDB_INVALID_METADATA_ERROR;
    }
    *value = awdb_strndup((char *)entry_data.utf8_string, entry_data.data_size);
    if (NULL == *value) {
        return AWDB_OUT_OF_MEMORY_ERROR;
    }
    return AWDB_SUCCESS;
}

LOCAL int populate_languages_metadata(AWDB_s *awdb, AWDB_s *metadata_db,
                                      AWDB_entry_s *metadata_start)
{
    AWDB_entry_data_s entry_data;

    const char *path[] = { "languages", NULL };
    int status = AWDB_aget_value(metadata_start, &entry_data, path);
    if (AWDB_SUCCESS != status) {
        return status;
    }
    if (AWDB_DATA_TYPE_ARRAY != entry_data.type) {
        return AWDB_INVALID_METADATA_ERROR;
    }

    AWDB_entry_s array_start = {
        .awdb   = metadata_db,
        .offset = entry_data.offset
    };

    AWDB_entry_data_list_s *member;
    status = AWDB_get_entry_data_list(&array_start, &member);
    if (AWDB_SUCCESS != status) {
        return status;
    }

    AWDB_entry_data_list_s *first_member = member;

    uint32_t array_size = member->entry_data.data_size;
    MAYBE_CHECK_SIZE_OVERFLOW(array_size, SIZE_MAX / sizeof(char *),
                              AWDB_INVALID_METADATA_ERROR);

    awdb->metadata.languages.count = 0;
    awdb->metadata.languages.names = malloc(array_size * sizeof(char *));
    if (NULL == awdb->metadata.languages.names) {
        return AWDB_OUT_OF_MEMORY_ERROR;
    }

    for (uint32_t i = 0; i < array_size; i++) {
        member = member->next;
        if (AWDB_DATA_TYPE_UTF8_STRING != member->entry_data.type) {
            return AWDB_INVALID_METADATA_ERROR;
        }

        awdb->metadata.languages.names[i] =
            awdb_strndup((char *)member->entry_data.utf8_string,
                         member->entry_data.data_size);

        if (NULL == awdb->metadata.languages.names[i]) {
            return AWDB_OUT_OF_MEMORY_ERROR;
        }
        // We assign this as we go so that if we fail a malloc and need to
        // free it, the count is right.
        awdb->metadata.languages.count = i + 1;
    }

    AWDB_free_entry_data_list(first_member);

    return AWDB_SUCCESS;
}

LOCAL int populate_description_metadata(AWDB_s *awdb, AWDB_s *metadata_db,
                                        AWDB_entry_s *metadata_start)
{
    AWDB_entry_data_s entry_data;

    const char *path[] = { "description", NULL };
    int status = AWDB_aget_value(metadata_start, &entry_data, path);
    if (AWDB_SUCCESS != status) {
        return status;
    }

    if (AWDB_DATA_TYPE_MAP != entry_data.type) {
        DEBUG_MSGF("Unexpected entry_data type: %d", entry_data.type);
        return AWDB_INVALID_METADATA_ERROR;
    }

    AWDB_entry_s map_start = {
        .awdb   = metadata_db,
        .offset = entry_data.offset
    };

    AWDB_entry_data_list_s *member;
    status = AWDB_get_entry_data_list(&map_start, &member);
    if (AWDB_SUCCESS != status) {
        DEBUG_MSGF(
            "AWDB_get_entry_data_list failed while populating description."
            " status = %d (%s)", status, AWDB_strerror(status));
        return status;
    }

    AWDB_entry_data_list_s *first_member = member;

    uint32_t map_size = member->entry_data.data_size;
    awdb->metadata.description.count = 0;
    if (0 == map_size) {
        awdb->metadata.description.descriptions = NULL;
        goto cleanup;
    }
    MAYBE_CHECK_SIZE_OVERFLOW(map_size, SIZE_MAX / sizeof(AWDB_description_s *),
                              AWDB_INVALID_METADATA_ERROR);

    awdb->metadata.description.descriptions =
        malloc(map_size * sizeof(AWDB_description_s *));
    if (NULL == awdb->metadata.description.descriptions) {
        status = AWDB_OUT_OF_MEMORY_ERROR;
        goto cleanup;
    }

    for (uint32_t i = 0; i < map_size; i++) {
        awdb->metadata.description.descriptions[i] =
            malloc(sizeof(AWDB_description_s));
        if (NULL == awdb->metadata.description.descriptions[i]) {
            status = AWDB_OUT_OF_MEMORY_ERROR;
            goto cleanup;
        }

        awdb->metadata.description.count = i + 1;
        awdb->metadata.description.descriptions[i]->language = NULL;
        awdb->metadata.description.descriptions[i]->description = NULL;

        member = member->next;

        if (AWDB_DATA_TYPE_UTF8_STRING != member->entry_data.type) {
            status = AWDB_INVALID_METADATA_ERROR;
            goto cleanup;
        }

        awdb->metadata.description.descriptions[i]->language =
            awdb_strndup((char *)member->entry_data.utf8_string,
                         member->entry_data.data_size);

        if (NULL == awdb->metadata.description.descriptions[i]->language) {
            status = AWDB_OUT_OF_MEMORY_ERROR;
            goto cleanup;
        }

        member = member->next;

        if (AWDB_DATA_TYPE_UTF8_STRING != member->entry_data.type) {
            status = AWDB_INVALID_METADATA_ERROR;
            goto cleanup;
        }

        awdb->metadata.description.descriptions[i]->description =
            awdb_strndup((char *)member->entry_data.utf8_string,
                         member->entry_data.data_size);

        if (NULL == awdb->metadata.description.descriptions[i]->description) {
            status = AWDB_OUT_OF_MEMORY_ERROR;
            goto cleanup;
        }
    }

 cleanup:
    AWDB_free_entry_data_list(first_member);

    return status;
}

AWDB_lookup_result_s AWDB_lookup_string(const AWDB_s *const awdb,
                                        const char *const ipstr,
                                        int *const gai_error,
                                        int *const awdb_error)
{
    AWDB_lookup_result_s result = {
        .found_entry = false,
        .netmask     = 0,
        .entry       = {
            .awdb    = awdb,
            .offset  = 0
        }
    };

    struct addrinfo *addresses = NULL;
    *gai_error = resolve_any_address(ipstr, &addresses);

    if (!*gai_error) {
        result = AWDB_lookup_sockaddr(awdb, addresses->ai_addr, awdb_error);
    }

    if (NULL != addresses) {
        freeaddrinfo(addresses);
    }

    return result;
}

LOCAL int resolve_any_address(const char *ipstr, struct addrinfo **addresses)
{
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_flags    = AI_NUMERICHOST,
        // We set ai_socktype so that we only get one result back
        .ai_socktype = SOCK_STREAM
    };

    int gai_status = getaddrinfo(ipstr, NULL, &hints, addresses);
    if (gai_status) {
        return gai_status;
    }

    return 0;
}

AWDB_lookup_result_s AWDB_lookup_sockaddr(
    const AWDB_s *const awdb,
    const struct sockaddr *const sockaddr,
    int *const awdb_error)
{
    AWDB_lookup_result_s result = {
        .found_entry = false,
        .netmask     = 0,
        .entry       = {
            .awdb    = awdb,
            .offset  = 0
        }
    };

    uint8_t mapped_address[16], *address;
    if (awdb->metadata.ip_version == 4) {
        if (sockaddr->sa_family == AF_INET6) {
            *awdb_error = AWDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR;
            return result;
        }
        address = (uint8_t *)&((struct sockaddr_in *)sockaddr)->sin_addr.s_addr;
    } else {
        if (sockaddr->sa_family == AF_INET6) {
            address =
                (uint8_t *)&((struct sockaddr_in6 *)sockaddr)->sin6_addr.
                s6_addr;
        } else {
            address = mapped_address;
            memset(address, 0, 12);
            memcpy(address + 12,
                   &((struct sockaddr_in *)sockaddr)->sin_addr.s_addr, 4);
        }
    }

    *awdb_error =
        find_address_in_search_tree(awdb, address, sockaddr->sa_family,
                                    &result);

    return result;
}

LOCAL int find_address_in_search_tree(const AWDB_s *const awdb,
                                      uint8_t *address,
                                      sa_family_t address_family,
                                      AWDB_lookup_result_s *result)
{
    record_info_s record_info = record_info_for_database(awdb);
    if (0 == record_info.right_record_offset) {
        return AWDB_UNKNOWN_DATABASE_FORMAT_ERROR;
    }

    uint32_t value = 0;
    uint16_t current_bit = 0;
    if (awdb->metadata.ip_version == 6 && address_family == AF_INET) {
        value = awdb->ipv4_start_node.node_value;
        current_bit = awdb->ipv4_start_node.netmask;
    }

    uint32_t node_count = awdb->metadata.node_count;
    const uint8_t *search_tree = awdb->file_content;
    const uint8_t *record_pointer;
    for (; current_bit < awdb->depth && value < node_count; current_bit++) {
        uint8_t bit = 1U &
                      (address[current_bit >> 3] >> (7 - (current_bit % 8)));

        record_pointer = &search_tree[value * record_info.record_length];
        if (record_pointer + record_info.record_length > awdb->data_section) {
            return AWDB_CORRUPT_SEARCH_TREE_ERROR;
        }
        if (bit) {
            record_pointer += record_info.right_record_offset;
            value = record_info.right_record_getter(record_pointer);
        } else {
            value = record_info.left_record_getter(record_pointer);
        }
    }

    result->netmask = current_bit;

    if (value >= node_count + awdb->data_section_size) {
        // The pointer points off the end of the database.
        return AWDB_CORRUPT_SEARCH_TREE_ERROR;
    }

    if (value == node_count) {
        // record is empty
        result->found_entry = false;
        return AWDB_SUCCESS;
    }
    result->found_entry = true;
    result->entry.offset = data_section_offset_for_record(awdb, value);

    return AWDB_SUCCESS;
}

LOCAL record_info_s record_info_for_database(const AWDB_s *const awdb)
{
    record_info_s record_info = {
        .record_length       = awdb->full_record_byte_size,
        .right_record_offset = 0
    };

    if (record_info.record_length == 6) {
        record_info.left_record_getter = &get_uint24;
        record_info.right_record_getter = &get_uint24;
        record_info.right_record_offset = 3;
    } else if (record_info.record_length == 7) {
        record_info.left_record_getter = &get_left_28_bit_record;
        record_info.right_record_getter = &get_right_28_bit_record;
        record_info.right_record_offset = 3;
    } else if (record_info.record_length == 8) {
        record_info.left_record_getter = &get_uint32;
        record_info.right_record_getter = &get_uint32;
        record_info.right_record_offset = 4;
    } else {
        assert(false);
    }

    return record_info;
}

LOCAL int find_ipv4_start_node(AWDB_s *const awdb)
{
    /* In a pathological case of a database with a single node search tree,
     * this check will be true even after we've found the IPv4 start node, but
     * that doesn't seem worth trying to fix. */
    if (awdb->ipv4_start_node.node_value != 0) {
        return AWDB_SUCCESS;
    }

    record_info_s record_info = record_info_for_database(awdb);

    const uint8_t *search_tree = awdb->file_content;
    uint32_t node_value = 0;
    const uint8_t *record_pointer;
    uint16_t netmask;
    uint32_t node_count = awdb->metadata.node_count;

    for (netmask = 0; netmask < 96 && node_value < node_count; netmask++) {
        record_pointer = &search_tree[node_value * record_info.record_length];
        if (record_pointer + record_info.record_length > awdb->data_section) {
            return AWDB_CORRUPT_SEARCH_TREE_ERROR;
        }
        node_value = record_info.left_record_getter(record_pointer);
    }

    awdb->ipv4_start_node.node_value = node_value;
    awdb->ipv4_start_node.netmask = netmask;

    return AWDB_SUCCESS;
}

LOCAL uint8_t record_type(const AWDB_s *const awdb, uint64_t record)
{
    uint32_t node_count = awdb->metadata.node_count;

    /* Ideally we'd check to make sure that a record never points to a
     * previously seen value, but that's more complicated. For now, we can
     * at least check that we don't end up at the top of the tree again. */
    if (record == 0) {
        DEBUG_MSG("record has a value of 0");
        return AWDB_RECORD_TYPE_INVALID;
    }

    if (record < node_count) {
        return AWDB_RECORD_TYPE_SEARCH_NODE;
    }

    if (record == node_count) {
        return AWDB_RECORD_TYPE_EMPTY;
    }

    if (record - node_count < awdb->data_section_size) {
        return AWDB_RECORD_TYPE_DATA;
    }

    DEBUG_MSG("record has a value that points outside of the database");
    return AWDB_RECORD_TYPE_INVALID;
}

LOCAL uint32_t get_left_28_bit_record(const uint8_t *record)
{
    return record[0] * 65536 + record[1] * 256 + record[2] +
           ((record[3] & 0xf0) << 20);
}

LOCAL uint32_t get_right_28_bit_record(const uint8_t *record)
{
    uint32_t value = get_uint32(record);
    return value & 0xfffffff;
}

int AWDB_read_node(const AWDB_s *const awdb, uint32_t node_number,
                   AWDB_search_node_s *const node)
{
    record_info_s record_info = record_info_for_database(awdb);
    if (0 == record_info.right_record_offset) {
        return AWDB_UNKNOWN_DATABASE_FORMAT_ERROR;
    }

    if (node_number > awdb->metadata.node_count) {
        return AWDB_INVALID_NODE_NUMBER_ERROR;
    }

    const uint8_t *search_tree = awdb->file_content;
    const uint8_t *record_pointer =
        &search_tree[node_number * record_info.record_length];
    node->left_record = record_info.left_record_getter(record_pointer);
    record_pointer += record_info.right_record_offset;
    node->right_record = record_info.right_record_getter(record_pointer);

    node->left_record_type = record_type(awdb, node->left_record);
    node->right_record_type = record_type(awdb, node->right_record);

    // Note that offset will be invalid if the record type is not
    // AWDB_RECORD_TYPE_DATA, but that's ok. Any use of the record entry
    // for other data types is a programming error.
    node->left_record_entry = (struct AWDB_entry_s) {
        .awdb = awdb,
        .offset = data_section_offset_for_record(awdb, node->left_record),
    };
    node->right_record_entry = (struct AWDB_entry_s) {
        .awdb = awdb,
        .offset = data_section_offset_for_record(awdb, node->right_record),
    };

    return AWDB_SUCCESS;
}

LOCAL uint32_t data_section_offset_for_record(const AWDB_s *const awdb,
                                              uint64_t record)
{
    return (uint32_t)record - awdb->metadata.node_count -
           AWDB_DATA_SECTION_SEPARATOR;
}

int AWDB_get_value(AWDB_entry_s *const start,
                   AWDB_entry_data_s *const entry_data,
                   ...)
{
    va_list path;
    va_start(path, entry_data);
    int status = AWDB_vget_value(start, entry_data, path);
    va_end(path);
    return status;
}

int AWDB_vget_value(AWDB_entry_s *const start,
                    AWDB_entry_data_s *const entry_data,
                    va_list va_path)
{
    int length = path_length(va_path);
    const char *path_elem;
    int i = 0;

    MAYBE_CHECK_SIZE_OVERFLOW(length, SIZE_MAX / sizeof(const char *) - 1,
                              AWDB_INVALID_METADATA_ERROR);

    const char **path = malloc((length + 1) * sizeof(const char *));
    if (NULL == path) {
        return AWDB_OUT_OF_MEMORY_ERROR;
    }

    while (NULL != (path_elem = va_arg(va_path, char *))) {
        path[i] = path_elem;
        i++;
    }
    path[i] = NULL;

    int status = AWDB_aget_value(start, entry_data, path);

    free((char **)path);

    return status;
}

LOCAL int path_length(va_list va_path)
{
    int i = 0;
    const char *ignore;
    va_list path_copy;
    va_copy(path_copy, va_path);

    while (NULL != (ignore = va_arg(path_copy, char *))) {
        i++;
    }

    va_end(path_copy);

    return i;
}

int AWDB_aget_value(AWDB_entry_s *const start,
                    AWDB_entry_data_s *const entry_data,
                    const char *const *const path)
{
    const AWDB_s *const awdb = start->awdb;
    uint32_t offset = start->offset;

    memset(entry_data, 0, sizeof(AWDB_entry_data_s));
    DEBUG_NL;
    DEBUG_MSG("looking up value by path");

    CHECKED_DECODE_ONE_FOLLOW(awdb, offset, entry_data);

    DEBUG_NL;
    DEBUG_MSGF("top level element is a %s", type_num_to_name(entry_data->type));

    /* Can this happen? It'd probably represent a pathological case under
     * normal use, but there's nothing preventing someone from passing an
     * invalid AWDB_entry_s struct to this function */
    if (!entry_data->has_data) {
        return AWDB_INVALID_LOOKUP_PATH_ERROR;
    }

    const char *path_elem;
    int i = 0;
    while (NULL != (path_elem = path[i++])) {
        DEBUG_NL;
        DEBUG_MSGF("path elem = %s", path_elem);

        /* XXX - it'd be good to find a quicker way to skip through these
           entries that doesn't involve decoding them
           completely. Basically we need to just use the size from the
           control byte to advance our pointer rather than calling
           decode_one(). */
        if (entry_data->type == AWDB_DATA_TYPE_ARRAY) {
            int status = lookup_path_in_array(path_elem, awdb, entry_data);
            if (AWDB_SUCCESS != status) {
                memset(entry_data, 0, sizeof(AWDB_entry_data_s));
                return status;
            }
        } else if (entry_data->type == AWDB_DATA_TYPE_MAP) {
            int status = lookup_path_in_map(path_elem, awdb, entry_data);
            if (AWDB_SUCCESS != status) {
                memset(entry_data, 0, sizeof(AWDB_entry_data_s));
                return status;
            }
        } else {
            /* Once we make the code traverse maps & arrays without calling
             * decode_one() we can get rid of this. */
            memset(entry_data, 0, sizeof(AWDB_entry_data_s));
            return AWDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
        }
    }

    return AWDB_SUCCESS;
}

LOCAL int lookup_path_in_array(const char *path_elem,
                               const AWDB_s *const awdb,
                               AWDB_entry_data_s *entry_data)
{
    uint32_t size = entry_data->data_size;
    char *first_invalid;

    int saved_errno = errno;
    errno = 0;
    int array_index = strtol(path_elem, &first_invalid, 10);
    if (ERANGE == errno) {
        errno = saved_errno;
        return AWDB_INVALID_LOOKUP_PATH_ERROR;
    }
    errno = saved_errno;

    if (array_index < 0) {
        array_index += size;

        if (array_index < 0) {
            return AWDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
        }
    }

    if (*first_invalid || (uint32_t)array_index >= size) {
        return AWDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
    }

    for (int i = 0; i < array_index; i++) {
        /* We don't want to follow a pointer here. If the next element is a
         * pointer we simply skip it and keep going */
        CHECKED_DECODE_ONE(awdb, entry_data->offset_to_next, entry_data);
        int status = skip_map_or_array(awdb, entry_data);
        if (AWDB_SUCCESS != status) {
            return status;
        }
    }

    AWDB_entry_data_s value;
    CHECKED_DECODE_ONE_FOLLOW(awdb, entry_data->offset_to_next, &value);
    memcpy(entry_data, &value, sizeof(AWDB_entry_data_s));

    return AWDB_SUCCESS;
}

LOCAL int lookup_path_in_map(const char *path_elem,
                             const AWDB_s *const awdb,
                             AWDB_entry_data_s *entry_data)
{
    uint32_t size = entry_data->data_size;
    uint32_t offset = entry_data->offset_to_next;
    size_t path_elem_len = strlen(path_elem);

    while (size-- > 0) {
        AWDB_entry_data_s key, value;
        CHECKED_DECODE_ONE_FOLLOW(awdb, offset, &key);

        uint32_t offset_to_value = key.offset_to_next;

        if (AWDB_DATA_TYPE_UTF8_STRING != key.type) {
            return AWDB_INVALID_DATA_ERROR;
        }

        if (key.data_size == path_elem_len &&
            !memcmp(path_elem, key.utf8_string, path_elem_len)) {

            DEBUG_MSG("found key matching path elem");

            CHECKED_DECODE_ONE_FOLLOW(awdb, offset_to_value, &value);
            memcpy(entry_data, &value, sizeof(AWDB_entry_data_s));
            return AWDB_SUCCESS;
        } else {
            /* We don't want to follow a pointer here. If the next element is
             * a pointer we simply skip it and keep going */
            CHECKED_DECODE_ONE(awdb, offset_to_value, &value);
            int status = skip_map_or_array(awdb, &value);
            if (AWDB_SUCCESS != status) {
                return status;
            }
            offset = value.offset_to_next;
        }
    }

    memset(entry_data, 0, sizeof(AWDB_entry_data_s));
    return AWDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
}

LOCAL int skip_map_or_array(const AWDB_s *const awdb,
                            AWDB_entry_data_s *entry_data)
{
    if (entry_data->type == AWDB_DATA_TYPE_MAP) {
        uint32_t size = entry_data->data_size;
        while (size-- > 0) {
            CHECKED_DECODE_ONE(awdb, entry_data->offset_to_next, entry_data);   // key
            CHECKED_DECODE_ONE(awdb, entry_data->offset_to_next, entry_data);   // value
            int status = skip_map_or_array(awdb, entry_data);
            if (AWDB_SUCCESS != status) {
                return status;
            }
        }
    } else if (entry_data->type == AWDB_DATA_TYPE_ARRAY) {
        uint32_t size = entry_data->data_size;
        while (size-- > 0) {
            CHECKED_DECODE_ONE(awdb, entry_data->offset_to_next, entry_data);   // value
            int status = skip_map_or_array(awdb, entry_data);
            if (AWDB_SUCCESS != status) {
                return status;
            }
        }
    }

    return AWDB_SUCCESS;
}

LOCAL int decode_one_follow(const AWDB_s *const awdb, uint32_t offset,
                            AWDB_entry_data_s *entry_data)
{
    CHECKED_DECODE_ONE(awdb, offset, entry_data);
    if (entry_data->type == AWDB_DATA_TYPE_POINTER) {
        uint32_t next = entry_data->offset_to_next;
        CHECKED_DECODE_ONE(awdb, entry_data->pointer, entry_data);
        /* Pointers to pointers are illegal under the spec */
        if (entry_data->type == AWDB_DATA_TYPE_POINTER) {
            DEBUG_MSG("pointer points to another pointer");
            return AWDB_INVALID_DATA_ERROR;
        }

        /* The pointer could point to any part of the data section but the
         * next entry for this particular offset may be the one after the
         * pointer, not the one after whatever the pointer points to. This
         * depends on whether the pointer points to something that is a simple
         * value or a compound value. For a compound value, the next one is
         * the one after the pointer result, not the one after the pointer. */
        if (entry_data->type != AWDB_DATA_TYPE_MAP
            && entry_data->type != AWDB_DATA_TYPE_ARRAY) {

            entry_data->offset_to_next = next;
        }
    }

    return AWDB_SUCCESS;
}

#if !AWDB_UINT128_IS_BYTE_ARRAY
LOCAL awdb_uint128_t get_uint128(const uint8_t *p, int length)
{
    awdb_uint128_t value = 0;
    while (length-- > 0) {
        value <<= 8;
        value += *p++;
    }
    return value;
}
#endif

LOCAL int decode_one(const AWDB_s *const awdb, uint32_t offset,
                     AWDB_entry_data_s *entry_data)
{
    const uint8_t *mem = awdb->data_section;

    // We subtract rather than add as it possible that offset + 1
    // could overflow for a corrupt database while an underflow
    // from data_section_size - 1 should not be possible.
    if (offset > awdb->data_section_size - 1) {
        DEBUG_MSGF("Offset (%d) past data section (%d)", offset,
                   awdb->data_section_size);
        return AWDB_INVALID_DATA_ERROR;
    }

    entry_data->offset = offset;
    entry_data->has_data = true;

    DEBUG_NL;
    DEBUG_MSGF("Offset: %i", offset);

    uint8_t ctrl = mem[offset++];
    DEBUG_BINARY("Control byte: %s", ctrl);

    int type = (ctrl >> 5) & 7;
    DEBUG_MSGF("Type: %i (%s)", type, type_num_to_name(type));

    if (type == AWDB_DATA_TYPE_EXTENDED) {
        // Subtracting 1 to avoid possible overflow on offset + 1
        if (offset > awdb->data_section_size - 1) {
            DEBUG_MSGF("Extended type offset (%d) past data section (%d)",
                       offset,
                       awdb->data_section_size);
            return AWDB_INVALID_DATA_ERROR;
        }
        type = get_ext_type(mem[offset++]);
        DEBUG_MSGF("Extended type: %i (%s)", type, type_num_to_name(type));
    }

    entry_data->type = type;

    if (type == AWDB_DATA_TYPE_POINTER) {
        uint8_t psize = ((ctrl >> 3) & 3) + 1;
        DEBUG_MSGF("Pointer size: %i", psize);

        // We check that the offset does not extend past the end of the
        // database and that the subtraction of psize did not underflow.
        if (offset > awdb->data_section_size - psize ||
            awdb->data_section_size < psize) {
            DEBUG_MSGF("Pointer offset (%d) past data section (%d)", offset +
                       psize,
                       awdb->data_section_size);
            return AWDB_INVALID_DATA_ERROR;
        }
        entry_data->pointer = get_ptr_from(ctrl, &mem[offset], psize);
        DEBUG_MSGF("Pointer to: %i", entry_data->pointer);

        entry_data->data_size = psize;
        entry_data->offset_to_next = offset + psize;
        return AWDB_SUCCESS;
    }

    uint32_t size = ctrl & 31;
    switch (size) {
    case 29:
        // We subtract when checking offset to avoid possible overflow
        if (offset > awdb->data_section_size - 1) {
            DEBUG_MSGF("String end (%d, case 29) past data section (%d)",
                       offset,
                       awdb->data_section_size);
            return AWDB_INVALID_DATA_ERROR;
        }
        size = 29 + mem[offset++];
        break;
    case 30:
        // We subtract when checking offset to avoid possible overflow
        if (offset > awdb->data_section_size - 2) {
            DEBUG_MSGF("String end (%d, case 30) past data section (%d)",
                       offset,
                       awdb->data_section_size);
            return AWDB_INVALID_DATA_ERROR;
        }
        size = 285 + get_uint16(&mem[offset]);
        offset += 2;
        break;
    case 31:
        // We subtract when checking offset to avoid possible overflow
        if (offset > awdb->data_section_size - 3) {
            DEBUG_MSGF("String end (%d, case 31) past data section (%d)",
                       offset,
                       awdb->data_section_size);
            return AWDB_INVALID_DATA_ERROR;
        }
        size = 65821 + get_uint24(&mem[offset]);
        offset += 3;
    default:
        break;
    }

    DEBUG_MSGF("Size: %i", size);

    if (type == AWDB_DATA_TYPE_MAP || type == AWDB_DATA_TYPE_ARRAY) {
        entry_data->data_size = size;
        entry_data->offset_to_next = offset;
        return AWDB_SUCCESS;
    }

    if (type == AWDB_DATA_TYPE_BOOLEAN) {
        entry_data->boolean = size ? true : false;
        entry_data->data_size = 0;
        entry_data->offset_to_next = offset;
        DEBUG_MSGF("boolean value: %s", entry_data->boolean ? "true" : "false");
        return AWDB_SUCCESS;
    }

    // Check that the data doesn't extend past the end of the memory
    // buffer and that the calculation in doing this did not underflow.
    if (offset > awdb->data_section_size - size ||
        awdb->data_section_size < size) {
        DEBUG_MSGF("Data end (%d) past data section (%d)", offset + size,
                   awdb->data_section_size);
        return AWDB_INVALID_DATA_ERROR;
    }

    if (type == AWDB_DATA_TYPE_UINT16) {
        if (size > 2) {
            DEBUG_MSGF("uint16 of size %d", size);
            return AWDB_INVALID_DATA_ERROR;
        }
        entry_data->uint16 = (uint16_t)get_uintX(&mem[offset], size);
        DEBUG_MSGF("uint16 value: %u", entry_data->uint16);
    } else if (type == AWDB_DATA_TYPE_UINT32) {
        if (size > 4) {
            DEBUG_MSGF("uint32 of size %d", size);
            return AWDB_INVALID_DATA_ERROR;
        }
        entry_data->uint32 = (uint32_t)get_uintX(&mem[offset], size);
        DEBUG_MSGF("uint32 value: %u", entry_data->uint32);
    } else if (type == AWDB_DATA_TYPE_INT32) {
        if (size > 4) {
            DEBUG_MSGF("int32 of size %d", size);
            return AWDB_INVALID_DATA_ERROR;
        }
        entry_data->int32 = get_sintX(&mem[offset], size);
        DEBUG_MSGF("int32 value: %i", entry_data->int32);
    } else if (type == AWDB_DATA_TYPE_UINT64) {
        if (size > 8) {
            DEBUG_MSGF("uint64 of size %d", size);
            return AWDB_INVALID_DATA_ERROR;
        }
        entry_data->uint64 = get_uintX(&mem[offset], size);
        DEBUG_MSGF("uint64 value: %" PRIu64, entry_data->uint64);
    } else if (type == AWDB_DATA_TYPE_UINT128) {
        if (size > 16) {
            DEBUG_MSGF("uint128 of size %d", size);
            return AWDB_INVALID_DATA_ERROR;
        }
#if AWDB_UINT128_IS_BYTE_ARRAY
        memset(entry_data->uint128, 0, 16);
        if (size > 0) {
            memcpy(entry_data->uint128 + 16 - size, &mem[offset], size);
        }
#else
        entry_data->uint128 = get_uint128(&mem[offset], size);
#endif
    } else if (type == AWDB_DATA_TYPE_FLOAT) {
        if (size != 4) {
            DEBUG_MSGF("float of size %d", size);
            return AWDB_INVALID_DATA_ERROR;
        }
        size = 4;
        entry_data->float_value = get_ieee754_float(&mem[offset]);
        DEBUG_MSGF("float value: %f", entry_data->float_value);
    } else if (type == AWDB_DATA_TYPE_DOUBLE) {
        if (size != 8) {
            DEBUG_MSGF("double of size %d", size);
            return AWDB_INVALID_DATA_ERROR;
        }
        size = 8;
        entry_data->double_value = get_ieee754_double(&mem[offset]);
        DEBUG_MSGF("double value: %f", entry_data->double_value);
    } else if (type == AWDB_DATA_TYPE_UTF8_STRING) {
        entry_data->utf8_string = size == 0 ? "" : (char *)&mem[offset];
        entry_data->data_size = size;
#ifdef AWDB_DEBUG
        char *string = awdb_strndup(entry_data->utf8_string,
                                    size > 50 ? 50 : size);
        if (NULL == string) {
            abort();
        }
        DEBUG_MSGF("string value: %s", string);
        free(string);
#endif
    } else if (type == AWDB_DATA_TYPE_BYTES) {
        entry_data->bytes = &mem[offset];
        entry_data->data_size = size;
    }

    entry_data->offset_to_next = offset + size;

    return AWDB_SUCCESS;
}

LOCAL int get_ext_type(int raw_ext_type)
{
    return 7 + raw_ext_type;
}

LOCAL uint32_t get_ptr_from(uint8_t ctrl, uint8_t const *const ptr,
                            int ptr_size)
{
    uint32_t new_offset;
    switch (ptr_size) {
    case 1:
        new_offset = ( (ctrl & 7) << 8) + ptr[0];
        break;
    case 2:
        new_offset = 2048 + ( (ctrl & 7) << 16 ) + ( ptr[0] << 8) + ptr[1];
        break;
    case 3:
        new_offset = 2048 + 524288 + ( (ctrl & 7) << 24 ) + get_uint24(ptr);
        break;
    case 4:
    default:
        new_offset = get_uint32(ptr);
        break;
    }
    return new_offset;
}

int AWDB_get_metadata_as_entry_data_list(
    const AWDB_s *const awdb, AWDB_entry_data_list_s **const entry_data_list)
{
    AWDB_s metadata_db = make_fake_metadata_db(awdb);

    AWDB_entry_s metadata_start = {
        .awdb   = &metadata_db,
        .offset = 0
    };

    return AWDB_get_entry_data_list(&metadata_start, entry_data_list);
}

int AWDB_get_entry_data_list(
    AWDB_entry_s *start, AWDB_entry_data_list_s **const entry_data_list)
{
    AWDB_data_pool_s *const pool = data_pool_new(AWDB_POOL_INIT_SIZE);
    if (!pool) {
        return AWDB_OUT_OF_MEMORY_ERROR;
    }

    AWDB_entry_data_list_s *const list = data_pool_alloc(pool);
    if (!list) {
        data_pool_destroy(pool);
        return AWDB_OUT_OF_MEMORY_ERROR;
    }

    int const status = get_entry_data_list(start->awdb, start->offset, list,
                                           pool, 0);

    *entry_data_list = data_pool_to_list(pool);
    if (!*entry_data_list) {
        data_pool_destroy(pool);
        return AWDB_OUT_OF_MEMORY_ERROR;
    }

    return status;
}

LOCAL int get_entry_data_list(const AWDB_s *const awdb,
                              uint32_t offset,
                              AWDB_entry_data_list_s *const entry_data_list,
                              AWDB_data_pool_s *const pool,
                              int depth)
{
    if (depth >= MAXIMUM_DATA_STRUCTURE_DEPTH) {
        DEBUG_MSG("reached the maximum data structure depth");
        return AWDB_INVALID_DATA_ERROR;
    }
    depth++;
    CHECKED_DECODE_ONE(awdb, offset, &entry_data_list->entry_data);

    switch (entry_data_list->entry_data.type) {
    case AWDB_DATA_TYPE_POINTER:
        {
            uint32_t next_offset = entry_data_list->entry_data.offset_to_next;
            uint32_t last_offset;
            CHECKED_DECODE_ONE(awdb, last_offset =
                                   entry_data_list->entry_data.pointer,
                               &entry_data_list->entry_data);

            /* Pointers to pointers are illegal under the spec */
            if (entry_data_list->entry_data.type == AWDB_DATA_TYPE_POINTER) {
                DEBUG_MSG("pointer points to another pointer");
                return AWDB_INVALID_DATA_ERROR;
            }

            if (entry_data_list->entry_data.type == AWDB_DATA_TYPE_ARRAY
                || entry_data_list->entry_data.type == AWDB_DATA_TYPE_MAP) {

                int status =
                    get_entry_data_list(awdb, last_offset, entry_data_list,
                                        pool, depth);
                if (AWDB_SUCCESS != status) {
                    DEBUG_MSG("get_entry_data_list on pointer failed.");
                    return status;
                }
            }
            entry_data_list->entry_data.offset_to_next = next_offset;
        }
        break;
    case AWDB_DATA_TYPE_ARRAY:
        {
            uint32_t array_size = entry_data_list->entry_data.data_size;
            uint32_t array_offset = entry_data_list->entry_data.offset_to_next;
            while (array_size-- > 0) {
                AWDB_entry_data_list_s *entry_data_list_to =
                    data_pool_alloc(pool);
                if (!entry_data_list_to) {
                    return AWDB_OUT_OF_MEMORY_ERROR;
                }

                int status =
                    get_entry_data_list(awdb, array_offset, entry_data_list_to,
                                        pool, depth);
                if (AWDB_SUCCESS != status) {
                    DEBUG_MSG("get_entry_data_list on array element failed.");
                    return status;
                }

                array_offset = entry_data_list_to->entry_data.offset_to_next;
            }
            entry_data_list->entry_data.offset_to_next = array_offset;

        }
        break;
    case AWDB_DATA_TYPE_MAP:
        {
            uint32_t size = entry_data_list->entry_data.data_size;

            offset = entry_data_list->entry_data.offset_to_next;
            while (size-- > 0) {
                AWDB_entry_data_list_s *list_key = data_pool_alloc(pool);
                if (!list_key) {
                    return AWDB_OUT_OF_MEMORY_ERROR;
                }

                int status =
                    get_entry_data_list(awdb, offset, list_key, pool, depth);
                if (AWDB_SUCCESS != status) {
                    DEBUG_MSG("get_entry_data_list on map key failed.");
                    return status;
                }

                offset = list_key->entry_data.offset_to_next;

                AWDB_entry_data_list_s *list_value = data_pool_alloc(pool);
                if (!list_value) {
                    return AWDB_OUT_OF_MEMORY_ERROR;
                }

                status = get_entry_data_list(awdb, offset, list_value, pool,
                                             depth);
                if (AWDB_SUCCESS != status) {
                    DEBUG_MSG("get_entry_data_list on map element failed.");
                    return status;
                }
                offset = list_value->entry_data.offset_to_next;
            }
            entry_data_list->entry_data.offset_to_next = offset;
        }
        break;
    default:
        break;
    }

    return AWDB_SUCCESS;
}

LOCAL float get_ieee754_float(const uint8_t *restrict p)
{
    volatile float f;
    uint8_t *q = (void *)&f;
/* Windows builds don't use autoconf but we can assume they're all
 * little-endian. */
#if AWDB_LITTLE_ENDIAN || _WIN32
    q[3] = p[0];
    q[2] = p[1];
    q[1] = p[2];
    q[0] = p[3];
#else
    memcpy(q, p, 4);
#endif
    return f;
}

LOCAL double get_ieee754_double(const uint8_t *restrict p)
{
    volatile double d;
    uint8_t *q = (void *)&d;
#if AWDB_LITTLE_ENDIAN || _WIN32
    q[7] = p[0];
    q[6] = p[1];
    q[5] = p[2];
    q[4] = p[3];
    q[3] = p[4];
    q[2] = p[5];
    q[1] = p[6];
    q[0] = p[7];
#else
    memcpy(q, p, 8);
#endif

    return d;
}

LOCAL uint32_t get_uint32(const uint8_t *p)
{
    return p[0] * 16777216U + p[1] * 65536 + p[2] * 256 + p[3];
}

LOCAL uint32_t get_uint24(const uint8_t *p)
{
    return p[0] * 65536U + p[1] * 256 + p[2];
}

LOCAL uint32_t get_uint16(const uint8_t *p)
{
    return p[0] * 256U + p[1];
}

LOCAL uint64_t get_uintX(const uint8_t *p, int length)
{
    uint64_t value = 0;
    while (length-- > 0) {
        value <<= 8;
        value += *p++;
    }
    return value;
}

LOCAL int32_t get_sintX(const uint8_t *p, int length)
{
    return (int32_t)get_uintX(p, length);
}

void AWDB_free_entry_data_list(AWDB_entry_data_list_s *const entry_data_list)
{
    if (entry_data_list == NULL) {
        return;
    }
    data_pool_destroy(entry_data_list->pool);
}

void AWDB_close(AWDB_s *const awdb)
{
    free_awdb_struct(awdb);
}

LOCAL void free_awdb_struct(AWDB_s *const awdb)
{
    if (!awdb) {
        return;
    }

    if (NULL != awdb->filename) {
        FREE_AND_SET_NULL(awdb->filename);
    }
    if (NULL != awdb->file_content) {
#ifdef _WIN32
        UnmapViewOfFile(awdb->file_content);
        /* Winsock is only initialized if open was successful so we only have
         * to cleanup then. */
        WSACleanup();
#else
        munmap((void *)awdb->file_content, awdb->file_size);
#endif
    }

    if (NULL != awdb->metadata.database_type) {
        FREE_AND_SET_NULL(awdb->metadata.database_type);
    }

    free_languages_metadata(awdb);
    free_descriptions_metadata(awdb);
}

LOCAL void free_languages_metadata(AWDB_s *awdb)
{
    if (!awdb->metadata.languages.names) {
        return;
    }

    for (size_t i = 0; i < awdb->metadata.languages.count; i++) {
        FREE_AND_SET_NULL(awdb->metadata.languages.names[i]);
    }
    FREE_AND_SET_NULL(awdb->metadata.languages.names);
}

LOCAL void free_descriptions_metadata(AWDB_s *awdb)
{
    if (!awdb->metadata.description.count) {
        return;
    }

    for (size_t i = 0; i < awdb->metadata.description.count; i++) {
        if (NULL != awdb->metadata.description.descriptions[i]) {
            if (NULL !=
                awdb->metadata.description.descriptions[i]->language) {
                FREE_AND_SET_NULL(
                    awdb->metadata.description.descriptions[i]->language);
            }

            if (NULL !=
                awdb->metadata.description.descriptions[i]->description) {
                FREE_AND_SET_NULL(
                    awdb->metadata.description.descriptions[i]->description);
            }
            FREE_AND_SET_NULL(awdb->metadata.description.descriptions[i]);
        }
    }

    FREE_AND_SET_NULL(awdb->metadata.description.descriptions);
}

const char *AWDB_lib_version(void)
{
    return PACKAGE_VERSION;
}

int AWDB_dump_entry_data_list(FILE *const stream,
                              AWDB_entry_data_list_s *const entry_data_list,
                              int indent)
{
    int status;
    dump_entry_data_list(stream, entry_data_list, indent, &status);
    return status;
}

LOCAL AWDB_entry_data_list_s *dump_entry_data_list(
    FILE *stream, AWDB_entry_data_list_s *entry_data_list, int indent,
    int *status)
{
    switch (entry_data_list->entry_data.type) {
    case AWDB_DATA_TYPE_MAP:
        {
            uint32_t size = entry_data_list->entry_data.data_size;

            print_indentation(stream, indent);
            fprintf(stream, "{\n");
            indent += 2;

            for (entry_data_list = entry_data_list->next;
                 size && entry_data_list; size--) {

                if (AWDB_DATA_TYPE_UTF8_STRING !=
                    entry_data_list->entry_data.type) {
                    *status = AWDB_INVALID_DATA_ERROR;
                    return NULL;
                }
                char *key =
                    awdb_strndup(
                        (char *)entry_data_list->entry_data.utf8_string,
                        entry_data_list->entry_data.data_size);
                if (NULL == key) {
                    *status = AWDB_OUT_OF_MEMORY_ERROR;
                    return NULL;
                }

                print_indentation(stream, indent);
                fprintf(stream, "\"%s\": \n", key);
                free(key);

                entry_data_list = entry_data_list->next;
                entry_data_list =
                    dump_entry_data_list(stream, entry_data_list, indent + 2,
                                         status);

                if (AWDB_SUCCESS != *status) {
                    return NULL;
                }
            }

            indent -= 2;
            print_indentation(stream, indent);
            fprintf(stream, "}\n");
        }
        break;
    case AWDB_DATA_TYPE_ARRAY:
        {
            uint32_t size = entry_data_list->entry_data.data_size;

            print_indentation(stream, indent);
            fprintf(stream, "[\n");
            indent += 2;

            for (entry_data_list = entry_data_list->next;
                 size && entry_data_list; size--) {
                entry_data_list =
                    dump_entry_data_list(stream, entry_data_list, indent,
                                         status);
                if (AWDB_SUCCESS != *status) {
                    return NULL;
                }
            }

            indent -= 2;
            print_indentation(stream, indent);
            fprintf(stream, "]\n");
        }
        break;
    case AWDB_DATA_TYPE_UTF8_STRING:
        {
            char *string =
                awdb_strndup((char *)entry_data_list->entry_data.utf8_string,
                             entry_data_list->entry_data.data_size);
            if (NULL == string) {
                *status = AWDB_OUT_OF_MEMORY_ERROR;
                return NULL;
            }
            print_indentation(stream, indent);
            fprintf(stream, "\"%s\" <utf8_string>\n", string);
            free(string);
            entry_data_list = entry_data_list->next;
        }
        break;
    case AWDB_DATA_TYPE_BYTES:
        {
            char *hex_string =
                bytes_to_hex((uint8_t *)entry_data_list->entry_data.bytes,
                             entry_data_list->entry_data.data_size);
            if (NULL == hex_string) {
                *status = AWDB_OUT_OF_MEMORY_ERROR;
                return NULL;
            }

            print_indentation(stream, indent);
            fprintf(stream, "%s <bytes>\n", hex_string);
            free(hex_string);

            entry_data_list = entry_data_list->next;
        }
        break;
    case AWDB_DATA_TYPE_DOUBLE:
        print_indentation(stream, indent);
        fprintf(stream, "%f <double>\n",
                entry_data_list->entry_data.double_value);
        entry_data_list = entry_data_list->next;
        break;
    case AWDB_DATA_TYPE_FLOAT:
        print_indentation(stream, indent);
        fprintf(stream, "%f <float>\n",
                entry_data_list->entry_data.float_value);
        entry_data_list = entry_data_list->next;
        break;
    case AWDB_DATA_TYPE_UINT16:
        print_indentation(stream, indent);
        fprintf(stream, "%u <uint16>\n", entry_data_list->entry_data.uint16);
        entry_data_list = entry_data_list->next;
        break;
    case AWDB_DATA_TYPE_UINT32:
        print_indentation(stream, indent);
        fprintf(stream, "%u <uint32>\n", entry_data_list->entry_data.uint32);
        entry_data_list = entry_data_list->next;
        break;
    case AWDB_DATA_TYPE_BOOLEAN:
        print_indentation(stream, indent);
        fprintf(stream, "%s <boolean>\n",
                entry_data_list->entry_data.boolean ? "true" : "false");
        entry_data_list = entry_data_list->next;
        break;
    case AWDB_DATA_TYPE_UINT64:
        print_indentation(stream, indent);
        fprintf(stream, "%" PRIu64 " <uint64>\n",
                entry_data_list->entry_data.uint64);
        entry_data_list = entry_data_list->next;
        break;
    case AWDB_DATA_TYPE_UINT128:
        print_indentation(stream, indent);
#if AWDB_UINT128_IS_BYTE_ARRAY
        char *hex_string =
            bytes_to_hex((uint8_t *)entry_data_list->entry_data.uint128, 16);
        if (NULL == hex_string) {
            *status = AWDB_OUT_OF_MEMORY_ERROR;
            return NULL;
        }
        fprintf(stream, "0x%s <uint128>\n", hex_string);
        free(hex_string);
#else
        uint64_t high = entry_data_list->entry_data.uint128 >> 64;
        uint64_t low = (uint64_t)entry_data_list->entry_data.uint128;
        fprintf(stream, "0x%016" PRIX64 "%016" PRIX64 " <uint128>\n", high,
                low);
#endif
        entry_data_list = entry_data_list->next;
        break;
    case AWDB_DATA_TYPE_INT32:
        print_indentation(stream, indent);
        fprintf(stream, "%d <int32>\n", entry_data_list->entry_data.int32);
        entry_data_list = entry_data_list->next;
        break;
    default:
        *status = AWDB_INVALID_DATA_ERROR;
        return NULL;
    }

    *status = AWDB_SUCCESS;
    return entry_data_list;
}

LOCAL void print_indentation(FILE *stream, int i)
{
    char buffer[1024];
    int size = i >= 1024 ? 1023 : i;
    memset(buffer, 32, size);
    buffer[size] = '\0';
    fputs(buffer, stream);
}

LOCAL char *bytes_to_hex(uint8_t *bytes, uint32_t size)
{
    char *hex_string;
    MAYBE_CHECK_SIZE_OVERFLOW(size, SIZE_MAX / 2 - 1, NULL);

    hex_string = malloc((size * 2) + 1);
    if (NULL == hex_string) {
        return NULL;
    }

    for (uint32_t i = 0; i < size; i++) {
        sprintf(hex_string + (2 * i), "%02X", bytes[i]);
    }

    return hex_string;
}

const char *AWDB_strerror(int error_code)
{
    switch (error_code) {
    case AWDB_SUCCESS:
        return "Success (not an error)";
    case AWDB_FILE_OPEN_ERROR:
        return "please enter the right filepath,or ask for data file from https://www.ipplus360.com/";
    case AWDB_CORRUPT_SEARCH_TREE_ERROR:
        return "The aiwen DB file's search tree is corrupt";
    case AWDB_INVALID_METADATA_ERROR:
        return "The aiwen DB file contains invalid metadata";
    case AWDB_IO_ERROR:
        return "An attempt to read data from the aiwen DB file failed";
    case AWDB_OUT_OF_MEMORY_ERROR:
        return "A memory allocation call failed";
    case AWDB_UNKNOWN_DATABASE_FORMAT_ERROR:
        return
            "The aiwen DB file is in a format this library can't handle (unknown record size or binary format version)";
    case AWDB_INVALID_DATA_ERROR:
        return
            "The aiwen DB file's data section contains bad data (unknown data type or corrupt data)";
    case AWDB_INVALID_LOOKUP_PATH_ERROR:
        return
            "The lookup path contained an invalid value (like a negative integer for an array index)";
    case AWDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR:
        return
            "The lookup path does not match the data (key that doesn't exist, array index bigger than the array, expected array or map where none exists)";
    case AWDB_INVALID_NODE_NUMBER_ERROR:
        return
            "The AWDB_read_node function was called with a node number that does not exist in the search tree";
    case AWDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR:
        return
            "You attempted to look up an IPv6 address in an IPv4-only database";
    default:
        return "Unknown error code";
    }
}
