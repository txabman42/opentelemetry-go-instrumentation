// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef _GO_TYPES_H
#define _GO_TYPES_H

#include "utils.h"
#include "alloc.h"
#include "bpf_helpers.h"

/* Max size of slice array in bytes 
 Keep a power of 2 to help with masks */
#define MAX_SLICE_ARRAY_SIZE 1024

typedef struct go_string
{
    char *str;
    s64 len;
} go_string_t;

typedef struct go_slice
{
    void *array;
    s64 len;
    s64 cap;
} go_slice_t;

typedef struct go_iface
{
    void *type;
    void *data;
} go_iface_t;

// a map bucket type with the given key and value types
#define MAP_BUCKET_TYPE(key_type, value_type) struct map_bucket_##key_type##_##value_type##_t
// a map bucket struct definition with the given key and value types
// for more details about the structure of a map bucket see:
// https://github.com/golang/go/blob/639cc0dcc0948dd02c9d5fc12fbed730a21ebebc/src/runtime/map.go#L143
#define MAP_BUCKET_DEFINITION(key_type, value_type) \
MAP_BUCKET_TYPE(key_type, value_type) { \
    char tophash[8]; \
    key_type keys[8]; \
    value_type values[8]; \
    void *overflow; \
};

struct slice_array_buff
{
    unsigned char buff[MAX_SLICE_ARRAY_SIZE];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct slice_array_buff);
    __uint(max_entries, 1);
} slice_array_buff_map SEC(".maps");

// In Go, interfaces are represented as a pair of pointers: a pointer to the
// interface data, and a pointer to the interface table.
// See: runtime.iface in https://golang.org/src/runtime/runtime2.go
static __always_inline void* get_go_interface_instance(void *iface)
{
    return (void*)(iface + 8);
}

// Structure to hold the result of finding a key in a map
struct map_key_find_result {
    bool found;                      // Whether the key was found
    u32 bucket_index;                // Bucket index where the key was found
    u32 entry_index;                 // Entry index within the bucket
    void *key_ptr;                   // Pointer to the key
    void *value_ptr;                 // Pointer to the value
};

// Define the map bucket structure for go_string_t keys and go_slice_t values
MAP_BUCKET_DEFINITION(go_string_t, go_slice_t)

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(MAP_BUCKET_TYPE(go_string_t, go_slice_t)));
    __uint(max_entries, 1);
} golang_mapbucket_storage_map SEC(".maps");

// Generic function to search for a key in a Go map
// Parameters:
//   map_ptr: pointer to the go map
//   key_to_find: string to search for
//   key_length: length of the key to find
//   buckets_ptr_pos: offset to the buckets pointer from map_ptr
//   result: pointer to a map_key_find_result structure to store the result
// Returns:
//   0 on success, negative value on error
static __always_inline long find_key_in_go_map(void *map_ptr, const char *key_to_find, u32 key_length, 
                                        u64 buckets_ptr_pos, struct map_key_find_result *result)
{
    long res;
    if (!map_ptr || !result) {
        return -1;
    }

    // Initialize result
    result->found = false;
    result->bucket_index = 0;
    result->entry_index = 0;
    result->key_ptr = NULL;
    result->value_ptr = NULL;

    // Read map count and bucket count
    u64 headers_count = 0;
    res = bpf_probe_read(&headers_count, sizeof(headers_count), map_ptr);
    if (res < 0 || headers_count == 0) {
        return -2;
    }

    unsigned char log_2_bucket_count;
    res = bpf_probe_read(&log_2_bucket_count, sizeof(log_2_bucket_count), map_ptr + 9);
    if (res < 0) {
        return -3;
    }

    u64 bucket_count = 1 << log_2_bucket_count;
    void *header_buckets;
    res = bpf_probe_read(&header_buckets, sizeof(header_buckets), (void*)(map_ptr + buckets_ptr_pos));
    if (res < 0 || header_buckets == NULL) {
        return -4;
    }

    // Get temporary storage for the bucket
    u32 map_id = 0;
    MAP_BUCKET_TYPE(go_string_t, go_slice_t) *map_value = bpf_map_lookup_elem(&golang_mapbucket_storage_map, &map_id);
    if (!map_value) {
        return -5;
    }

    // Iterate over buckets
    #pragma unroll
    // for (u64 bucket_idx = 0; bucket_idx < 8 && bucket_idx < bucket_count; bucket_idx++) {
    for (u64 bucket_idx = 0; bucket_idx < 8 && bucket_idx < bucket_count; bucket_idx++) {
        res = bpf_probe_read(map_value, sizeof(MAP_BUCKET_TYPE(go_string_t, go_slice_t)), 
                          header_buckets + (bucket_idx * sizeof(MAP_BUCKET_TYPE(go_string_t, go_slice_t))));
        if (res < 0) {
            continue;
        }

        // Iterate over entries in the bucket
        #pragma unroll
        for (u64 entry_idx = 0; entry_idx < 3; entry_idx++) {
            // Skip empty entries
            if (map_value->tophash[entry_idx] == 0) {
                bpf_printk("XMB999: Skip empty entries - tophash[%d] = 0", entry_idx);
                continue;
            }
            
            // Check if this key matches
            if (map_value->keys[entry_idx].len != key_length) {
                // char key_buffer[64] = {0};
                // if (map_value->keys[entry_idx].str != NULL && map_value->keys[entry_idx].len > 0) {
                //     u32 key_read_len = map_value->keys[entry_idx].len < 63 ? map_value->keys[entry_idx].len : 63;
                //     bpf_probe_read(key_buffer, key_read_len, map_value->keys[entry_idx].str);
                // }
                // bpf_printk("XMB999: Skip empty entries - key length mismatch, key=%s (key_length=%d, entry_idx=%d)", key_buffer, key_length, entry_idx);
                continue;
            }
            
            char current_key[32] = {0};  // Buffer to hold the key content
            u32 read_len = key_length < 32 ? key_length : 32;
            
            res = bpf_probe_read(current_key, read_len, map_value->keys[entry_idx].str);
            if (res < 0) {
                bpf_printk("XMB999: Skip empty entries - read error");
                continue;
            }

            // Print the current key for debugging
            bpf_printk("Current key: %s", current_key);
            if (bpf_memicmp(current_key, key_to_find, read_len) == 0) {
                // Key found
                result->found = true;
                result->bucket_index = bucket_idx;
                result->entry_index = entry_idx;
                result->key_ptr = &map_value->keys[entry_idx];
                result->value_ptr = &map_value->values[entry_idx];
                return 0;
            }
        }
    }
    
    return -6;  // Key not found
}

static __always_inline struct go_string write_user_go_string(char *str, u32 len)
{
    // Copy chars to userspace
    struct go_string new_string = {.str = NULL, .len = 0};
    char *addr = write_target_data((void *)str, len);
    if (addr == NULL) {
        bpf_printk("write_user_go_string: failed to copy string to userspace");
        return new_string;
    }

    // Build string struct in kernel space
    new_string.str = addr;
    new_string.len = len;

    // Copy new string struct to userspace
    void *res = write_target_data((void *)&new_string, sizeof(new_string));
    if (res == NULL) {
        new_string.len = 0;
    }

    return new_string;
}

static __always_inline void append_item_to_slice(void *new_item, u32 item_size, void *slice_user_ptr)
{
    // read the slice descriptor
    struct go_slice slice = {0};
    bpf_probe_read(&slice, sizeof(slice), slice_user_ptr);
    long res = 0;

    u64 slice_len = slice.len;
    u64 slice_cap = slice.cap;
    if (slice_len < slice_cap && slice.array != NULL)
    {
        // Room available on current array, append to the underlying array
        res = bpf_probe_write_user(slice.array + (item_size * slice_len), new_item, item_size);
    }
    else
    { 
        // No room on current array - try to copy new one of size item_size * (len + 1)
        u32 alloc_size = item_size * slice_len;
        if (alloc_size >= MAX_SLICE_ARRAY_SIZE)
        {
            return;
        }
    
        // Get temporary buffer
        u32 index = 0;
        struct slice_array_buff *map_buff = bpf_map_lookup_elem(&slice_array_buff_map, &index);
        if (!map_buff)
        {
            return;
        }
    
        unsigned char *new_slice_array = map_buff->buff;
        // help the verifier
        alloc_size &= (MAX_SLICE_ARRAY_SIZE - 1);
        if (alloc_size + item_size > MAX_SLICE_ARRAY_SIZE)
        {
            // No room for new item
            return;
        }
        // Append to buffer
        if (slice.array != NULL) {
            bpf_probe_read_user(new_slice_array, alloc_size, slice.array);
            bpf_printk("append_item_to_slice: copying %d bytes to new array from address 0x%llx", alloc_size, slice.array);
        }
        copy_byte_arrays(new_item, new_slice_array + alloc_size, item_size);

        // Copy buffer to userspace
        u32 new_array_size = alloc_size + item_size;

        void *new_array = write_target_data(new_slice_array, new_array_size);
        if (new_array == NULL)
        {
            bpf_printk("append_item_to_slice: failed to copy new array to userspace");
            return;
        }

        // Update array pointer of slice
        slice.array = new_array;
        slice.cap++;
    }

    // Update len
    slice.len++;
    long success = bpf_probe_write_user(slice_user_ptr, &slice, sizeof(slice));
    if (success != 0)
    {
        bpf_printk("append_item_to_slice: failed to update slice in userspace");
        return;
    }
}

static __always_inline bool get_go_string_from_user_ptr(void *user_str_ptr, char *dst, u64 max_len)
{
    if (user_str_ptr == NULL)
    {
        return false;
    }

    struct go_string user_str = {0};
    long success = 0;
    success = bpf_probe_read(&user_str, sizeof(struct go_string), user_str_ptr);
    if (success != 0 || user_str.len < 1)
    {
        return false;
    }

    u64 size_to_read = user_str.len > max_len ? max_len : user_str.len;
    success = bpf_probe_read(dst, size_to_read, user_str.str);
    if (success != 0)
    {
        return false;
    }

    return true;
}
#endif
