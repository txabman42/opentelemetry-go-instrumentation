// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "common.h"
#include "arguments.h"
#include "trace/span_context.h"
#include "go_context.h"
#include "go_types.h"
#include "uprobe.h"
#include "trace/span_output.h"
#include "trace/start_span.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PATH_MAX_LEN 128
#define MAX_BUCKETS 8
#define METHOD_MAX_LEN 8
#define MAX_CONCURRENT 50
#define REMOTE_ADDR_MAX_LEN 256
#define HOST_MAX_LEN 256
#define PROTO_MAX_LEN 8
#define HEADER_KEY_MAX_LEN 32
#define HEADER_VALUE_MAX_LEN 32
#define MAX_HEADERS_PER_TYPE 2

struct header_attribute
{
    char key[HEADER_KEY_MAX_LEN];
    char value[HEADER_VALUE_MAX_LEN];
};

struct http_server_span_t
{
    BASE_SPAN_PROPERTIES
    u64 status_code;
    char method[METHOD_MAX_LEN];
    char path[PATH_MAX_LEN];
    char path_pattern[PATH_MAX_LEN];
    char remote_addr[REMOTE_ADDR_MAX_LEN];
    char host[HOST_MAX_LEN];
    char proto[PROTO_MAX_LEN];
    struct header_attribute headers[MAX_HEADERS_PER_TYPE];
};

struct uprobe_data_t
{
    struct http_server_span_t span;
    // bpf2go doesn't support pointers fields
    // saving the response pointer in the entry probe
    // and using it in the return probe
    u64 resp_ptr;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *);
    __type(value, struct uprobe_data_t);
    __uint(max_entries, MAX_CONCURRENT);
} http_server_uprobes SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *);
    __type(value, struct span_context);
    __uint(max_entries, MAX_CONCURRENT);
} http_server_context_headers SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct uprobe_data_t));
    __uint(max_entries, 1);
} http_server_uprobe_storage_map SEC(".maps");

// Injected in init
volatile const u64 method_ptr_pos;
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 ctx_ptr_pos;
volatile const u64 headers_ptr_pos;
volatile const u64 buckets_ptr_pos;
volatile const u64 req_ptr_pos;
volatile const u64 status_code_pos;
volatile const u64 remote_addr_pos;
volatile const u64 host_pos;
volatile const u64 proto_pos;

// A flag indicating whether pattern handlers are supported
volatile const bool pattern_path_supported;
// In case pattern handlers are supported the following offsets will be used:
volatile const u64 req_pat_pos;
volatile const u64 pat_str_pos;
// A flag indicating whether the Go version is using swiss maps
volatile const bool swiss_maps_used;

// Headers configuration injected from Go
struct headers_config {
    char request_headers[MAX_HEADERS_PER_TYPE][HEADER_KEY_MAX_LEN];
    u32 request_header_count;
    char response_headers[MAX_HEADERS_PER_TYPE][HEADER_VALUE_MAX_LEN];
    u32 response_header_count;
};
volatile const struct headers_config headers_config;

// Data structure for traceparent header extraction
struct traceparent_extraction_data {
    struct span_context *parent_span_context;
    bool found;
};

// Extracts the span context from the request headers by looking for the 'traceparent' header.
// Fills the parent_span_context with the extracted span context.
// Returns 0 on success, negative value on error.
static __always_inline long extract_context_from_req_headers_go_map(void *headers_ptr_ptr, struct span_context *parent_span_context)
{
    void *headers_ptr;
    long res;
    res = bpf_probe_read(&headers_ptr, sizeof(headers_ptr), headers_ptr_ptr);
    if (res < 0) {
        return res;
    }
    
    // Use find_key_in_go_map to find the traceparent header
    struct map_key_find_result result = {0};
    res = find_key_in_go_map(headers_ptr, "traceparent", W3C_KEY_LENGTH, buckets_ptr_pos, &result);
    
    if (res < 0 || !result.found) {
        // Try with capitalized variant as well
        res = find_key_in_go_map(headers_ptr, "Traceparent", W3C_KEY_LENGTH, buckets_ptr_pos, &result);
        if (res < 0 || !result.found) {
            return -1;
        }
    }
    
    // Extract the value if the key was found
    if (result.found && result.value_ptr != NULL) {
        go_slice_t *value_slice = (go_slice_t *)result.value_ptr;
        if (value_slice->array == NULL || value_slice->len != W3C_VAL_LENGTH) {
            return -1;
        }
        
        char traceparent_header_value[W3C_VAL_LENGTH];
        res = bpf_probe_read(traceparent_header_value, sizeof(traceparent_header_value), value_slice->array);
        if (res < 0) {
            return -1;
        }
        
        w3c_string_to_span_context(traceparent_header_value, parent_span_context);
        return 0;
    }
    
    return -1;
}

static __always_inline long extract_context_from_req_headers_pre_parsed(void *key, struct span_context *parent_span_context) {
    struct span_context *parsed_header_context = bpf_map_lookup_elem(&http_server_context_headers, &key);
    if (!parsed_header_context) {
        return -1;
    }

    __builtin_memcpy(parent_span_context, parsed_header_context, sizeof(struct span_context));
    return 0;
}

static __always_inline long extract_context_from_req_headers(void *key, struct span_context *parent_span_context) {
    if (swiss_maps_used) {
        return extract_context_from_req_headers_pre_parsed(key, parent_span_context);
    }
    return extract_context_from_req_headers_go_map(key, parent_span_context);
}

static __always_inline void read_go_string(void *base, int offset, char *output, int maxLen, const char *errorMsg) {
    void *ptr = (void *)(base + offset);
    if (!get_go_string_from_user_ptr(ptr, output, maxLen)) {
        bpf_printk("Failed to get %s", errorMsg);
    }
}

// Data structure for header value extraction
struct header_extraction_data {
    const char *header_name;
    char *output;
    int max_len;
    bool found;
};


static __always_inline void extract_header_value(void *headers_ptr, const char *header_name, int header_name_len, char *output) {
    if (!headers_ptr) {
        return;
    }
    
    // If using swiss maps, rely on pre-parsed headers
    if (swiss_maps_used) {
        bpf_printk("XMB1: swiss maps used");
        // For Swiss maps we currently don't extract arbitrary headers
        // This would require extending the existing parsing in uprobe_textproto_Reader_readContinuedLineSlice_Returns
        return;
    }
    
    // Use find_key_in_go_map to find the header
    struct map_key_find_result result = {0};
    // We don't use strlen here since it's not available in BPF
    // Instead, use a constant maximum header name length (32 bytes)
    // The actual comparison in find_key_in_go_map will handle shorter strings properly
    long res = find_key_in_go_map(headers_ptr, header_name, header_name_len, buckets_ptr_pos, &result);
    // Print debug information about the map search
    bpf_printk("XMB2: find_key_in_go_map result: %ld", res);
    
    if (res >= 0) {
        bpf_printk("XMB2.1: found=%d, bucket=%d, entry=%d", 
                  result.found, result.bucket_index, result.entry_index);
        
        if (result.found && result.key_ptr != NULL) {
            go_string_t *key_str = (go_string_t *)result.key_ptr;
            bpf_printk("XMB2.2: key len=%d", key_str->len);
        }
    }

    if (res < 0 || !result.found || result.value_ptr == NULL) {
        bpf_printk("XMB3: header not found (%d): %s", res, header_name);
        return;
    }
    
    // Extract the value
    go_slice_t *value_slice = (go_slice_t *)result.value_ptr;
    if (value_slice->array == NULL || value_slice->len <= 0) {
        bpf_printk("XMB5: header value length is less than or equal to 0");
        return;
    }
    
    int value_len = value_slice->len < HEADER_VALUE_MAX_LEN ? value_slice->len : HEADER_VALUE_MAX_LEN - 1;
    
    res = bpf_probe_read(output, value_len, value_slice->array);
    if (res < 0) {
        bpf_printk("XMB6: failed to read header value");
        return;
    }
    
    output[value_len] = '\0';
    bpf_printk("XMB9: Extracted value for %s: %s", header_name, output);
}

static __always_inline void capture_request_headers(void *req_ptr, struct http_server_span_t *span) {
    void *headers_ptr;
    bpf_probe_read(&headers_ptr, sizeof(headers_ptr), (void*)(req_ptr + headers_ptr_pos));
    if (!headers_ptr) {
        return;
    }
    
    for (int i = 0; i < MAX_HEADERS_PER_TYPE; i++) {
        if (i >= headers_config.request_header_count) {
            break;
        }
        
        char header_key[HEADER_KEY_MAX_LEN] = "request_";
        char req_header_name[32];
        u32 j;
        for (j = 0; j < 32; j++) {
            char c;
            bpf_probe_read(&c, 1, (char *)&headers_config.request_headers[i][j]);
            req_header_name[j] = c;
            if (c == '\0') break;
        }
        
        bpf_printk("XMB11: req_header_name: %s", req_header_name);
        
        // Prepare the full header key with prefix
        u32 prefix_len = 8; // Length of "request_"
        
        // Safe concatenation - copy the header name after the prefix
        for (j = 0; j < HEADER_KEY_MAX_LEN - prefix_len - 1 || req_header_name[j] == '\0'; j++) {
            header_key[prefix_len + j] = req_header_name[j];
        }
        // Ensure null termination
        header_key[prefix_len + j] = '\0';
        
        // bpf_printk("XMB23: header_key: %s", header_key);
        bpf_probe_read_str(span->headers[i].key, HEADER_KEY_MAX_LEN, header_key);
        // bpf_printk("XMB10: header_key: %s", span->headers[i].key);
        
        // // Calculate length manually instead of using strlen
        u32 req_header_name_len = 0;
        for (req_header_name_len = 0; req_header_name_len < 32; req_header_name_len++) {
            if (req_header_name[req_header_name_len] == '\0') {
                break;
            }
        }
        
        extract_header_value(headers_ptr, req_header_name, req_header_name_len, 
            span->headers[i].value);
        // bpf_printk("XMB0: Request header captured: %s=%s", span->headers[i].key, span->headers[i].value);
    }
}

// This instrumentation attaches uprobe to the following function:
// func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request)
SEC("uprobe/serverHandler_ServeHTTP")
int uprobe_serverHandler_ServeHTTP(struct pt_regs *ctx)
{
    struct go_iface go_context = {0};
    get_Go_context(ctx, 4, ctx_ptr_pos, false, &go_context);
    void *key = (void *)GOROUTINE(ctx);
    void *httpReq_ptr = bpf_map_lookup_elem(&http_server_uprobes, &key);
    if (httpReq_ptr != NULL)
    {
        bpf_printk("uprobe/HandlerFunc_ServeHTTP already tracked with the current request");
        return 0;
    }

    u32 map_id = 0;
    struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&http_server_uprobe_storage_map, &map_id);
    if (uprobe_data == NULL)
    {
        bpf_printk("uprobe/HandlerFunc_ServeHTTP: http_server_span is NULL");
        return 0;
    }

    __builtin_memset(uprobe_data, 0, sizeof(struct uprobe_data_t));

    // Save response writer
    void *resp_impl = get_argument(ctx, 3);
    uprobe_data->resp_ptr = (u64)resp_impl;

    struct http_server_span_t *http_server_span = &uprobe_data->span;
    http_server_span->start_time = bpf_ktime_get_ns();

    // Propagate context
    void *req_ptr = get_argument(ctx, 4);
    start_span_params_t start_span_params = {
        .ctx = ctx,
        .go_context = &go_context,
        .psc = &http_server_span->psc,
        .sc = &http_server_span->sc,
        .get_parent_span_context_fn = extract_context_from_req_headers,
    };

    // If Go is using swiss maps, we currently rely on the uretprobe setup
    // on readContinuedLineSlice to store the parsed value in a map, which
    // we query with the same goroutine/context key.
    if (swiss_maps_used) {
        start_span_params.get_parent_span_context_arg = key;
    } else {
        start_span_params.get_parent_span_context_arg = (void*)(req_ptr + headers_ptr_pos);
    }

    start_span(&start_span_params);

    bpf_map_update_elem(&http_server_uprobes, &key, uprobe_data, 0);
    start_tracking_span(go_context.data, &http_server_span->sc);
    return 0;
}

// This instrumentation attaches uprobe to the following function:
// func (sh serverHandler) ServeHTTP(rw ResponseWriter, req *Request)
SEC("uprobe/serverHandler_ServeHTTP")
int uprobe_serverHandler_ServeHTTP_Returns(struct pt_regs *ctx) {
    u64 end_time = bpf_ktime_get_ns();
    void *key = (void *)GOROUTINE(ctx);

    struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&http_server_uprobes, &key);
    if (uprobe_data == NULL) {
        bpf_printk("uprobe/HandlerFunc_ServeHTTP_Returns: entry_state is NULL");
        bpf_map_delete_elem(&http_server_context_headers, &key);
        return 0;
    }

    struct http_server_span_t *http_server_span = &uprobe_data->span;

    void *resp_ptr = (void *)uprobe_data->resp_ptr;
    void *req_ptr = NULL;
    bpf_probe_read(&req_ptr, sizeof(req_ptr), (void *)(resp_ptr + req_ptr_pos));

    http_server_span->end_time = end_time;

    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));
    // Collect fields from response
    read_go_string(req_ptr, method_ptr_pos, http_server_span->method, sizeof(http_server_span->method), "method from request");
    if (pattern_path_supported) {
        void *pat_ptr = NULL;
        bpf_probe_read(&pat_ptr, sizeof(pat_ptr), (void *)(req_ptr + req_pat_pos));
        if (pat_ptr != NULL) {
            read_go_string(pat_ptr, pat_str_pos, http_server_span->path_pattern, sizeof(http_server_span->path), "patterned path from Request");
        }
    }
    read_go_string(url_ptr, path_ptr_pos, http_server_span->path, sizeof(http_server_span->path), "path from Request.URL");
    read_go_string(req_ptr, remote_addr_pos, http_server_span->remote_addr, sizeof(http_server_span->remote_addr), "remote addr from Request.RemoteAddr");
    read_go_string(req_ptr, host_pos, http_server_span->host, sizeof(http_server_span->host), "host from Request.Host");
    read_go_string(req_ptr, proto_pos, http_server_span->proto, sizeof(http_server_span->proto), "proto from Request.Proto");
    capture_request_headers(req_ptr, http_server_span);

    // status code
    bpf_probe_read(&http_server_span->status_code, sizeof(http_server_span->status_code), (void *)(resp_ptr + status_code_pos));

    output_span_event(ctx, http_server_span, sizeof(*http_server_span), &http_server_span->sc);

    stop_tracking_span(&http_server_span->sc, &http_server_span->psc);
    bpf_map_delete_elem(&http_server_uprobes, &key);
    bpf_map_delete_elem(&http_server_context_headers, &key);
    return 0;
}

// This instrumentation attaches uprobe to the following function:
// func (r *Reader) readContinuedLineSlice(lim int64, validateFirstLine func([]byte) error) ([]byte, error) {
SEC("uprobe/textproto_Reader_readContinuedLineSlice")
int uprobe_textproto_Reader_readContinuedLineSlice_Returns(struct pt_regs *ctx) {
    void *key = (void *)GOROUTINE(ctx);

    u64 len = (u64)GO_PARAM2(ctx);
    u8 *buf = (u8 *)GO_PARAM1(ctx);

    if (len >= (W3C_KEY_LENGTH + W3C_VAL_LENGTH + 2)) {
        u8 temp[W3C_KEY_LENGTH + W3C_VAL_LENGTH + 2];
        bpf_probe_read(temp, sizeof(temp), buf);

        if (!bpf_memicmp((const char *)temp, "traceparent: ", W3C_KEY_LENGTH + 2)) {
            struct span_context parent_span_context = {};
            w3c_string_to_span_context((char *)(temp + W3C_KEY_LENGTH + 2), &parent_span_context);            
            bpf_map_update_elem(&http_server_context_headers, &key, &parent_span_context, BPF_ANY);
        }
    }

    return 0;
}
