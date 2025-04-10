// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

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

MAP_BUCKET_DEFINITION(go_string_t, go_slice_t)

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
    __uint(value_size, sizeof(MAP_BUCKET_TYPE(go_string_t, go_slice_t)));
    __uint(max_entries, 1);
} golang_mapbucket_storage_map SEC(".maps");

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

// Helper function to iterate through Go maps
static __always_inline long iterate_go_map(void *headers_ptr, void (*process_entry)(MAP_BUCKET_TYPE(go_string_t, go_slice_t) *, u64, void *), void *data) {
    long res;
    if (!headers_ptr) {
        return -1;
    }

    u64 headers_count = 0;
    res = bpf_probe_read(&headers_count, sizeof(headers_count), headers_ptr);
    if (res < 0 || headers_count == 0) {
        return -1;
    }

    unsigned char log_2_bucket_count;
    res = bpf_probe_read(&log_2_bucket_count, sizeof(log_2_bucket_count), headers_ptr + 9);
    if (res < 0) {
        return -1;
    }

    u64 bucket_count = 1 << log_2_bucket_count;
    void *header_buckets;
    res = bpf_probe_read(&header_buckets, sizeof(header_buckets), (void*)(headers_ptr + buckets_ptr_pos));
    if (res < 0) {
        return -1;
    }

    u32 map_id = 0;
    MAP_BUCKET_TYPE(go_string_t, go_slice_t) *map_value = bpf_map_lookup_elem(&golang_mapbucket_storage_map, &map_id);
    if (!map_value) {
        return -1;
    }

    for (u64 j = 0; j < MAX_BUCKETS && j < bucket_count; j++) {
        res = bpf_probe_read(map_value, sizeof(MAP_BUCKET_TYPE(go_string_t, go_slice_t)), 
                          header_buckets + (j * sizeof(MAP_BUCKET_TYPE(go_string_t, go_slice_t))));
        if (res < 0) {
            continue;
        }
        
        for (u64 i = 0; i < 8; i++) {
            if (map_value->tophash[i] == 0) {
                continue;
            }
            
            process_entry(map_value, i, data);
        }
    }
    
    return 0;
}

// Data structure for traceparent header extraction
struct traceparent_extraction_data {
    struct span_context *parent_span_context;
    bool found;
};

// Process function for traceparent extraction
static __always_inline void process_traceparent_entry(MAP_BUCKET_TYPE(go_string_t, go_slice_t) *map_value, u64 i, void *data) {
    struct traceparent_extraction_data *extraction_data = (struct traceparent_extraction_data *)data;
    long res;
    
    if (map_value->keys[i].len != W3C_KEY_LENGTH) {
        return;
    }
    
    char current_header_key[W3C_KEY_LENGTH];
    res = bpf_probe_read(current_header_key, sizeof(current_header_key), map_value->keys[i].str);
    if (res < 0) {
        return;
    }
    
    if (!bpf_memcmp(current_header_key, "traceparent", W3C_KEY_LENGTH) && 
        !bpf_memcmp(current_header_key, "Traceparent", W3C_KEY_LENGTH)) {
        return;
    }
    
    void *traceparent_header_value_ptr = map_value->values[i].array;
    struct go_string traceparent_header_value_go_str;
    res = bpf_probe_read(&traceparent_header_value_go_str, sizeof(traceparent_header_value_go_str), traceparent_header_value_ptr);
    if (res < 0 || traceparent_header_value_go_str.len != W3C_VAL_LENGTH) {
        return;
    }
    
    char traceparent_header_value[W3C_VAL_LENGTH];
    res = bpf_probe_read(&traceparent_header_value, sizeof(traceparent_header_value), traceparent_header_value_go_str.str);
    if (res < 0) {
        return;
    }
    
    w3c_string_to_span_context(traceparent_header_value, extraction_data->parent_span_context);
    extraction_data->found = true;
}

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
    
    struct traceparent_extraction_data extraction_data = {
        .parent_span_context = parent_span_context,
        .found = false
    };
    
    iterate_go_map(headers_ptr, process_traceparent_entry, &extraction_data);
    
    return extraction_data.found ? 0 : -1;
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

// Process function for header value extraction
static __always_inline void process_header_entry(MAP_BUCKET_TYPE(go_string_t, go_slice_t) *map_value, u64 i, void *data) {
    struct header_extraction_data *extraction_data = (struct header_extraction_data *)data;
    long res;
    
    // Check if this is the header we're looking for
    char current_header_key[64] = {0};
    int header_key_len = map_value->keys[i].len < 64 ? map_value->keys[i].len : 63;
    if (header_key_len <= 0) {
        bpf_printk("XMB2: header key length is less than 0");
        return;
    }
    
    // TODO: Review this
    // Bound the header_key_len to avoid unbounded memory access
    if (header_key_len > 64) {
        header_key_len = 64;
    }
    
    res = bpf_probe_read(current_header_key, header_key_len, map_value->keys[i].str);
    if (res < 0) {
        bpf_printk("XMB3: failed to read header key");
        return;
    }
    
    // Print debug information about the header key comparison
    bpf_printk("XMB444: Header comparison: current_key=%s, target_key=%s, key_len=%d", 
               current_header_key, extraction_data->header_name, header_key_len);
    if (bpf_memicmp(current_header_key, extraction_data->header_name, header_key_len) != 0) {
        bpf_printk("XMB4: header key does not match");
        return;
    }
    
    void *header_value_ptr = map_value->values[i].array;
    struct go_string header_value_go_str;
    res = bpf_probe_read(&header_value_go_str, sizeof(header_value_go_str), header_value_ptr);
    if (res < 0 || header_value_go_str.len <= 0) {
        bpf_printk("XMB5: header value length is less than 0");
        return;
    }
    
    int value_len = header_value_go_str.len < extraction_data->max_len ? 
                   header_value_go_str.len : extraction_data->max_len - 1;
    
    res = bpf_probe_read(extraction_data->output, value_len, header_value_go_str.str);
    if (res < 0) {
        bpf_printk("XMB6: failed to read header value");
        return;
    }
    
    bpf_printk("XMB7: header value read successfully: name=%s, found=%d, value_len=%d", 
               extraction_data->header_name, extraction_data->found, value_len);
    extraction_data->output[value_len] = '\0';
    extraction_data->found = true;
    // Print the extraction data for debugging
    bpf_printk("XMB8: Extraction data - header_name: %s, found: %d, max_len: %d", 
               extraction_data->header_name, extraction_data->found, extraction_data->max_len);
    
    // Print the actual extracted value
    bpf_printk("XMB9: Extracted value: %s", extraction_data->output);
}

static __always_inline void extract_header_value(void *headers_ptr, const char *header_name, char *output, int max_len) {
    if (!headers_ptr) {
        return;
    }
    
    // TODO
    // If using swiss maps, rely on pre-parsed headers
    if (swiss_maps_used) {
        bpf_printk("XMB1: swiss maps used");
        // For Swiss maps we currently don't extract arbitrary headers
        // This would require extending the existing parsing in uprobe_textproto_Reader_readContinuedLineSlice_Returns
        return;
    }
    
    struct header_extraction_data extraction_data = {
        .header_name = header_name,
        .output = output,
        .max_len = max_len,
        .found = false
    };
    
    iterate_go_map(headers_ptr, process_header_entry, &extraction_data);
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
        
        bpf_printk("XMB22: header_key: %s", header_key);
        bpf_probe_read_str(span->headers[i].key, HEADER_KEY_MAX_LEN, header_key);
        bpf_printk("XMB10: header_key: %s", span->headers[i].key);
        extract_header_value(headers_ptr, req_header_name, 
            span->headers[i].value, HEADER_VALUE_MAX_LEN);
        bpf_printk("XMB0: Request header captured: %s=%s", span->headers[i].key, span->headers[i].value);
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
