/*
 Copyright (c) 2013-2021 Etsy

 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated documentation
 files (the "Software"), to deal in the Software without
 restriction, including without limitation the rights to use,
 copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following
 conditions:

 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
*/

#define CORE_PRIVATE

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "apr_strings.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char **docroot;
    const char *original;
} realdoc_request_save_struct;

typedef struct {
    apr_time_t realpath_every;
    unsigned int use_readlink;
    const char *prefix_path;
    apr_thread_mutex_t *mutex;
} realdoc_config_struct;

typedef struct {
    const char *resolved_docroot;
    unsigned int is_resolved;
} realdoc_request_config;

typedef struct
{
    char path[PATH_MAX];
    apr_time_t timestamp;
    const char *original_docroot; // Store original with the cache entry
} cache_entry;

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, rec, "[realdoc] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERROR(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, rec, "[realdoc] " fmt, ##__VA_ARGS__)

module AP_MODULE_DECLARE_DATA realdoc_module;

static void *create_realdoc_config(apr_pool_t *p, server_rec *d)
{
    realdoc_config_struct *conf = (realdoc_config_struct *) apr_pcalloc(p, sizeof(realdoc_config_struct));

    if (!conf) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, d, "[realdoc] Failed to allocate realdoc config");
        return NULL;
    }

    apr_status_t rv = apr_thread_mutex_create(&conf->mutex, APR_THREAD_MUTEX_UNNESTED, p);
    if (rv != APR_SUCCESS) {
        char errbuf[256];
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, d, "[realdoc] Failed to create mutex: %s",
                    apr_strerror(rv, errbuf, sizeof(errbuf)));
        return NULL;
    }

    return conf;
}

static void *merge_realdoc_config(apr_pool_t *p, void *basev, void *addv)
{
    realdoc_config_struct *base = (realdoc_config_struct *) basev;
    realdoc_config_struct *add = (realdoc_config_struct *) addv;
    realdoc_config_struct *new = (realdoc_config_struct *)
                            apr_palloc(p, sizeof(realdoc_config_struct));

    new->realpath_every = add->realpath_every ? add->realpath_every : base->realpath_every;
    new->use_readlink = add->use_readlink ? add->use_readlink : base->use_readlink;
    new->prefix_path = add->prefix_path ? add->prefix_path : base->prefix_path;
    new->mutex = base->mutex;
    return new;
}

static const char *set_realdoc_config(cmd_parms *cmd, void *dummy, const char *arg)
{
    char *endptr = NULL;
    realdoc_config_struct *conf = (realdoc_config_struct *) ap_get_module_config(cmd->server->module_config,
                      &realdoc_module);

    if (!conf) {
        return apr_psprintf(cmd->pool,
                     "realdoc configuration not initialized");
    }

    conf->realpath_every = strtol(arg, &endptr, 10);

    if ((*arg == '\0') || (*endptr != '\0')) {
        return apr_psprintf(cmd->pool,
                     "Invalid value for realdoc directive %s, expected integer",
                     cmd->directive->directive);
    }

    return NULL;
}

/*
 * Return path with first symlink resolved, if any.
 * Buffer buf must be null-terminated and can be
 * pre-filled with the path to skip ahead to avoid
 * having to stat those path components.
 */
int first_link(char *path, char *buf)
{
    struct stat st;
    char *p = path;

    if (!*path) return 0;
    if (*path != '/') {
        errno = ENOENT;
        return -1;
    }

    if (strlen(buf)) {
        char *skip = strstr(path, buf);
        if (skip == path) {
            p = path + strlen(buf) - 1;
        } else {
            *buf = '\0';
        }
    }

    while((p = strchr(p+1, '/'))) {
        int bytes;
        *p = '\0';
        strcpy(buf, path);
        *p = '/';
        if (lstat(buf, &st) < 0) return -1;
        if (S_ISLNK(st.st_mode)) {
            char lbuf[PATH_MAX];
            if ((bytes = readlink(buf, lbuf, sizeof(lbuf))) < 0) return -1;
            lbuf[bytes] = '\0';
            if (lbuf[0] == '/') {
                strncpy(buf, lbuf, bytes+1);
            } else {
                // For a relative symlink backtrack and replace
                char *pb = strchr(buf, '\0');
                while (*--pb != '/');
                *++pb = '\0';
                strncat(buf, lbuf, bytes+1);
            }
            strcat(buf, p);
            return 0;
        }
    }

    // No symlinks were found, just return the original path in the buffer
    strcpy(buf, path);
    return 0;
}

static const char *set_realdoc_readlink(cmd_parms *cmd, void *dummy, const char *arg)
{
    realdoc_config_struct *conf = (realdoc_config_struct *) ap_get_module_config(cmd->server->module_config,
                      &realdoc_module);

    if (!conf) {
        return apr_psprintf(cmd->pool,
                     "realdoc configuration not initialized");
    }

    if (*arg == '/') {
        conf->use_readlink = 1;
        conf->prefix_path = arg;
    } else if (strcasecmp(arg, "On") == 0) {
        conf->use_readlink = 1;
        conf->prefix_path = NULL;
    } else {
        conf->use_readlink = 0;
    }

    return NULL;
}

static const command_rec realdoc_cmds[] =
{
    AP_INIT_TAKE1("RealpathEvery", set_realdoc_config, NULL, RSRC_CONF,
     "Run the realpath at most every so many seconds"),
    AP_INIT_TAKE1("UseReadlink", set_realdoc_readlink, NULL, RSRC_CONF,
     "Use readlink instead of realpath to just get the first symlink target (On|Off|<path>)"),
    {NULL}
};

static realdoc_request_config *get_realdoc_request_config(request_rec *r)
{
    realdoc_request_config *reqc;

    // walk to main request
    while (r->main != NULL) {
        //AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "realdoc: request %d has main request %d ***", r, r->main);
        r = r->main;
    }

    // walk to first request of internal redirect chain
    while (r->prev != NULL) {
        //AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "realdoc: request %d has previous request %d ***", r, r->prev);
        r = r->prev;
    }

    reqc = ap_get_module_config(r->request_config, &realdoc_module);
    if (!reqc) {
        //AP_LOG_ERROR(APLOG_MARK, APLOG_DEBUG, 0, r->server, "realdoc: variable reqc does not exists.... creating ! pid=%d request_rec=%d @request_config='%d'", getpid(), r, &(r->request_config));
        reqc = (realdoc_request_config *) apr_pcalloc(r->pool, sizeof(realdoc_request_config));
        reqc->is_resolved = 0;
        ap_set_module_config(r->request_config, &realdoc_module, reqc);
    }

    return reqc;
}

static int realdoc_hook_handler(request_rec *r) {
    core_server_config *core_conf = ap_get_module_config(r->server->module_config, &core_module);
    realdoc_config_struct *realdoc_conf = (realdoc_config_struct *) ap_get_module_config(r->server->module_config, &realdoc_module);

    // Skip if RealpathEvery is not configured
    if (!realdoc_conf->realpath_every) {
        return DECLINED;
    }

    realdoc_request_config *req_cfg = get_realdoc_request_config(r);
    if(req_cfg->is_resolved) {
        return DECLINED;
    }

    apr_time_t current_request_time = apr_time_sec(r->request_time);
    const char *cache_key = apr_psprintf(r->pool, "%s:%u:realdoc_cache",
                                       ap_get_server_name(r), ap_get_server_port(r));

    cache_entry *cached_data;

    // Lock for thread safety
    apr_status_t mutex_rv = apr_thread_mutex_lock(realdoc_conf->mutex);
    if (mutex_rv != APR_SUCCESS) {
        AP_LOG_ERROR(r, "Failed to acquire mutex");
        return DECLINED;
    }

    // Always restore original docroot from previous cache entry if it exists
    apr_pool_userdata_get((void **)&cached_data, cache_key, r->server->process->pool);
    if (cached_data && cached_data->original_docroot) {
        core_conf->ap_document_root = cached_data->original_docroot;
    }

    // Check if we need to resolve the path (cache miss or expired)
    if (!cached_data ||
        (current_request_time - cached_data->timestamp) > realdoc_conf->realpath_every) {

        // Allocate new cache entry if needed
        if (!cached_data) {
            cached_data = apr_pcalloc(r->server->process->pool, sizeof(cache_entry));
            if (!cached_data) {
                AP_LOG_ERROR(r, "Failed to allocate memory for cache entry");
                apr_thread_mutex_unlock(realdoc_conf->mutex);
                return DECLINED;
            }
        }

        // Store original docroot before modification
        cached_data->original_docroot = core_conf->ap_document_root;

        // Resolve the path
        if (realdoc_conf->use_readlink) {
            if (realdoc_conf->prefix_path) {
                strcpy(cached_data->path, realdoc_conf->prefix_path);
            }
            if (-1 == first_link((char *)core_conf->ap_document_root, cached_data->path)) {
                AP_LOG_ERROR(r, "Error from readlink: %d. Original docroot: %s",
                           errno, core_conf->ap_document_root);
                apr_thread_mutex_unlock(realdoc_conf->mutex);
                return DECLINED;
            }
        } else {
            if (NULL == realpath(core_conf->ap_document_root, cached_data->path)) {
                AP_LOG_ERROR(r, "Error from realpath: %d. Original docroot: %s",
                           errno, core_conf->ap_document_root);
                apr_thread_mutex_unlock(realdoc_conf->mutex);
                return DECLINED;
            }
        }

        // Update cache timestamp and store in pool userdata
        cached_data->timestamp = current_request_time;
        apr_pool_userdata_set(cached_data, cache_key, NULL, r->server->process->pool);

        AP_LOG_DEBUG(r, "Updated cache - Original docroot: %s. Resolved: %s",
                    core_conf->ap_document_root, cached_data->path);
    } else {
        AP_LOG_DEBUG(r, "Using cached data - Original docroot: %s. Resolved: %s",
                     core_conf->ap_document_root, cached_data->path);
    }

    // Set the resolved path in request config
    req_cfg->is_resolved = 1;
    req_cfg->resolved_docroot = apr_pstrdup(r->pool, cached_data->path);

    AP_LOG_DEBUG(r, "Using docroot - Original: %s, Resolved: %s",
                core_conf->ap_document_root, cached_data->path);

    apr_status_t unlock_rv = apr_thread_mutex_unlock(realdoc_conf->mutex);
    if (unlock_rv != APR_SUCCESS) {
        AP_LOG_ERROR(r, "Failed to release mutex");
    }
    return DECLINED;
}

static int realdoc_translate_name(request_rec *r)
{
    realdoc_request_config *req_cfg = get_realdoc_request_config(r);
    if(!req_cfg->is_resolved) {
        return DECLINED;
    }

    ap_set_document_root(r, req_cfg->resolved_docroot);

    return DECLINED;
}

void realdoc_register_hook(apr_pool_t *p)
{
    static const char *const aszPre[] = {"mod_alias.c", "mod_userdir.c", NULL};

    ap_hook_post_read_request(realdoc_hook_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_translate_name(realdoc_translate_name, aszPre, NULL, APR_HOOK_MIDDLE);
}

AP_MODULE_DECLARE_DATA module realdoc_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                   /* create per-directory config structure */
    NULL,                   /* merge per-directory config structures */
    create_realdoc_config,  /* create per-server config structure */
    merge_realdoc_config,   /* merge per-server config structures */
    realdoc_cmds,           /* command apr_table_t */
    realdoc_register_hook   /* register hooks */
};
