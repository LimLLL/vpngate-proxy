#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VPNHandle VPNHandle;

typedef struct {
    int error;
    char *code;
    char *message;
} VPNStatus;

typedef void (*VPNEventCallback)(uint32_t id, const char *name, const char *info,
                                 int error, int fatal);
typedef void (*VPNLogCallback)(uint32_t id, const char *text);

VPNHandle *vpn_client_new(uint32_t id, VPNEventCallback event_cb, VPNLogCallback log_cb);
void vpn_client_delete(VPNHandle *handle);
VPNStatus vpn_client_configure(VPNHandle *handle, const char *profile,
                               const char *username, const char *password,
                               int connect_timeout);
VPNStatus vpn_client_connect(VPNHandle *handle);
VPNStatus vpn_client_stop(VPNHandle *handle);
char *vpn_client_connection_info_json(VPNHandle *handle);
const char *vpn_platform(void);
void vpn_status_free(VPNStatus *status);
void vpn_string_free(char *value);

#ifdef __cplusplus
}
#endif
