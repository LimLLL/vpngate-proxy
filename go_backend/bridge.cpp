// C ABI for Go; OpenVPN handshakes, crypto and TUN stay in the official C++ Core.

#include "bridge.h"

#include "client/ovpncli.hpp"

#include <json/json.h>

#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <string>

class NativeClient final : public openvpn::ClientAPI::OpenVPNClient
{
  public:
    NativeClient(uint32_t callback_id, VPNEventCallback events, VPNLogCallback logs)
        : callback_id_(callback_id), events_(events), logs_(logs)
    {
    }

    void event(const openvpn::ClientAPI::Event &event) override
    {
        events_(callback_id_, event.name.c_str(), event.info.c_str(), event.error, event.fatal);
    }

    void log(const openvpn::ClientAPI::LogInfo &info) override
    {
        logs_(callback_id_, info.text.c_str());
    }

    bool socket_protect(openvpn_io::detail::socket_type, std::string, bool) override
    {
        // Profiles use route-nopull, so the transport keeps the physical default route.
        return true;
    }

    bool pause_on_connection_timeout() override
    {
        return false;
    }

    void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent &) override
    {
        // App-specific SSO for other providers is outside this VPNGate prototype.
    }

    void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest &request) override
    {
        request.error = true;
        request.errorText = "External PKI is not implemented in this prototype";
    }

    void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest &request) override
    {
        request.error = true;
        request.errorText = "External PKI is not implemented in this prototype";
    }

  private:
    uint32_t callback_id_;
    VPNEventCallback events_;
    VPNLogCallback logs_;
};

struct VPNHandle
{
    VPNHandle(uint32_t id, VPNEventCallback events, VPNLogCallback logs)
        : client(std::make_unique<NativeClient>(id, events, logs))
    {
    }

    std::unique_ptr<NativeClient> client;
};

namespace
{
char *copy_string(const std::string &value)
{
    char *result = new char[value.size() + 1];
    std::memcpy(result, value.c_str(), value.size() + 1);
    return result;
}

VPNStatus status_from(const openvpn::ClientAPI::Status &status)
{
    return {status.error, copy_string(status.status), copy_string(status.message)};
}

VPNStatus failure(const char *code, const char *message)
{
    return {1, copy_string(code), copy_string(message)};
}

template <typename Func>
VPNStatus guarded(Func &&func)
{
    try
    {
        return status_from(func());
    }
    catch (const std::exception &e)
    {
        // No C++ exception may propagate through a Go/C call boundary.
        return failure("OPENVPN3_EXCEPTION", e.what());
    }
    catch (...)
    {
        return failure("OPENVPN3_EXCEPTION", "unknown native exception");
    }
}
} // namespace

extern "C" {

VPNHandle *vpn_client_new(uint32_t id, VPNEventCallback events, VPNLogCallback logs)
{
    if (!events || !logs)
        return nullptr;
    static std::once_flag initialized;
    try
    {
        std::call_once(initialized, [] { openvpn::ClientAPI::OpenVPNClientHelper::init_process(); });
        return new VPNHandle{id, events, logs};
    }
    catch (...)
    {
        return nullptr;
    }
}

void vpn_client_delete(VPNHandle *handle)
{
    delete handle;
}

VPNStatus vpn_client_configure(VPNHandle *handle, const char *profile,
                               const char *username, const char *password,
                               int connect_timeout)
{
    if (!handle || !profile || !username || !password || connect_timeout < 1)
        return failure("INVALID_ARGUMENT", "invalid client configuration arguments");
    return guarded([&]() -> VPNStatus {
        openvpn::ClientAPI::Config config;
        config.content = profile;
        config.connTimeout = connect_timeout;
        config.autologinSessions = false;
        config.compressionMode = "no";
        config.enableLegacyAlgorithms = true;
        config.enableNonPreferredDCAlgorithms = true;
        config.tunPersist = false;
        const auto evaluation = handle->client->eval_config(config);
        if (evaluation.error)
            return failure("OPENVPN3_PROFILE_ERROR", evaluation.message.c_str());
        openvpn::ClientAPI::ProvideCreds credentials;
        credentials.username = username;
        credentials.password = password;
        return handle->client->provide_creds(credentials);
    });
}

VPNStatus vpn_client_connect(VPNHandle *handle)
{
    return handle ? guarded([&] { return handle->client->connect(); })
                  : failure("INVALID_ARGUMENT", "null client handle");
}

VPNStatus vpn_client_stop(VPNHandle *handle)
{
    return handle ? guarded([&] {
                        handle->client->stop();
                        return openvpn::ClientAPI::Status{};
                    })
                  : failure("INVALID_ARGUMENT", "null client handle");
}

char *vpn_client_connection_info_json(VPNHandle *handle)
{
    if (!handle)
        return nullptr;
    Json::Value root;
    const auto info = handle->client->connection_info();
    root["defined"] = info.defined;
    root["user"] = info.user;
    root["serverHost"] = info.serverHost;
    root["serverPort"] = info.serverPort;
    root["serverProto"] = info.serverProto;
    root["serverIp"] = info.serverIp;
    root["vpnIp4"] = info.vpnIp4;
    root["vpnIp6"] = info.vpnIp6;
    root["vpnMtu"] = info.vpnMtu;
    root["gw4"] = info.gw4;
    root["gw6"] = info.gw6;
    root["clientIp"] = info.clientIp;
    root["tunName"] = info.tunName;
    Json::StreamWriterBuilder builder;
    return copy_string(Json::writeString(builder, root));
}

const char *vpn_platform(void)
{
    static const std::string platform = openvpn::ClientAPI::OpenVPNClientHelper::platform();
    return platform.c_str();
}

void vpn_status_free(VPNStatus *status)
{
    if (status)
    {
        delete[] status->code;
        delete[] status->message;
        status->code = nullptr;
        status->message = nullptr;
    }
}

void vpn_string_free(char *value)
{
    delete[] value;
}

} // extern "C"
