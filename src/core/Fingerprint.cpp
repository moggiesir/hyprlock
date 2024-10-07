#include "Fingerprint.hpp"
#include "hyprlock.hpp"
#include "../helpers/Log.hpp"
#include "src/config/ConfigManager.hpp"

#include <filesystem>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>
#if __has_include(<security/pam_misc.h>)
#include <security/pam_misc.h>
#endif

#include <cstring>
#include <thread>

int fingerprint_conv(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
    const auto           CONVERSATIONSTATE = (CFingerprint::SPamConversationState*)appdata_ptr;

    for (int i = 0; i < num_msg; ++i) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON: Debug::log(LOG, "PAM_PROMPT: {}", msg[i]->msg); break;
            case PAM_ERROR_MSG: {
                Debug::log(ERR, "PAM error: {}", msg[i]->msg); 
                const auto MSG = std::string(msg[i]->msg); 
                CONVERSATIONSTATE->message = std::move(MSG);
                g_pHyprlock->enqueueForceUpdateTimers();
            } break;
            case PAM_TEXT_INFO: Debug::log(LOG, "PAM text: {}", msg[i]->msg); break;
        }
    }

    return PAM_SUCCESS;
}

CFingerprint::CFingerprint() {
    static auto* const PFINGERPRINT_DISABLED = (Hyprlang::INT* const*)g_pConfigManager->getValuePtr("general:disable_fingerprint");
    if (**PFINGERPRINT_DISABLED) {
        Debug::log(LOG, "Fingerprint disabled");
        m_sPamModule = "";
        return;
    }
    static auto* const PPAMMODULE = (Hyprlang::STRING*)(g_pConfigManager->getValuePtr("general:fingerprint_pam_module"));
    m_sPamModule                  = *PPAMMODULE;

    if (!std::filesystem::exists(std::filesystem::path("/etc/pam.d/") / m_sPamModule)) {
        Debug::log(ERR, "Pam module \"/etc/pam.d/{}\" does not exist! Fingerprint auth could not be started", m_sPamModule);
        m_sPamModule = "";
    }
}

static void fingerprintCheckTimerCallback(std::shared_ptr<CTimer> self, void* data) {
    g_pHyprlock->onPasswordCheckTimer();
}

void CFingerprint::start() {
    Debug::log(LOG, "starting fingerprint auth");
    if (m_sPamModule.empty())
        return;
    std::thread([this]() {
        // For grace or SIGUSR1 unlocks
        if (g_pHyprlock->isUnlocked())
            return;

        const auto AUTHENTICATED = auth();
        m_bAuthenticated         = AUTHENTICATED;

        if (!AUTHENTICATED) {
            m_sConversationState.message = "Too many failed attempts - fingerprint auth disabled";
            g_pHyprlock->enqueueForceUpdateTimers();
            return;
        }

        // For SIGUSR1 unlocks
        if (g_pHyprlock->isUnlocked())
            return;

        g_pHyprlock->addTimer(std::chrono::milliseconds(1), fingerprintCheckTimerCallback, nullptr);
    }).detach();
}

bool CFingerprint::auth() {
    int ret = PAM_AUTHINFO_UNAVAIL;
    while (ret != PAM_SUCCESS && ret != PAM_MAXTRIES) {
        const pam_conv localConv   = {fingerprint_conv, (void*)&m_sConversationState};
        pam_handle_t*  handle      = NULL;
        auto           uidPassword = getpwuid(getuid());

        ret = pam_start(m_sPamModule.c_str(), uidPassword->pw_name, &localConv, &handle);

        if (ret != PAM_SUCCESS) {
            Debug::log(ERR, "auth: pam_start failed for {}", m_sPamModule);
            return false;
        }

        ret = pam_authenticate(handle, 0);
        pam_end(handle, ret);
        handle = nullptr;

        Debug::log(LOG, "fingerprint: auth result {} {}", ret);
    }

    if (ret != PAM_SUCCESS) {
        const auto FAIL_TEXT = "pam_authenticate failed";
        Debug::log(ERR, "auth: {} for {}", FAIL_TEXT, m_sPamModule);
        return false;
    }

    return true;
}

bool CFingerprint::isAuthenticated() {
    return m_bAuthenticated;
}

std::optional<std::string> CFingerprint::getLastMessage() {
    return m_sConversationState.message.empty() ? std::nullopt : std::optional(m_sConversationState.message);
}
