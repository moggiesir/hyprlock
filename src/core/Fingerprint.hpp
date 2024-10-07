#pragma once

#include <memory>
#include <optional>
#include <string>

class CFingerprint {
  public:
    struct SPamConversationState {
        std::string             message  = "";
    };

    CFingerprint();

    void                       start();
    bool                       isAuthenticated();
    std::optional<std::string> getLastMessage();

  private:
    SPamConversationState m_sConversationState;

    bool                  m_bAuthenticated = false;

    std::string           m_sPamModule;

    bool                  auth();
};

inline std::unique_ptr<CFingerprint> g_pFingerprint;
