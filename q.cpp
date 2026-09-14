/*
 * Copyright (C) 2004-2026 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <znc/Modules.h>
#include <znc/User.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/Server.h>
#include <znc/Chan.h>

#ifndef Q_DEBUG_COMMUNICATION
#define Q_DEBUG_COMMUNICATION 0
#endif

namespace {
constexpr int kDefaultRetryInterval = 30;

bool PackHex(const CString& sHex, CString& sPackedHex) {
    if (sHex.length() % 2) return false;
    sPackedHex.clear();
    for (size_t i = 0; i < sHex.length() / 2; i++) {
        unsigned int value;
        if (sscanf(sHex.c_str() + i * 2, "%02x", &value) != 1 ||
            value > 0xff)
            return false;
        sPackedHex += static_cast<unsigned char>(value);
    }
    return true;
}

CString HmacSha256(const CString& sKey, const CString& sData) {
    CString sRealKey = sKey;
    if (sKey.length() > 64)
        PackHex(sKey.SHA256(), sRealKey);

    CString sOuterKey, sInnerKey;
    for (unsigned int i = 0; i < 64; i++) {
        char r = (i < sRealKey.length()) ? sRealKey[i] : '\0';
        sOuterKey += static_cast<char>(r ^ 0x5c);
        sInnerKey += static_cast<char>(r ^ 0x36);
    }

    CString sInnerHash;
    PackHex(CString(sInnerKey + sData).SHA256(), sInnerHash);
    return CString(sOuterKey + sInnerHash).SHA256();
}

bool IsQuakeNet(CIRCNetwork* pNetwork) {
    CIRCSock* pIRCSock = pNetwork->GetIRCSock();
    if (!pIRCSock) return false;
    CString sNetwork = pIRCSock->GetISupport("NETWORK");
    if (!sNetwork.empty() && sNetwork.Equals("QuakeNet"))
        return true;
    CServer* pServer = pNetwork->GetCurrentServer();
    if (!pServer) return false;
    return pServer->GetName().AsLower().find("quakenet") != CString::npos;
}

struct QConfig {
    CString username;
    CString password;
    bool useCloakedHost{true};
    bool useChallenge{true};
    bool requestPerms{false};
    bool joinOnInvite{true};
    bool joinAfterCloaked{true};
    bool enabled{true};
    unsigned int retryInterval{kDefaultRetryInterval};
};

struct QSession {
    bool authed{};
    bool authPending{};
    bool requestedChallenge{};
    bool requestedWhoami{};
    bool catchResponse{};
    bool cloaked{};

    void Reset() { *this = QSession{}; }
};

struct BoolSettingDesc {
    const char* nvKey;    // NV / config key
    const char* cmd;      // lowercase command and web form name
    const char* display;  // human readable label
    const char* setMsg;   // confirmation message for the Set command
    bool QConfig::*member;
    bool def;
    bool web;             // include in the web UI
    const char* tooltip;  // web UI tooltip
};

static const BoolSettingDesc kBoolSettings[] = {
    {"QModuleEnabled", "enabled", "Enabled", "QModuleEnabled set",
     &QConfig::enabled, true, false, nullptr},
    {"UseCloakedHost", "usecloakedhost", "UseCloakedHost",
     "UseCloakedHost set", &QConfig::useCloakedHost, true, true,
     "Whether to cloak your hostname (+x) automatically on connect."},
    {"UseChallenge", "usechallenge", "UseChallenge", "UseChallenge set",
     &QConfig::useChallenge, true, true,
     "Whether to use the CHALLENGEAUTH mechanism to avoid sending "
     "passwords in cleartext."},
    {"RequestPerms", "requestperms", "RequestPerms", "RequestPerms set",
     &QConfig::requestPerms, false, true,
     "Whether to request voice/op from Q on join/devoice/deop."},
    {"JoinOnInvite", "joinoninvite", "JoinOnInvite", "JoinOnInvite set",
     &QConfig::joinOnInvite, true, true,
     "Whether to join channels when Q invites you."},
    {"JoinAfterCloaked", "joinaftercloaked", "JoinAfterCloaked",
     "JoinAfterCloaked set", &QConfig::joinAfterCloaked, true, true,
     "Whether to delay joining channels until after you are cloaked."},
};
}  // namespace

class CQModule;

class CRetryTimer final : public CTimer {
  public:
    explicit CRetryTimer(CModule* pModule, unsigned int uInterval)
        : CTimer(pModule, uInterval, 0, "RetryTimer",
                 "Retries authentication and cloaking until successful") {}

  protected:
    void RunJob() override;

  public:
    CRetryTimer(const CRetryTimer&) = delete;
    CRetryTimer& operator=(const CRetryTimer&) = delete;
};

class CQModule final : public CModule {
  public:
    MODCONSTRUCTOR(CQModule) {
        AddHelpCommand();

        AddCommand("Set", t_d("<setting> <value>"),
                   t_d("Changes the value of the given setting."),
                   [=, this](const CString& sLine) { SetCommand(sLine); });

        AddCommand("Get", "",
                   t_d("Prints out the current configuration."),
                   [=, this](const CString& sLine) { GetCommand(sLine); });

        AddCommand("Status", "",
                   t_d("Prints the current status of the module."),
                   [=, this](const CString& sLine) { StatusCommand(sLine); });

        AddCommand("Cloak", "",
                   t_d("Tries to set usermode +x to hide your real "
                       "hostname."),
                   [=, this](const CString& sLine) { CloakCommand(sLine); });

        AddCommand("Auth", t_d("[<username> <password>]"),
                   t_d("Tries to authenticate you with Q. Only HMAC-SHA-256 "
                        "CHALLENGEAUTH is supported (HMAC-SHA-1, HMAC-MD5, "
                        "and plain AUTH are insecure). Both parameters "
                        "are optional."),
                   [=, this](const CString& sLine) { AuthCommand(sLine); });

        AddCommand("Update", "",
                   t_d("Re-requests the current user information from Q."),
                   [=, this](const CString& sLine) { UpdateCommand(sLine); });
    }

    ~CQModule() override {
        StopRetryTimer();
    }

    CQModule(const CQModule&) = delete;
    CQModule(CQModule&&) = delete;
    CQModule& operator=(const CQModule&) = delete;
    CQModule& operator=(CQModule&&) = delete;

    friend class CRetryTimer;

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        LoadSettings(sArgs);

        ResetSession();

        if (IsIRCConnected()) {
            const auto* pIRCSock = GetNetwork()->GetIRCSock();
            if (pIRCSock) {
                const auto& scUserModes = pIRCSock->GetUserModes();
                if (scUserModes.find('x') != scUserModes.end())
                    m_sess.cloaked = true;
            }

            if (IsQuakeNet(GetNetwork())) {
                if (GetNV("UseCloakedHost").empty()) {
                    if (!m_sess.cloaked)
                        PutModule(t_s(
                            "Notice: Your host will be cloaked the next "
                            "time you reconnect to IRC. "
                            "If you want to cloak your host now, "
                            "/msg *q Cloak. "
                            "You can set your preference "
                            "with /msg *q Set UseCloakedHost true/false."));
                    m_cfg.useCloakedHost = true;
                    SetUseCloakedHost(m_cfg.useCloakedHost);
                    m_cfg.joinAfterCloaked = true;
                    SetJoinAfterCloaked(m_cfg.joinAfterCloaked);
                }
                if (m_cfg.enabled) {
                    StartRetryTimer();
                }
            }
        } else {
            SetUseCloakedHost(m_cfg.useCloakedHost);
        }

        return true;
    }

    void OnIRCDisconnected() override { ResetSession(); }

    void OnIRCConnected() override {
        if (m_cfg.enabled && IsQuakeNet(GetNetwork())) {
            StartRetryTimer();
        }
    }

    EModRet OnNumericMessage(CNumericMessage& msg) override {
        if (msg.GetCode() == 396 &&
            msg.GetParam(1).find("users.quakenet.org") != CString::npos) {
            m_sess.cloaked = true;
            PutModule(
                t_s("Cloak successful: Your hostname is now cloaked."));

            if (ShouldJoinAfterCloak()) {
                TryJoinDeferred();
                PutModule(t_s("Channels are being joined now."));
            }
            StopRetryTimerIfComplete();
        }
        return CONTINUE;
    }

    EModRet OnPrivTextMessage(CTextMessage& msg) override {
        return HandleMessage(msg.GetNick(), msg.GetText());
    }

    EModRet OnPrivNoticeMessage(CNoticeMessage& msg) override {
        return HandleMessage(msg.GetNick(), msg.GetText());
    }

    EModRet OnJoining(CChan&) override {
        if (!m_sess.authed)
            return HALT;
        if (!m_sess.cloaked && ShouldJoinAfterCloak())
            return HALT;
        return CONTINUE;
    }

    void OnJoinMessage(CJoinMessage& msg) override {
        CChan* pChan = GetNetwork()->FindChan(msg.GetTarget());
        if (m_cfg.requestPerms && pChan && IsSelf(msg.GetNick()))
            HandleNeed(*pChan, "ov");
    }

    void OnChanPermission3(const CNick* pOpNick, const CNick& Nick,
                           CChan& Channel, char cMode, bool bAdded,
                           bool bNoChange) override {
        if (!m_cfg.requestPerms || !IsSelf(Nick) || bAdded || bNoChange)
            return;
        if (!pOpNick || !IsSelf(*pOpNick)) {
            if (cMode == 'o')
                HandleNeed(Channel, "o");
            else if (cMode == 'v')
                HandleNeed(Channel, "v");
        }
    }

    EModRet OnInvite(const CNick& Nick, const CString& sChan) override {
        if (!Nick.NickEquals("Q") ||
            !Nick.GetHost().Equals("CServe.quakenet.org"))
            return CONTINUE;
        if (m_cfg.joinOnInvite && m_sess.authed && m_sess.cloaked)
            GetNetwork()->AddChan(sChan, false);
        return CONTINUE;
    }

    CString GetWebMenuTitle() override { return "Q"; }

    bool OnWebRequest(CWebSock& WebSock, const CString& sPageName,
                      CTemplate& Tmpl) override {
        if (sPageName == "index") {
            bool bSubmitted = (WebSock.GetParam("submitted").ToInt() != 0);

            if (bSubmitted) {
                CString FormUsername = WebSock.GetParam("user");
                if (!FormUsername.empty()) SetUsername(FormUsername);

                CString FormPassword = WebSock.GetParam("password");
                if (!FormPassword.empty()) SetPassword(FormPassword);

                for (const auto& d : kBoolSettings)
                    if (d.web)
                        SetBoolSetting(d, WebSock.GetParam(d.cmd).ToBool());
            }

            Tmpl["Username"] = m_cfg.username;

            for (const auto& d : kBoolSettings)
                if (d.web)
                    AddWebOption(Tmpl, d.cmd, d.display, t_s(d.tooltip),
                                 m_cfg.*(d.member));

            if (bSubmitted) {
                WebSock.GetSession()->AddSuccess(
                    t_s("Changes have been saved!"));
            }

            return true;
        }

        return false;
    }

  private:
    QSession m_sess;
    QConfig m_cfg;
    MCString m_msChanModes;
    CTimer* m_pRetryTimer{};

    void ResetSession() {
        m_sess.Reset();
        StopRetryTimer();
    }

    bool ShouldJoinAfterCloak() const {
        return m_cfg.useCloakedHost && m_cfg.joinAfterCloaked;
    }

    void StopRetryTimerIfComplete() {
        if (m_sess.authed && (m_sess.cloaked || !m_cfg.useCloakedHost))
            StopRetryTimer();
    }

    void TryJoinDeferred() {
        if (!m_sess.authed) return;
        if (ShouldJoinAfterCloak() && !m_sess.cloaked) return;
        GetNetwork()->JoinChans();
    }

    void AdvanceSession() {
        if (m_cfg.useCloakedHost && !m_sess.cloaked)
            Cloak();
        if (m_sess.cloaked && ShouldJoinAfterCloak())
            TryJoinDeferred();
        StopRetryTimerIfComplete();
    }

    void StartRetryTimer() {
        RemTimer("RetryTimer");
        delete m_pRetryTimer;
        m_pRetryTimer = nullptr;
        if (m_cfg.enabled && IsQuakeNet(GetNetwork()) &&
            !m_cfg.username.empty() && !m_cfg.password.empty() &&
            (!m_sess.authed ||
             (m_cfg.useCloakedHost && !m_sess.cloaked))) {
            m_pRetryTimer = new CRetryTimer(this, m_cfg.retryInterval);
            AddTimer(m_pRetryTimer);
        }
    }

    void StopRetryTimer() {
        RemTimer("RetryTimer");
        delete m_pRetryTimer;
        m_pRetryTimer = nullptr;
    }

    bool RequireConnected() {
        if (!IsIRCConnected()) {
            PutModule(t_s("Error: You are not connected to IRC."));
            return false;
        }
        return true;
    }

    bool RequireQuakeNet() {
        if (!IsQuakeNet(GetNetwork())) {
            PutModule(t_s("Error: This module only works on QuakeNet."));
            return false;
        }
        return true;
    }

    void RetryAll() {
        if (IsIRCConnected() && IsQuakeNet(GetNetwork())) {
            if (!m_sess.authed) {
                if (!m_sess.authPending) {
                    PutModule(t_s("Auth: Retrying authentication..."));
                    Auth();
                }
            } else if (m_cfg.useCloakedHost && !m_sess.cloaked) {
                PutModule(t_s("Cloak: Retrying..."));
                Cloak();
            }
        }
    }

    void PutQ(const CString& sMessage) {
        PutIRC("PRIVMSG Q@CServe.quakenet.org :" + sMessage);
#if Q_DEBUG_COMMUNICATION
        PutModule("[ZNC --> Q] " + sMessage);
#endif
    }

    void Cloak() {
        if (m_sess.cloaked) return;

        CIRCSock* pIRCSock = GetNetwork()->GetIRCSock();
        if (!pIRCSock) return;

        PutModule(
            t_s("Cloak: Trying to cloak your hostname, setting +x..."));
        PutIRC("MODE " + pIRCSock->GetNick() + " +x");
    }

    void WhoAmI() {
        m_sess.requestedWhoami = true;
        PutQ("WHOAMI");
    }

    void Auth(const CString& sUsername = "",
              const CString& sPassword = "") {
        if (m_sess.authed || m_sess.authPending) return;

        if (!sUsername.empty()) SetUsername(sUsername);
        if (!sPassword.empty()) SetPassword(sPassword);

        if (m_cfg.username.empty() || m_cfg.password.empty()) {
            PutModule(
                t_s("You have to set a username and password to use "
                    "this module! See 'help' for details."));
            return;
        }

        m_sess.authPending = true;
        if (m_cfg.useChallenge) {
            PutModule(t_s("Auth: Requesting CHALLENGE..."));
            m_sess.requestedChallenge = true;
            PutQ("CHALLENGE");
        } else {
            PutModule(t_s("Auth: Sending AUTH request... (warning: cleartext password)"));
            PutQ("AUTH " + m_cfg.username + " " + m_cfg.password);
        }
    }

    void ChallengeAuth(CString sChallenge) {
        if (m_sess.authed) return;

        CString sUsername = m_cfg.username.AsLower()
                                .Replace_n("[", "{")
                                .Replace_n("]", "}")
                                .Replace_n("\\", "|");
        CString sPasswordHash = m_cfg.password.Left(10).SHA256();
        CString sKey =
            CString(sUsername + ":" + sPasswordHash).SHA256();
        CString sResponse = HmacSha256(sKey, sChallenge);

#if Q_DEBUG_COMMUNICATION
        PutModule(
            t_f("CHALLENGEAUTH: lcuser={1}")(sUsername));
        PutModule(
            t_f("CHALLENGEAUTH: pw10hash={1}")(sPasswordHash));
        PutModule(t_f("CHALLENGEAUTH: key={1}")(sKey));
        PutModule(
            t_f("CHALLENGEAUTH: challenge={1}")(sChallenge));
        PutModule(
            t_f("CHALLENGEAUTH: response={1}")(sResponse));
#endif

        PutModule(t_s("Auth: Received challenge, sending "
                      "CHALLENGEAUTH request..."));
        PutQ("CHALLENGEAUTH " + m_cfg.username + " " + sResponse +
             " HMAC-SHA-256");
    }

    EModRet HandleMessage(const CNick& Nick, CString sMessage) {
        if (!Nick.NickEquals("Q") ||
            !Nick.GetHost().Equals("CServe.quakenet.org"))
            return CONTINUE;

        sMessage.Trim();

#if Q_DEBUG_COMMUNICATION
        PutModule("[ZNC <-- Q] " + sMessage);
#endif

        if (sMessage.find(
                "WHOAMI is only available to authed users") !=
            CString::npos) {
            HandleWhoamiNotAuthed();
        } else if (sMessage.find("Information for user") !=
                   CString::npos) {
            HandleWhoamiInfo();
        } else if (m_sess.requestedWhoami && sMessage.WildCmp("#*")) {
            HandleWhoamiChannel(sMessage);
        } else if (m_sess.requestedWhoami && m_sess.catchResponse &&
                   (sMessage.Equals("End of list.") ||
                    sMessage.Equals("account, or HELLO to create an "
                                    "account."))) {
            return HandleWhoamiEnd();
        } else if (sMessage.Equals(
                       "Username or password incorrect.")) {
            return HandleLoginFailed();
        } else if (sMessage.WildCmp(
                       "You are now logged in as *.")) {
            return HandleLoginSuccess(sMessage);
        } else if (m_sess.requestedChallenge &&
                   sMessage.Token(0).Equals("CHALLENGE")) {
            return HandleChallengeResponse(sMessage);
        }

        return !m_sess.catchResponse && GetUser()->IsUserAttached()
                   ? CONTINUE
                   : HALT;
    }

    void HandleNeed(const CChan& Channel, const CString& sPerms) {
        MCString::iterator it =
            m_msChanModes.find(Channel.GetName());
        if (it == m_msChanModes.end()) return;
        CString sModes = it->second;

        bool bMaster =
            (sModes.find("m") != CString::npos) ||
            (sModes.find("n") != CString::npos);

        if (sPerms.find("o") != CString::npos) {
            bool bOp = (sModes.find("o") != CString::npos);
            bool bAutoOp = (sModes.find("a") != CString::npos);
            if (bMaster || bOp) {
                if (!bAutoOp) {
                    PutModule(
                        t_f("RequestPerms: Requesting op on {1}")(
                            Channel.GetName()));
                    PutQ("OP " + Channel.GetName());
                }
                return;
            }
        }

        if (sPerms.find("v") != CString::npos) {
            bool bVoice = (sModes.find("v") != CString::npos);
            bool bAutoVoice = (sModes.find("g") != CString::npos);
            if (bMaster || bVoice) {
                if (!bAutoVoice) {
                    PutModule(
                        t_f("RequestPerms: Requesting voice on {1}")(
                            Channel.GetName()));
                    PutQ("VOICE " + Channel.GetName());
                }
                return;
            }
        }
    }

    bool IsIRCConnected() const {
        CIRCSock* pIRCSock = GetNetwork()->GetIRCSock();
        return pIRCSock && pIRCSock->IsAuthed();
    }

    bool IsSelf(const CNick& Nick) const {
        return Nick.NickEquals(GetNetwork()->GetCurNick());
    }

    bool LoadBoolSetting(const CString& sKey, bool bDefault) const {
        CString sVal = GetNV(sKey);
        return sVal.empty() ? bDefault : sVal.ToBool();
    }

    unsigned int LoadUIntSetting(const CString& sKey,
                                 unsigned int uDefault) const {
        CString sVal = GetNV(sKey);
        return sVal.empty() ? uDefault : sVal.ToUInt();
    }

    void LoadSettings(const CString& sArgs) {
        if (!sArgs.empty()) {
            SetUsername(sArgs.Token(0));
            SetPassword(sArgs.Token(1));
        } else {
            m_cfg.username = GetNV("Username");
            m_cfg.password = LoadPassword();
        }

        for (const auto& d : kBoolSettings)
            m_cfg.*(d.member) = LoadBoolSetting(d.nvKey, d.def);
        m_cfg.retryInterval =
            LoadUIntSetting("RetryInterval", kDefaultRetryInterval);

        SetNV("UseChallenge", CString(m_cfg.useChallenge));
        SetNV("RequestPerms", CString(m_cfg.requestPerms));
        SetNV("JoinOnInvite", CString(m_cfg.joinOnInvite));
        SetNV("JoinAfterCloaked", CString(m_cfg.joinAfterCloaked));
    }

    void AddWebOption(CTemplate& Tmpl, const CString& sName,
                      const CString& sDisplay,
                      const CString& sTooltip, bool bChecked) {
        CTemplate& o = Tmpl.AddRow("OptionLoop");
        o["Name"] = sName;
        o["DisplayName"] = sDisplay;
        o["Tooltip"] = sTooltip;
        o["Checked"] = CString(bChecked);
    }

    void CloakCommand(const CString& sLine) {
        if (!RequireConnected() || !RequireQuakeNet()) return;
        if (!m_sess.cloaked)
            Cloak();
        else
            PutModule(t_s("Error: You are already cloaked!"));
    }

    void AuthCommand(const CString& sLine) {
        if (!RequireConnected() || !RequireQuakeNet()) return;
        if (!m_sess.authed)
            Auth(sLine.Token(1), sLine.Token(2));
        else
            PutModule(t_s("Error: You are already authed!"));
    }

    void UpdateCommand(const CString& sLine) {
        if (!RequireConnected() || !RequireQuakeNet()) return;
        WhoAmI();
        PutModule(t_s("Update requested."));
    }

    void GetCommand(const CString& sLine) {
        CTable Table;
        Table.AddColumn(t_s("Setting"));
        Table.AddColumn(t_s("Value"));

        auto addRow = [this, &Table](const CString& sSetting,
                                     const CString& sValue) {
            Table.AddRow();
            Table.SetCell(t_s("Setting"), sSetting);
            Table.SetCell(t_s("Value"), sValue);
        };

        addRow(t_s("Enabled"), CString(m_cfg.enabled));
        addRow(t_s("Username"), m_cfg.username);
        addRow(t_s("Password"), CString("*****"));
        for (const auto& d : kBoolSettings)
            if (d.web)
                addRow(t_s(d.display), CString(m_cfg.*(d.member)));
        addRow(t_s("RetryInterval (seconds)"),
               CString(m_cfg.retryInterval));

        PutModule(Table);
    }

    void StatusCommand(const CString& sLine) {
        PutModule(IsIRCConnected() ? t_s("Connected: yes")
                                   : t_s("Connected: no"));
        PutModule(m_sess.cloaked ? t_s("Cloaked: yes")
                                 : t_s("Cloaked: no"));
        PutModule(m_sess.authed ? t_s("Authenticated: yes")
                                : t_s("Authenticated: no"));
        PutModule(m_cfg.enabled ? t_s("Enabled: yes")
                                : t_s("Enabled: no"));
    }

    void SetCommand(const CString& sLine) {
        CString sSetting = sLine.Token(1).AsLower();
        CString sValue = sLine.Token(2);
        if (sSetting.empty() || sValue.empty()) {
            PutModule(t_s("Syntax: Set <setting> <value>"));
            return;
        }

        if (sSetting == "username") {
            SetUsername(sValue);
            PutModule(t_s("Username set"));
        } else if (sSetting == "password") {
            SetPassword(sValue);
            PutModule(t_s("Password set"));
        } else if (sSetting == "retryinterval") {
            if (sValue.ToUInt() >= 10) {
                SetRetryInterval(sValue.ToUInt());
                PutModule(t_f("RetryInterval set to {1} seconds")(
                    sValue));
            } else {
                PutModule(t_s(
                    "RetryInterval must be >= 10 seconds"));
            }
        } else {
            for (const auto& d : kBoolSettings) {
                if (sSetting == CString(d.cmd)) {
                    SetBoolSetting(d, sValue.ToBool());
                    PutModule(t_s(d.setMsg));
                    return;
                }
            }
            PutModule(t_f("Unknown setting: {1}")(sSetting));
        }
    }

    void HandleWhoamiNotAuthed() {
        m_sess.authed = false;
        m_sess.authPending = false;
        Auth();
        m_sess.catchResponse = m_sess.requestedWhoami;
    }

    void HandleWhoamiInfo() {
        m_sess.authed = true;
        m_sess.authPending = false;
        m_msChanModes.clear();
        m_sess.catchResponse = m_sess.requestedWhoami;
        m_sess.requestedWhoami = true;
        AdvanceSession();
    }

    void HandleWhoamiChannel(const CString& sMessage) {
        CString sChannel = sMessage.Token(0);
        CString sFlags =
            sMessage.Token(1, true).Trim_n().TrimLeft_n("+");
        m_msChanModes[sChannel] = sFlags;
    }

    EModRet HandleWhoamiEnd() {
        m_sess.requestedWhoami = m_sess.catchResponse = false;
        return HALT;
    }

    EModRet HandleLoginFailed() {
        m_sess.authed = false;
        m_sess.authPending = false;
        PutModule(t_s("Authentication failed: Username or password "
                      "incorrect."));
        return HALT;
    }

    EModRet HandleLoginSuccess(const CString& sMessage) {
        m_sess.authed = true;
        m_sess.authPending = false;
        PutModule(
            t_f("Authentication successful: {1}")(sMessage));
        WhoAmI();
        AdvanceSession();
        return HALT;
    }

    EModRet HandleChallengeResponse(const CString& sMessage) {
        m_sess.requestedChallenge = false;
#if Q_DEBUG_COMMUNICATION
        PutModule(
            t_f("CHALLENGE response: {1}")(sMessage));
#endif
        if (sMessage.find("not available once you have authed") !=
            CString::npos) {
            m_sess.authed = true;
            m_sess.authPending = false;
            AdvanceSession();
        } else if (sMessage.find("HMAC-SHA-256") !=
                   CString::npos) {
            ChallengeAuth(sMessage.Token(1));
        } else {
            PutModule(t_s(
                "Auth failed: Q does not offer HMAC-SHA-256. "
                "HMAC-SHA-1, HMAC-MD5, and plain AUTH are insecure "
                "and not implemented. The retry timer will try again."));
            m_sess.authPending = false;
        }
        return HALT;
    }

    CString GetEncryptionKey() const {
        return CBlowfish::MD5(GetUser()->GetUsername() + ":" + GetSavePath());
    }

    CString EncryptPassword(const CString& sPlaintext) const {
        CBlowfish c(GetEncryptionKey(), BF_ENCRYPT);
        return c.Crypt(sPlaintext);
    }

    CString DecryptPassword(const CString& sCiphertext) const {
        CBlowfish c(GetEncryptionKey(), BF_DECRYPT);
        return c.Crypt(sCiphertext);
    }

    CString LoadPassword() {
        CString sPassword = GetNV("PasswordEnc");
        if (!sPassword.empty()) {
            return DecryptPassword(sPassword);
        }
        sPassword = GetNV("Password");
        if (!sPassword.empty()) {
            PutModule(t_s("Upgraded Q password to encrypted on-disk storage."));
            SetNV("PasswordEnc", EncryptPassword(sPassword));
            DelNV("Password");
        }
        return sPassword;
    }

    void SavePassword(const CString& sPlaintext) {
        SetNV("PasswordEnc", EncryptPassword(sPlaintext));
        DelNV("Password");
    }

    void SetUsername(const CString& sUsername) {
        m_cfg.username = sUsername;
        SetNV("Username", sUsername);
        StartRetryTimer();
    }

    void SetPassword(const CString& sPassword) {
        m_cfg.password = sPassword;
        SavePassword(sPassword);
        StartRetryTimer();
    }

    void SetUseCloakedHost(const bool bUseCloakedHost) {
        m_cfg.useCloakedHost = bUseCloakedHost;
        SetNV("UseCloakedHost", CString(bUseCloakedHost));

        if (!m_sess.cloaked && m_cfg.useCloakedHost && IsIRCConnected())
            Cloak();
    }

    void SetBoolSetting(const BoolSettingDesc& d, const bool bValue) {
        m_cfg.*(d.member) = bValue;
        SetNV(d.nvKey, CString(bValue));

        if (CString(d.cmd).Equals("usecloakedhost")) {
            if (!m_sess.cloaked && m_cfg.useCloakedHost && IsIRCConnected())
                Cloak();
            StartRetryTimer();
        } else if (CString(d.cmd).Equals("enabled")) {
            if (!m_cfg.enabled)
                StopRetryTimer();
            else if (IsIRCConnected())
                StartRetryTimer();
        }
    }

    void SetJoinAfterCloaked(const bool bJoinAfterCloaked) {
        m_cfg.joinAfterCloaked = bJoinAfterCloaked;
        SetNV("JoinAfterCloaked", CString(bJoinAfterCloaked));
    }

    void SetRetryInterval(unsigned int uInterval) {
        m_cfg.retryInterval = uInterval;
        SetNV("RetryInterval", CString(uInterval));
        if (m_pRetryTimer)
            StartRetryTimer();
    }
};

template <>
void TModInfo<CQModule>(CModInfo& Info) {
    Info.SetWikiPage("Q");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText(
        Info.t_s("Please provide your username and password for Q."));
}

NETWORKMODULEDEFS(CQModule, t_s("Auths you with QuakeNet's Q bot."))

void CRetryTimer::RunJob() {
    auto* pQModule = dynamic_cast<CQModule*>(GetModule());
    if (pQModule && pQModule->GetNetwork()) pQModule->RetryAll();
}
