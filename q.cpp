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

#include <set>

#ifndef Q_DEBUG_COMMUNICATION
#define Q_DEBUG_COMMUNICATION 0
#endif

namespace {
constexpr int kDefaultRetryInterval = 30;
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

        OnIRCDisconnected();

        if (IsIRCConnected()) {
            const auto* pIRCSock = GetNetwork()->GetIRCSock();
            if (pIRCSock) {
                const auto& scUserModes = pIRCSock->GetUserModes();
                if (scUserModes.find('x') != scUserModes.end())
                    m_bCloaked = true;
            }

            if (IsQuakeNet()) {
                if (GetNV("UseCloakedHost").empty()) {
                    if (!m_bCloaked)
                        PutModule(t_s(
                            "Notice: Your host will be cloaked the next "
                            "time you reconnect to IRC. "
                            "If you want to cloak your host now, "
                            "/msg *q Cloak. "
                            "You can set your preference "
                            "with /msg *q Set UseCloakedHost true/false."));
                    m_bUseCloakedHost = true;
                    SetUseCloakedHost(m_bUseCloakedHost);
                    m_bJoinAfterCloaked = true;
                    SetJoinAfterCloaked(m_bJoinAfterCloaked);
                } else if (m_bQModuleEnabled && m_bUseChallenge) {
                    Cloak();
                }
                WhoAmI();
            }
        } else {
            SetUseCloakedHost(m_bUseCloakedHost);
        }

        return true;
    }

    void OnIRCDisconnected() override {
        m_bCloaked = false;
        m_bAuthed = false;
        m_bRequestedWhoami = false;
        m_bRequestedChallenge = false;
        m_bCatchResponse = false;
        m_bAuthPending = false;
        m_ssDeferredChannels.clear();
        StopRetryTimer();
    }

    void OnIRCConnected() override {
        if (m_bQModuleEnabled && IsQuakeNet()) {
            StartRetryTimer();
        }
    }

    EModRet OnNumericMessage(CNumericMessage& msg) override {
        if (msg.GetCode() == 396 &&
            msg.GetParam(1).find("users.quakenet.org") != CString::npos) {
            m_bCloaked = true;
            PutModule(
                t_s("Cloak successful: Your hostname is now cloaked."));

            if (m_bJoinAfterCloaked) {
                TryJoinDeferred();
            }
        }
        return CONTINUE;
    }

    EModRet OnPrivTextMessage(CTextMessage& msg) override {
        return HandleMessage(msg.GetNick(), msg.GetText());
    }

    EModRet OnPrivNoticeMessage(CNoticeMessage& msg) override {
        return HandleMessage(msg.GetNick(), msg.GetText());
    }

    EModRet OnJoining(CChan& Channel) override {
        if (!m_bAuthed) {
            m_ssDeferredChannels.insert(Channel.GetName());
            return HALT;
        }
        if (!m_bCloaked && m_bUseCloakedHost && m_bJoinAfterCloaked) {
            m_ssDeferredChannels.insert(Channel.GetName());
            return HALT;
        }
        return CONTINUE;
    }

    void OnJoinMessage(CJoinMessage& msg) override {
        CChan* pChan = GetNetwork()->FindChan(msg.GetTarget());
        if (m_bRequestPerms && pChan && IsSelf(msg.GetNick()))
            HandleNeed(*pChan, "ov");
    }

    void OnChanPermission3(const CNick* pOpNick, const CNick& Nick,
                           CChan& Channel, char cMode, bool bAdded,
                           bool bNoChange) override {
        if (!m_bRequestPerms || !IsSelf(Nick) || bAdded || bNoChange)
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
        if (m_bJoinOnInvite && m_bAuthed && m_bCloaked)
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

                SetUseCloakedHost(
                    WebSock.GetParam("usecloakedhost").ToBool());
                SetUseChallenge(
                    WebSock.GetParam("usechallenge").ToBool());
                SetRequestPerms(
                    WebSock.GetParam("requestperms").ToBool());
                SetJoinOnInvite(
                    WebSock.GetParam("joinoninvite").ToBool());
                SetJoinAfterCloaked(
                    WebSock.GetParam("joinaftercloaked").ToBool());
            }

            Tmpl["Username"] = m_sUsername;

            struct WebOpt {
                CString sName;
                CString sDisplay;
                CString sTooltip;
                bool bValue;
            };
            for (const auto& opt : {
                     WebOpt{"usecloakedhost", "UseCloakedHost",
                            t_s("Whether to cloak your hostname (+x) "
                                "automatically on connect."),
                            m_bUseCloakedHost},
                     WebOpt{"usechallenge", "UseChallenge",
                            t_s("Whether to use the CHALLENGEAUTH "
                                "mechanism to avoid sending passwords "
                                "in cleartext."),
                            m_bUseChallenge},
                     WebOpt{"requestperms", "RequestPerms",
                            t_s("Whether to request voice/op from Q "
                                "on join/devoice/deop."),
                            m_bRequestPerms},
                     WebOpt{"joinoninvite", "JoinOnInvite",
                            t_s("Whether to join channels when Q "
                                "invites you."),
                            m_bJoinOnInvite},
                     WebOpt{"joinaftercloaked", "JoinAfterCloaked",
                            t_s("Whether to delay joining channels "
                                "until after you are cloaked."),
                            m_bJoinAfterCloaked},
                 }) {
                AddWebOption(Tmpl, opt.sName, opt.sDisplay,
                             opt.sTooltip, opt.bValue);
            }

            if (bSubmitted) {
                WebSock.GetSession()->AddSuccess(
                    t_s("Changes have been saved!"));
            }

            return true;
        }

        return false;
    }

  private:
    bool m_bCloaked{};
    bool m_bAuthed{};
    bool m_bRequestedWhoami{};
    bool m_bRequestedChallenge{};
    bool m_bCatchResponse{};
    bool m_bAuthPending{};
    bool m_bQModuleEnabled{true};
    unsigned int m_uRetryInterval{kDefaultRetryInterval};
    MCString m_msChanModes;
    CTimer* m_pRetryTimer{};
    std::set<CString> m_ssDeferredChannels;

    void TryJoinDeferred() {
        if (!m_bAuthed) return;
        if (m_bUseCloakedHost && m_bJoinAfterCloaked && !m_bCloaked) return;
        m_ssDeferredChannels.clear();
        GetNetwork()->JoinChans();
    }

    void AfterAuthOrCloakSuccess() {
        if (m_bUseCloakedHost && !m_bCloaked)
            Cloak();
        if (m_bCloaked && m_bJoinAfterCloaked)
            TryJoinDeferred();
    }

    void StartRetryTimer() {
        RemTimer("RetryTimer");
        delete m_pRetryTimer;
        m_pRetryTimer = nullptr;
        if (m_bQModuleEnabled && IsQuakeNet() &&
            !m_sUsername.empty() && !m_sPassword.empty() &&
            (!m_bAuthed ||
             (m_bUseCloakedHost && !m_bCloaked))) {
            m_pRetryTimer = new CRetryTimer(this, m_uRetryInterval);
            AddTimer(m_pRetryTimer);
        }
    }

    void StopRetryTimer() {
        RemTimer("RetryTimer");
        delete m_pRetryTimer;
        m_pRetryTimer = nullptr;
    }

    bool IsQuakeNet() const {
        CIRCSock* pIRCSock = GetNetwork()->GetIRCSock();
        if (!pIRCSock) return false;
        CString sNetwork = pIRCSock->GetISupport("NETWORK");
        if (!sNetwork.empty() && sNetwork.Equals("QuakeNet"))
            return true;
        CServer* pServer = GetNetwork()->GetCurrentServer();
        if (!pServer) return false;
        return pServer->GetName().AsLower().find("quakenet") != CString::npos;
    }

    bool RequireConnected() {
        if (!IsIRCConnected()) {
            PutModule(t_s("Error: You are not connected to IRC."));
            return false;
        }
        return true;
    }

    bool RequireQuakeNet() {
        if (!IsQuakeNet()) {
            PutModule(t_s("Error: This module only works on QuakeNet."));
            return false;
        }
        return true;
    }

    void RetryAll() {
        if (IsIRCConnected() && IsQuakeNet()) {
            if (!m_bAuthed && !m_bAuthPending) {
                PutModule(t_s("Auth: Retrying authentication..."));
                Auth();
            } else if (m_bUseCloakedHost && !m_bCloaked) {
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
        if (m_bCloaked) return;

        CIRCSock* pIRCSock = GetNetwork()->GetIRCSock();
        if (!pIRCSock) return;

        PutModule(
            t_s("Cloak: Trying to cloak your hostname, setting +x..."));
        PutIRC("MODE " + pIRCSock->GetNick() + " +x");
    }

    void WhoAmI() {
        m_bRequestedWhoami = true;
        PutQ("WHOAMI");
    }

    void Auth(const CString& sUsername = "",
              const CString& sPassword = "") {
        if (m_bAuthed || m_bAuthPending) return;

        if (!sUsername.empty()) SetUsername(sUsername);
        if (!sPassword.empty()) SetPassword(sPassword);

        if (m_sUsername.empty() || m_sPassword.empty()) {
            PutModule(
                t_s("You have to set a username and password to use "
                    "this module! See 'help' for details."));
            return;
        }

        m_bAuthPending = true;
        if (m_bUseChallenge) {
            PutModule(t_s("Auth: Requesting CHALLENGE..."));
            m_bRequestedChallenge = true;
            PutQ("CHALLENGE");
        } else {
            PutModule(t_s("Auth: Sending AUTH request... (warning: cleartext password)"));
            PutQ("AUTH " + m_sUsername + " " + m_sPassword);
        }
    }

    void ChallengeAuth(CString sChallenge) {
        if (m_bAuthed) return;

        CString sUsername = m_sUsername.AsLower()
                                .Replace_n("[", "{")
                                .Replace_n("]", "}")
                                .Replace_n("\\", "|");
        CString sPasswordHash = m_sPassword.Left(10).SHA256();
        CString sKey =
            CString(sUsername + ":" + sPasswordHash).SHA256();
        CString sResponse = HMAC_SHA256(sKey, sChallenge);

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
        PutQ("CHALLENGEAUTH " + m_sUsername + " " + sResponse +
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
        } else if (m_bRequestedWhoami && sMessage.WildCmp("#*")) {
            HandleWhoamiChannel(sMessage);
        } else if (m_bRequestedWhoami && m_bCatchResponse &&
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
        } else if (m_bRequestedChallenge &&
                   sMessage.Token(0).Equals("CHALLENGE")) {
            return HandleChallengeResponse(sMessage);
        }

        return !m_bCatchResponse && GetUser()->IsUserAttached()
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

    bool PackHex(const CString& sHex, CString& sPackedHex) const {
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

    CString HMAC_SHA256(const CString& sKey,
                        const CString& sData) const {
        CString sRealKey = sKey;
        if (sKey.length() > 64)
            PackHex(sKey.SHA256(), sRealKey);

        CString sOuterKey, sInnerKey;
        for (unsigned int i = 0; i < 64; i++) {
            char r =
                (i < sRealKey.length()) ? sRealKey[i] : '\0';
            sOuterKey += static_cast<char>(r ^ 0x5c);
            sInnerKey += static_cast<char>(r ^ 0x36);
        }

        CString sInnerHash;
        PackHex(CString(sInnerKey + sData).SHA256(), sInnerHash);
        return CString(sOuterKey + sInnerHash).SHA256();
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
            m_sUsername = GetNV("Username");
            m_sPassword = LoadPassword();
        }

        m_bUseCloakedHost = LoadBoolSetting("UseCloakedHost", true);
        m_bUseChallenge = LoadBoolSetting("UseChallenge", true);
        m_bRequestPerms = LoadBoolSetting("RequestPerms", false);
        m_bJoinOnInvite = LoadBoolSetting("JoinOnInvite", true);
        m_bJoinAfterCloaked =
            LoadBoolSetting("JoinAfterCloaked", true);
        m_bQModuleEnabled = LoadBoolSetting("QModuleEnabled", true);
        m_uRetryInterval =
            LoadUIntSetting("RetryInterval", kDefaultRetryInterval);

        SetUseChallenge(m_bUseChallenge);
        SetRequestPerms(m_bRequestPerms);
        SetJoinOnInvite(m_bJoinOnInvite);
        SetJoinAfterCloaked(m_bJoinAfterCloaked);
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
        if (!m_bCloaked)
            Cloak();
        else
            PutModule(t_s("Error: You are already cloaked!"));
    }

    void AuthCommand(const CString& sLine) {
        if (!RequireConnected() || !RequireQuakeNet()) return;
        if (!m_bAuthed)
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

        struct Row { CString sSetting; CString sValue; };
        for (const auto& row : {
                 Row{t_s("Enabled"), CString(m_bQModuleEnabled)},
                 Row{t_s("Username"), m_sUsername},
                 Row{t_s("Password"), CString("*****")},
                 Row{t_s("UseCloakedHost"), CString(m_bUseCloakedHost)},
                 Row{t_s("UseChallenge"), CString(m_bUseChallenge)},
                 Row{t_s("RequestPerms"), CString(m_bRequestPerms)},
                 Row{t_s("JoinOnInvite"), CString(m_bJoinOnInvite)},
                 Row{t_s("JoinAfterCloaked"),
                     CString(m_bJoinAfterCloaked)},
                 Row{t_s("RetryInterval (seconds)"),
                     CString(m_uRetryInterval)},
             }) {
            Table.AddRow();
            Table.SetCell(t_s("Setting"), row.sSetting);
            Table.SetCell(t_s("Value"), row.sValue);
        }
        PutModule(Table);
    }

    void StatusCommand(const CString& sLine) {
        PutModule(IsIRCConnected() ? t_s("Connected: yes")
                                   : t_s("Connected: no"));
        PutModule(m_bCloaked ? t_s("Cloaked: yes")
                             : t_s("Cloaked: no"));
        PutModule(m_bAuthed ? t_s("Authenticated: yes")
                            : t_s("Authenticated: no"));
        PutModule(m_bQModuleEnabled ? t_s("Enabled: yes")
                                    : t_s("Enabled: no"));
    }

    void SetCommand(const CString& sLine) {
        CString sSetting = sLine.Token(1).AsLower();
        CString sValue = sLine.Token(2);
        if (sSetting.empty() || sValue.empty()) {
            PutModule(t_s("Syntax: Set <setting> <value>"));
        } else if (sSetting == "username") {
            SetUsername(sValue);
            PutModule(t_s("Username set"));
        } else if (sSetting == "password") {
            SetPassword(sValue);
            PutModule(t_s("Password set"));
        } else if (sSetting == "usecloakedhost") {
            SetUseCloakedHost(sValue.ToBool());
            PutModule(t_s("UseCloakedHost set"));
        } else if (sSetting == "usechallenge") {
            SetUseChallenge(sValue.ToBool());
            PutModule(t_s("UseChallenge set"));
        } else if (sSetting == "requestperms") {
            SetRequestPerms(sValue.ToBool());
            PutModule(t_s("RequestPerms set"));
        } else if (sSetting == "joinoninvite") {
            SetJoinOnInvite(sValue.ToBool());
            PutModule(t_s("JoinOnInvite set"));
        } else if (sSetting == "joinaftercloaked") {
            SetJoinAfterCloaked(sValue.ToBool());
            PutModule(t_s("JoinAfterCloaked set"));
        } else if (sSetting == "enabled") {
            SetQModuleEnabled(sValue.ToBool());
            PutModule(t_s("QModuleEnabled set"));
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
            PutModule(t_f("Unknown setting: {1}")(sSetting));
        }
    }

    void HandleWhoamiNotAuthed() {
        m_bAuthed = false;
        m_bAuthPending = false;
        Auth();
        m_bCatchResponse = m_bRequestedWhoami;
    }

    void HandleWhoamiInfo() {
        m_bAuthed = true;
        m_bAuthPending = false;
        m_msChanModes.clear();
        m_bCatchResponse = m_bRequestedWhoami;
        m_bRequestedWhoami = true;
        AfterAuthOrCloakSuccess();
    }

    void HandleWhoamiChannel(const CString& sMessage) {
        CString sChannel = sMessage.Token(0);
        CString sFlags =
            sMessage.Token(1, true).Trim_n().TrimLeft_n("+");
        m_msChanModes[sChannel] = sFlags;
    }

    EModRet HandleWhoamiEnd() {
        m_bRequestedWhoami = m_bCatchResponse = false;
        return HALT;
    }

    EModRet HandleLoginFailed() {
        m_bAuthed = false;
        m_bAuthPending = false;
        PutModule(t_s("Authentication failed: Username or password "
                      "incorrect."));
        return HALT;
    }

    EModRet HandleLoginSuccess(const CString& sMessage) {
        m_bAuthed = true;
        m_bAuthPending = false;
        PutModule(
            t_f("Authentication successful: {1}")(sMessage));
        WhoAmI();
        AfterAuthOrCloakSuccess();
        return HALT;
    }

    EModRet HandleChallengeResponse(const CString& sMessage) {
        m_bRequestedChallenge = false;
#if Q_DEBUG_COMMUNICATION
        PutModule(
            t_f("CHALLENGE response: {1}")(sMessage));
#endif
        if (sMessage.find("not available once you have authed") !=
            CString::npos) {
            m_bAuthed = true;
            m_bAuthPending = false;
            AfterAuthOrCloakSuccess();
        } else if (sMessage.find("HMAC-SHA-256") !=
                   CString::npos) {
            ChallengeAuth(sMessage.Token(1));
        } else {
            PutModule(t_s(
                "Auth failed: Q does not offer HMAC-SHA-256. "
                "HMAC-SHA-1, HMAC-MD5, and plain AUTH are insecure "
                "and not implemented. The retry timer will try again."));
            m_bAuthPending = false;
        }
        return HALT;
    }

    CString m_sUsername;
    CString m_sPassword;
    bool m_bUseCloakedHost{};
    bool m_bUseChallenge{};
    bool m_bRequestPerms{};
    bool m_bJoinOnInvite{};
    bool m_bJoinAfterCloaked{};

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
        m_sUsername = sUsername;
        SetNV("Username", sUsername);
    }

    void SetPassword(const CString& sPassword) {
        m_sPassword = sPassword;
        SavePassword(sPassword);
    }

    void SetUseCloakedHost(const bool bUseCloakedHost) {
        m_bUseCloakedHost = bUseCloakedHost;
        SetNV("UseCloakedHost", CString(bUseCloakedHost));

        if (!m_bCloaked && m_bUseCloakedHost && IsIRCConnected())
            Cloak();
    }

    void SetUseChallenge(const bool bUseChallenge) {
        m_bUseChallenge = bUseChallenge;
        SetNV("UseChallenge", CString(bUseChallenge));
    }

    void SetRequestPerms(const bool bRequestPerms) {
        m_bRequestPerms = bRequestPerms;
        SetNV("RequestPerms", CString(bRequestPerms));
    }

    void SetJoinOnInvite(const bool bJoinOnInvite) {
        m_bJoinOnInvite = bJoinOnInvite;
        SetNV("JoinOnInvite", CString(bJoinOnInvite));
    }

    void SetJoinAfterCloaked(const bool bJoinAfterCloaked) {
        m_bJoinAfterCloaked = bJoinAfterCloaked;
        SetNV("JoinAfterCloaked", CString(bJoinAfterCloaked));
    }

    void SetQModuleEnabled(const bool bQModuleEnabled) {
        m_bQModuleEnabled = bQModuleEnabled;
        SetNV("QModuleEnabled", CString(bQModuleEnabled));
        if (!bQModuleEnabled)
            StopRetryTimer();
        else if (IsIRCConnected())
            StartRetryTimer();
    }

    void SetRetryInterval(unsigned int uInterval) {
        m_uRetryInterval = uInterval;
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
    if (pQModule) pQModule->RetryAll();
}
