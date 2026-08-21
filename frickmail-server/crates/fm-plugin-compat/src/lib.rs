use fm_core::plugin::{PluginRequest, PluginResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionNameError {
    Empty,
    DoublePluginPrefix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompatHookKind {
    Json,
    Part,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatHook {
    pub kind: CompatHookKind,
    pub action: &'static str,
}

pub const FRICKMAIL_COMPAT_HOOKS: &[CompatHook] = &[
    json("Avatar"),
    json("SGetFilters"),
    json("SAddEditFilter"),
    json("SUpdateSearchQ"),
    json("SDeleteFilter"),
    json("KolabFolder"),
    json("JsonAdminBackupData"),
    json("JsonAdminRestoreData"),
    json("JsonContactsSync"),
    json("JsonDeduplicateContacts"),
    json("JsonAddContact"),
    json("JsonGetExampleUserData"),
    json("JsonSaveExampleUserData"),
    json("JsonAdminGetData"),
    json("ChangePassword"),
    json("FrickmailLogin"),
    json("FrickmailBridgeSession"),
    json("FrickmailRegister"),
    json("FrickmailListAccounts"),
    json("FrickmailAddAccount"),
    json("FrickmailUpdateAccount"),
    json("FrickmailDeleteAccount"),
    json("FrickmailSetPrimary"),
    json("FrickmailSwitchAccount"),
    json("FrickmailSetAccountPassword"),
    json("FrickmailRequestPasswordReset"),
    json("FrickmailResetPassword"),
    json("FrickmailMe"),
    json("FrickmailGetTotpStatus"),
    json("FrickmailEnableTotp"),
    json("FrickmailConfirmTotp"),
    json("FrickmailDisableTotp"),
    json("FrickmailDiscoverServices"),
    json("FrickmailActivateService"),
    json("FrickmailSaveOAuthToken"),
    json("FrickmailGraphListMessages"),
    json("FrickmailGraphSearch"),
    json("FrickmailGraphDelta"),
    json("FrickmailGraphGetMessage"),
    json("FrickmailGraphMarkRead"),
    json("FrickmailGraphMove"),
    json("FrickmailGraphDelete"),
    json("FrickmailSearch"),
    json("FrickmailUnifiedInbox"),
    json("FrickmailGetPrefs"),
    json("FrickmailSetPrefs"),
    json("FrickmailListIdentities"),
    json("FrickmailAddIdentity"),
    json("FrickmailDeleteIdentity"),
    json("FrickmailSetDefaultIdentity"),
    json("FrickmailListRules"),
    json("FrickmailAddRule"),
    json("FrickmailDeleteRule"),
    json("FrickmailToggleRule"),
    json("FrickmailApplyRules"),
    json("FrickmailCheckNewMail"),
    json("FrickmailLongPollNewMail"),
    json("FrickmailGetMessageBody"),
    json("FrickmailGetVapidKey"),
    json("FrickmailPushSubscribe"),
    json("FrickmailPushUnsubscribe"),
    json("FrickmailExportMessage"),
    json("FrickmailExportFolder"),
    json("FrickmailImportEml"),
    json("FrickmailListTasks"),
    json("FrickmailAddTask"),
    json("FrickmailCompleteTask"),
    json("FrickmailDeleteTask"),
    json("FrickmailUpdateTask"),
    json("FrickmailSmimeListCerts"),
    json("FrickmailSmimeImportP12"),
    json("FrickmailSmimeImportCert"),
    json("FrickmailSmimeDeleteCert"),
    json("FrickmailSmimeSign"),
    json("FrickmailSmimeVerify"),
    json("FrickmailListOidcLinks"),
    json("FrickmailUnlinkOidc"),
    json("MessageList"),
    json("Message"),
    json("MessageSetSeen"),
    json("MessageSetSeenToAll"),
    json("MessageSetFlagged"),
    json("MessageSetDeleted"),
    json("MessageSetKeyword"),
    json("MessageCopy"),
    json("MessageMove"),
    json("MessageDelete"),
    json("Folders"),
    json("FolderInformation"),
    json("FolderInformationMultiply"),
    json("FolderAppend"),
    json("FolderCreate"),
    json("FolderRename"),
    json("FolderDelete"),
    json("FolderClear"),
    json("FolderSettings"),
    json("FolderDeleteACL"),
    json("FolderACL"),
    json("FolderSetACL"),
    json("FolderIdentifierRights"),
    json("SystemFoldersUpdate"),
    json("FolderSetMetadata"),
    json("FolderSubscribe"),
    json("FolderCheckable"),
    json("AttachmentsActions"),
    json("MessageUploadAttachments"),
    json("Upload"),
    json("SendMessage"),
    json("SaveMessage"),
    json("SendReadReceiptMessage"),
    json("NextcloudSaveMsg"),
    json("NextcloudAttachFile"),
    json("JsonCalendarEvents"),
    json("JsonCalendarList"),
    json("JsonCalendarSave"),
    json("JsonCalendarDelete"),
    json("HibpCheck"),
    json("GetTwoFactorInfo"),
    json("CreateTwoFactorSecret"),
    json("ShowTwoFactorSecret"),
    json("EnableTwoFactor"),
    json("VerifyTwoFactorCode"),
    json("ClearTwoFactorInfo"),
    part("RemoteAutoLogin"),
    part("Avatar"),
    part("StartLoginGMail"),
    part("LoginGMail"),
    part("StartLoginO365"),
    part("LoginO365"),
    part("ExternalLogin"),
    part("StartLoginOIDC"),
    part("LoginOIDC"),
    part("cPanelAutoLogin"),
    part("ProxyAuth"),
    part("UserHeaderSet"),
    part("ExternalSso"),
];

pub fn is_compat_hook(action: &str) -> bool {
    FRICKMAIL_COMPAT_HOOKS
        .iter()
        .any(|hook| hook.action.eq_ignore_ascii_case(action))
}

pub fn normalize_plugin_action(action: &str) -> Result<&str, ActionNameError> {
    let action = action.trim();
    if action.is_empty() {
        return Err(ActionNameError::Empty);
    }

    if let Some(canonical) = action.strip_prefix("Plugin") {
        if canonical.starts_with("Plugin") {
            return Err(ActionNameError::DoublePluginPrefix);
        }
        Ok(canonical)
    } else {
        Ok(action)
    }
}

pub fn bridge_unimplemented(request: PluginRequest) -> PluginResponse {
    json!({
        "Result": false,
        "code": 501,
        "message": format!(
            "Frickmail compatibility hook '{}' is not migrated yet",
            request.action
        )
    })
}

const fn json(action: &'static str) -> CompatHook {
    CompatHook {
        kind: CompatHookKind::Json,
        action,
    }
}

const fn part(action: &'static str) -> CompatHook {
    CompatHook {
        kind: CompatHookKind::Part,
        action,
    }
}

#[cfg(test)]
mod tests {
    use fm_core::plugin::PluginRequest;
    use serde_json::Value;

    use super::{
        bridge_unimplemented, is_compat_hook, normalize_plugin_action, ActionNameError,
        CompatHookKind, FRICKMAIL_COMPAT_HOOKS,
    };

    #[test]
    fn frickmail_user_hook_inventory_is_complete_for_current_plugin() {
        let required = [
            "FrickmailLogin",
            "FrickmailBridgeSession",
            "FrickmailRegister",
            "FrickmailListAccounts",
            "FrickmailAddAccount",
            "FrickmailUpdateAccount",
            "FrickmailDeleteAccount",
            "FrickmailSetPrimary",
            "FrickmailSwitchAccount",
            "FrickmailSetAccountPassword",
            "FrickmailRequestPasswordReset",
            "FrickmailResetPassword",
            "FrickmailMe",
            "FrickmailGetTotpStatus",
            "FrickmailEnableTotp",
            "FrickmailConfirmTotp",
            "FrickmailDisableTotp",
            "FrickmailDiscoverServices",
            "FrickmailActivateService",
            "FrickmailSaveOAuthToken",
            "FrickmailGraphListMessages",
            "FrickmailGraphSearch",
            "FrickmailGraphDelta",
            "FrickmailGraphGetMessage",
            "FrickmailGraphMarkRead",
            "FrickmailGraphMove",
            "FrickmailGraphDelete",
            "FrickmailSearch",
            "FrickmailUnifiedInbox",
            "FrickmailGetPrefs",
            "FrickmailSetPrefs",
            "FrickmailListIdentities",
            "FrickmailAddIdentity",
            "FrickmailDeleteIdentity",
            "FrickmailSetDefaultIdentity",
            "FrickmailListRules",
            "FrickmailAddRule",
            "FrickmailDeleteRule",
            "FrickmailToggleRule",
            "FrickmailApplyRules",
            "FrickmailCheckNewMail",
            "FrickmailLongPollNewMail",
            "FrickmailGetMessageBody",
            "FrickmailGetVapidKey",
            "FrickmailPushSubscribe",
            "FrickmailPushUnsubscribe",
            "FrickmailExportMessage",
            "FrickmailExportFolder",
            "FrickmailImportEml",
            "FrickmailListTasks",
            "FrickmailAddTask",
            "FrickmailCompleteTask",
            "FrickmailDeleteTask",
            "FrickmailUpdateTask",
            "FrickmailSmimeListCerts",
            "FrickmailSmimeImportP12",
            "FrickmailSmimeImportCert",
            "FrickmailSmimeDeleteCert",
            "FrickmailSmimeSign",
            "FrickmailSmimeVerify",
        ];

        for action in required {
            assert!(is_compat_hook(action), "missing hook {action}");
        }
    }

    #[test]
    fn legacy_mailbox_core_hooks_are_known_during_rust_migration() {
        let required = [
            "MessageList",
            "Message",
            "MessageSetSeen",
            "MessageSetSeenToAll",
            "MessageSetFlagged",
            "MessageSetDeleted",
            "MessageSetKeyword",
            "MessageCopy",
            "MessageMove",
            "MessageDelete",
            "Folders",
            "FolderInformation",
            "FolderInformationMultiply",
            "FolderAppend",
            "FolderCreate",
            "FolderRename",
            "FolderDelete",
            "FolderClear",
            "FolderSettings",
            "FolderDeleteACL",
            "FolderACL",
            "FolderSetACL",
            "FolderIdentifierRights",
            "SystemFoldersUpdate",
            "FolderSetMetadata",
            "FolderSubscribe",
            "FolderCheckable",
            "AttachmentsActions",
            "MessageUploadAttachments",
            "Upload",
            "SendMessage",
            "SaveMessage",
            "SendReadReceiptMessage",
        ];

        for action in required {
            assert!(is_compat_hook(action), "missing legacy core hook {action}");
        }
    }

    #[test]
    fn part_hooks_include_oauth_entry_points() {
        let part_hooks = FRICKMAIL_COMPAT_HOOKS
            .iter()
            .filter(|hook| hook.kind == CompatHookKind::Part)
            .map(|hook| hook.action)
            .collect::<Vec<_>>();

        assert!(part_hooks.contains(&"StartLoginGMail"));
        assert!(part_hooks.contains(&"LoginO365"));
        assert!(part_hooks.contains(&"StartLoginOIDC"));
    }

    #[test]
    fn compatibility_errors_preserve_json_envelope_shape() {
        let response = bridge_unimplemented(PluginRequest {
            action: "FrickmailMe".to_string(),
            payload: Value::Null,
        });

        assert_eq!(response["Result"], false);
        assert_eq!(response["code"], 501);
        assert!(response["message"]
            .as_str()
            .unwrap()
            .contains("FrickmailMe"));
        assert!(response.get("ok").is_none());
        assert!(response.get("data").is_none());
    }

    #[test]
    fn plugin_prefixed_actions_normalize_once() {
        assert_eq!(
            normalize_plugin_action("PluginFrickmailMe").unwrap(),
            "FrickmailMe"
        );
        assert_eq!(
            normalize_plugin_action("FrickmailMe").unwrap(),
            "FrickmailMe"
        );
        assert_eq!(
            normalize_plugin_action("PluginPluginFrickmailMe"),
            Err(ActionNameError::DoublePluginPrefix)
        );
    }
}
