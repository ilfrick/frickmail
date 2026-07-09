# Legacy Action Inventory

This inventory is the migration map for the SnappyMail/RainLoop PHP runtime,
Frickmail-user plugin, and the Rust compatibility server.

Sources checked:

- `plugins/frickmail-user/index.php`
- `plugins/frickmail-user/js/*.js`
- `plugins/login-oidc/index.php`
- `plugins/login-oidc/LoginOIDC.js`
- `frickmail-server/crates/fm-core/src/plugin.rs`
- `frickmail-server/crates/fm-plugin-compat/src/lib.rs`
- `frickmail-server/crates/fm-http/src/router.rs`

Status meanings:

- `native`: handled by Rust in `fm-http`.
- `partial-native`: Rust validates or persists migration state, but still must not
  claim complete legacy behavior.
- `compat-known`: registered in the Rust compatibility inventory but not handled
  natively yet; it returns a 501 compatibility fallback unless the PHP bridge
  handles it.
- `php-hook`: registered in the PHP plugin runtime.

## Frickmail-User JSON Actions

| Action | PHP hook | Frontend caller | Rust status | Notes |
|---|---:|---|---|---|
| `FrickmailLogin` | yes | `Login.js` | native | Writes user and credential-key sessions, validates the primary-or-oldest account, and stores selected account on successful login. TOTP replay protection is native. |
| `FrickmailBridgeSession` | yes | `Login.js` | native | Validates credentials and stores selected account with PHP-compatible primary-or-oldest fallback. |
| `FrickmailRegister` | yes | `Login.js` | native | Signup gating and PHP-compatible validation covered. |
| `FrickmailListAccounts` | yes | `AccountSwitcher.js`, settings UIs | native | Returns safe metadata and inline identities. |
| `FrickmailAddAccount` | yes | `MailAccountsSettings.js` | native | Encrypts secrets with credential session key. |
| `FrickmailUpdateAccount` | yes | `MailAccountsSettings.js` | native | Preserves password when empty; SSRF guards apply. |
| `FrickmailDeleteAccount` | yes | `MailAccountsSettings.js` | native | Deletes account and indexed-message rows. |
| `FrickmailSetPrimary` | yes | `MailAccountsSettings.js` | native | User-scoped primary update. |
| `FrickmailSwitchAccount` | yes | `AccountSwitcher.js`, `Search.js`, `UnifiedInbox.js` | native | Validates target account ownership and credentials before storing the selected account. |
| `FrickmailSetAccountPassword` | yes | `MailAccountsSettings.js` | native | Updates encrypted secret. |
| `FrickmailRequestPasswordReset` | yes | `Login.js` | native | No account enumeration. |
| `FrickmailResetPassword` | yes | `Login.js` | native | Resets password and invalidates credentials. |
| `FrickmailMe` | yes | `Login.js`, shell probes | native | Reloads current session user from DB. |
| `FrickmailGetTotpStatus` | yes | `TwoFactorSettings.js` | native | Reads secret presence. |
| `FrickmailEnableTotp` | yes | `TwoFactorSettings.js` | native | Generates pending setup secret. |
| `FrickmailConfirmTotp` | yes | `TwoFactorSettings.js` | native | Confirms setup with live code. |
| `FrickmailDisableTotp` | yes | `TwoFactorSettings.js` | native | Requires valid live code. |
| `FrickmailDiscoverServices` | yes | `MailAccountsSettings.js` | native | CalDAV/service discovery with reserved-IP guard. |
| `FrickmailActivateService` | yes | `MailAccountsSettings.js` | native | Persists service activation metadata. |
| `FrickmailSaveOAuthToken` | yes | `Login.js`, OAuth popups | native | Stores encrypted refresh token by account/email. |
| `FrickmailGraphListMessages` | yes | `GraphMailbox.js` | native | Lists Office 365 folder messages through Microsoft Graph using the encrypted refresh token. |
| `FrickmailGraphSearch` | yes | `GraphMailbox.js` | native | Searches Office 365 mail through Microsoft Graph `$search` using the encrypted refresh token. |
| `FrickmailGraphDelta` | yes | `GraphMailbox.js` | native | Runs Microsoft Graph delta sync with validated follow-up links. |
| `FrickmailGraphGetMessage` | yes | `GraphMailbox.js` | native | Fetches Office 365 message detail through Microsoft Graph. |
| `FrickmailGraphMarkRead` | yes | `GraphMailbox.js` | native | Marks Office 365 messages read/unread through Microsoft Graph. |
| `FrickmailGraphMove` | yes | `GraphMailbox.js` | native | Moves Office 365 messages through Microsoft Graph. |
| `FrickmailGraphDelete` | yes | `GraphMailbox.js` | native | Deletes Office 365 messages through Microsoft Graph. |
| `FrickmailSearch` | yes | `Search.js` | native | Indexed search. |
| `FrickmailUnifiedInbox` | yes | `UnifiedInbox.js` | native | Indexed inbox, not live IMAP scan. |
| `FrickmailGetPrefs` | yes | `UserPrefs.js`, `Notifications.js` | native | Reads merged preferences. |
| `FrickmailSetPrefs` | yes | `UserPrefs.js` | native | Validates and persists patch. |
| `FrickmailListIdentities` | yes | `IdentitySettings.js` | native | Account-scoped. |
| `FrickmailAddIdentity` | yes | `IdentitySettings.js` | native | Account-scoped. |
| `FrickmailDeleteIdentity` | yes | `IdentitySettings.js` | native | Account-scoped. |
| `FrickmailSetDefaultIdentity` | yes | `IdentitySettings.js` | native | Account-scoped default update. |
| `FrickmailListRules` | yes | `Rules.js` | native | Account-scoped rules. |
| `FrickmailAddRule` | yes | `Rules.js` | native | Stores rule definition. |
| `FrickmailDeleteRule` | yes | `Rules.js` | native | Account-scoped delete. |
| `FrickmailToggleRule` | yes | `Rules.js` | native | Account-scoped enable/disable. |
| `FrickmailApplyRules` | yes | `Rules.js` | native | Executes IMAP rules with MailSo-compatible MOVE/UIDPLUS fallbacks. |
| `FrickmailCheckNewMail` | feature-gated | `Notifications.js` | native | Polls all IMAP accounts; do not narrow to selected account. |
| `FrickmailLongPollNewMail` | feature-gated | `Notifications.js` | native | Polls all IMAP accounts and triggers web push. |
| `FrickmailGetMessageBody` | feature-gated | `UnifiedInbox.js` | native | Supports explicit account id and selected-account fallback with ownership revalidation. |
| `FrickmailGetVapidKey` | feature-gated | `Notifications.js` | native | Creates/reads persistent VAPID key. |
| `FrickmailPushSubscribe` | feature-gated | `Notifications.js` | native | Validates public push endpoint before storing. |
| `FrickmailPushUnsubscribe` | feature-gated | `Notifications.js` | native | Deletes subscription. |
| `FrickmailExportMessage` | feature-gated | `ImportExport.js` | native | IMAP UID raw export with legacy filename/content envelope. |
| `FrickmailExportFolder` | feature-gated | `ImportExport.js` | native | IMAP folder export to mbox-compatible base64 payload. |
| `FrickmailImportEml` | feature-gated | `ImportExport.js` | native | Base64 EML validation and IMAP APPEND import. |
| `FrickmailListTasks` | feature-gated | `Tasks.js` | native | User-scoped tasks. |
| `FrickmailAddTask` | feature-gated | `Tasks.js` | native | User-scoped tasks. |
| `FrickmailCompleteTask` | feature-gated | `Tasks.js` | native | User-scoped tasks. |
| `FrickmailDeleteTask` | feature-gated | `Tasks.js` | native | User-scoped tasks. |
| `FrickmailUpdateTask` | feature-gated | `Tasks.js` | native | User-scoped tasks. |
| `FrickmailSmimeListCerts` | feature-gated | `SmimeSettings.js` | native | Lists public cert metadata only. |
| `FrickmailSmimeImportP12` | feature-gated | `SmimeSettings.js` | native | Native PKCS#12 private-key import with encrypted key storage. |
| `FrickmailSmimeImportCert` | feature-gated | `SmimeSettings.js` | native | Public certificate import. |
| `FrickmailSmimeDeleteCert` | feature-gated | `SmimeSettings.js` | native | User-scoped delete. |
| `FrickmailSmimeSign` | feature-gated | `SmimeSettings.js` | native | Native detached S/MIME signing. |
| `FrickmailSmimeVerify` | feature-gated | `SmimeSettings.js` | native | Native S/MIME verification against the system trust store. |
| `FrickmailListOidcLinks` | yes | `LoginOIDC.js` | native | Implemented by Rust for login-oidc compatibility. |
| `FrickmailUnlinkOidc` | yes | `LoginOIDC.js` | native | Implemented by Rust for login-oidc compatibility. |

## Legacy Webmail Core JSON Actions

These are SnappyMail/RainLoop mailbox actions used by the legacy Knockout app.
They are tracked separately from Frickmail-user plugin hooks because they are
part of the full webmail core migration.

| Action | Frontend source | Rust status | Notes |
|---|---|---|---|
| `MessageSetSeen` | `dev/Stores/User/Messagelist.js` | native | Uses selected Frickmail mail account; validates account ownership and stored IMAP credentials. |
| `MessageSetFlagged` | `dev/Stores/User/Messagelist.js` | native | Uses selected Frickmail mail account and safe UID STORE flag updates. |
| `MessageSetDeleted` | `dev/Stores/User/Messagelist.js` | native | Uses selected Frickmail mail account and safe UID STORE flag updates. |
| `MessageCopy` | `dev/Stores/User/Messagelist.js` | native | Uses selected Frickmail mail account, source folder, target folder, and comma-separated UIDs. |
| `MessageMove` | `dev/Stores/User/Messagelist.js` | native | Uses selected Frickmail mail account; honors legacy `markAsRead` plus `learning=SPAM/HAM` pre-move flags and falls back to COPY plus delete when IMAP MOVE is unavailable. |
| `MessageDelete` | `dev/Stores/User/Messagelist.js` | native | Uses selected Frickmail mail account; marks deleted and expunges safely. |
| `MessageList` | `dev/Stores/User/Messagelist.js` | compat-known | Native implementation is staged but dispatch remains disabled until sort/search/threading, complete hidden-deleted filtering, date grouping, RawKey GET cache backend interaction, previews, and full cache parity match legacy PHP behavior. `dateTimestamp`/`dateTimestampSource` parsing, including the INTERNALDATE fallback, BODYSTRUCTURE-based attachment presence and metadata, MailSo-compatible encrypted boolean metadata, MailSo-compatible spam metadata, MailSo-compatible limit normalization, branch-specific limit defaulting, `uidNext` defaulting, search trimming, reported sort and limited metadata normalization, nullable `totalThreads` collection emission, subject trimming, flag alias normalization, `References` whitespace normalization, nullable absent EmailId `id`, nullable absent/empty `preview`, MailSo-compatible 100-entry email collection caps, setting-driven fetched-window `\Deleted` suppression, exact-`INBOX` new-message probing, thread-view `newMessages` suppression, the internal legacy collection/message JSON adapter, PHP-compatible optional nested folder-info count/modseq/etag/permanent-flag/append-size fields, the selected-account POST request/fetcher path, the RawKey GET request decoder with `threadAlgorithm` and account-hash payload capture, and MailSo-compatible RawKey cache-key/validation-state calculation are staged internally; live dispatch remains pending. |
| `Message` | `dev/Remote/User/Fetch.js` | partial-native | Native for selected-account POST requests with `folder` and `uid`; reuses Rust IMAP body preview parsing and returns legacy `Object/Message` shape. The PHP-compatible array RawKey GET decoder (`folder`, `uid`, thread flag, account hash), PHP-compatible omission of empty `references`/body/thread fields, removal of the Rust-only `date` field, PHP fallback-branch `internal` source labeling for the zero timestamp when no INTERNALDATE is available, nullable absent EmailId `id`, nullable absent/empty `preview`, nullable unavailable email/attachment/header collections, raw-message fallback email collection and identity-header population, and MailSo-compatible 100-entry email collection caps are staged. Full attachment metadata, crypto, non-raw IMAP header/envelope email/header collections, RawKey cache, and exact PHP message model parity remain compatibility work. |
| `MessageSetSeenToAll` | `dev/View/User/MailBox/MessageList.js` | native | Uses selected Frickmail mail account; marks `1:*` by sequence for whole-folder updates and uses UID STORE when `threadUids` is supplied. |
| `MessageSetKeyword` | `dev/Model/Message.js` | native | Uses selected Frickmail mail account; stores safe ASCII IMAP keyword atoms, honors folder `PERMANENTFLAGS`, and no-ops unsafe or unsupported keywords like legacy PHP's skip-unsupported path. |
| `FolderInformation` | `dev/Common/Folders.js` | partial-native | Native for selected-account POST requests; returns legacy folder status shape with counts, UIDNEXT, UIDVALIDITY, permanent flags, PHP-compatible optional count/modseq/etag/permanent-flag/append-size fields, PHP-compatible folder ETag, `messagesFlags` for `flagsUids`, and INBOX `newMessages` summaries when `uidNext` changes. `appendLimit`/`size` adapter emission is staged; live extraction remains pending an IMAP source. Server-specific CONDSTORE/HIGHESTMODSEQ parity still needs broader IMAP validation. |
| `FolderInformationMultiply` | `dev/Common/Folders.js` | partial-native | Native for selected-account POST refreshes; fetches each requested folder status and skips per-folder failures like legacy PHP. Full cache interaction parity remains compatibility work. |
| `FolderAppend` | `dev/Common/Folders.js` | native | Handles legacy multipart `appendFile` uploads when `FRICKMAIL__FRICKMAIL_USER__ALLOW_MESSAGE_APPEND=true`; uses selected Frickmail mail account and appends validated RFC822 data to IMAP without adding flags. |
| `FolderClear`, `FolderSettings`, `FolderDeleteACL`, `FolderACL`, `FolderSetACL`, `FolderIdentifierRights`, `SystemFoldersUpdate`, `FolderSetMetadata`, `FolderSubscribe`, `FolderCheckable` | `dev/View/Popup`, `dev/Settings/User/Folders.js`, `dev/Stores/User/Folder.js` | compat-known | Folder management and ACL routes remain unmigrated. |
| `AttachmentsActions`, `MessageUploadAttachments` | `dev/Common/UtilsUser.js`, `dev/View/Popup/Compose.js` | compat-known | Attachment actions remain on the compatibility roadmap. |

## Other Bundled Plugin JSON Hooks

These hooks are known by the Rust compatibility layer so existing SnappyMail
plugins remain compatible during the migration. They are not Frickmail-user native
features unless noted elsewhere.

| Plugin area | Actions |
|---|---|
| Avatars | `Avatar` |
| Search filters | `SGetFilters`, `SAddEditFilter`, `SUpdateSearchQ`, `SDeleteFilter` |
| Kolab | `KolabFolder` |
| Backup | `JsonAdminBackupData`, `JsonAdminRestoreData` |
| Contacts sync | `JsonContactsSync`, `JsonDeduplicateContacts`, `JsonAddContact` |
| Example plugin | `JsonGetExampleUserData`, `JsonSaveExampleUserData`, `JsonAdminGetData` |
| Change password | `ChangePassword` |
| Nextcloud | `NextcloudSaveMsg`, `NextcloudAttachFile` |
| Calendar | `JsonCalendarEvents`, `JsonCalendarList`, `JsonCalendarSave`, `JsonCalendarDelete` |
| Have I Been Pwned | `HibpCheck` |
| Two-factor-auth legacy plugin | `GetTwoFactorInfo`, `CreateTwoFactorSecret`, `ShowTwoFactorSecret`, `EnableTwoFactor`, `VerifyTwoFactorCode`, `ClearTwoFactorInfo` |

## Part Hooks

Part hooks must remain compatible while the SnappyMail plugin API is supported:

- `RemoteAutoLogin`
- `Avatar`
- `StartLoginGMail`
- `LoginGMail`
- `StartLoginO365`
- `LoginO365`
- `ExternalLogin`
- `StartLoginOIDC`
- `LoginOIDC`
- `cPanelAutoLogin`
- `ProxyAuth`
- `UserHeaderSet`
- `ExternalSso`

## Legacy Transport Shapes

The Rust server currently accepts these legacy request forms:

- Form body `Action=PluginFrickmailMe&XToken=...`
- Query action `/?_action=FrickmailListAccounts`
- Legacy JSON route shape `/?/Json/&q[]=/0/FrickmailMe/`
- Multipart form requests with an `Action` field

Unknown actions intentionally return the legacy JSON envelope with an
`UNKNOWN_ERROR`. Known-but-not-native compatibility actions return a 501
compatibility fallback until they are migrated.

## Remaining Native Migration Targets

The next Rust implementation targets from this inventory are:

1. Complete `MessageList`, `Message`, and folder status parity: RawKey GET cache
   paths, search/threaded lists, precise legacy sort semantics, previews,
   attachment/header details, and detailed new-message notification payloads.
