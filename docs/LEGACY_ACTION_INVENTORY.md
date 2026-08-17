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
| `MessageList` | `dev/Stores/User/Messagelist.js` | native | Native dispatch handles selected-account POST and RawKey GET requests. It includes `dateTimestamp`/`dateTimestampSource` parsing, including the INTERNALDATE fallback and existing client-side date grouping, BODYSTRUCTURE-based attachment presence and metadata, MailSo-compatible encrypted boolean metadata, MailSo-compatible spam metadata, MailSo-compatible read-receipt validation, RFC 8474 capability-gated and UID-correlated `EMAILID` parsing with PHP-compatible precedence over the capability-gated Gmail `X-GM-MSGID` fallback for `id`, MailSo-compatible limit normalization, branch-specific limit defaulting, `uidNext` defaulting, search trimming, injection-safe plain-text/address/subject/body/attachment/state/header/keyword/size/absolute-date criteria across their legacy prefixed and URL-query forms, prefixed calendar-relative criteria, capability-gated RFC 5032 age intervals, application-configurable and domain-pattern-specific fast-simple-search/permanent-filter/message-list-limit precedence, UTF8=ACCEPT-aware Unicode search with `CHARSET UTF-8` synchronizing literals for classic servers, completion-checked server-side `UID SEARCH`, typed RFC 4731/7377 ESEARCH results plus safely quoted `mailboxes`/`subtree`/`subtree-one` command execution with TAG/MAILBOX/UIDVALIDITY correlation, required COUNT capture, deterministic mailbox planning, exact sparse-UID re-search after per-mailbox UIDVALIDITY revalidation, explicit mailbox/UID-enumeration/deadline bounds, complete requested-FETCH enforcement, flat-list responses with SORT/THREAD reporting disabled, and synchronizing UTF-8 literals, capability-gated RFC 5256/5957 `UID SORT` with validated criteria and stable newest-UID fallback, capability-gated RFC 5256 `UID THREAD` with advertised-algorithm validation, nested response flattening, representative selection, selected-thread views, search expansion, unseen metadata, and legacy message fields, PHP-compatible large-mailbox limiting with full-UID-cache bypass, per-key single-flight and globally concurrency-bounded full-UID/thread-cache warming after a miss, cache-cardinality-aware warm suppression, search-without-SORT behavior, bounded approximate 3× sequence SORT windows, descending sequence FETCH fallback, and thread suppression, capability-gated RFC 8970 server-generated UTF-8 previews with NIL tolerance, reported sort and limited metadata normalization, nullable `totalThreads` collection emission, first-occurrence duplicate-header selection, RFC 2047 subject/address decoding, MailSo-compatible comment/display-name/unbracketed/IDN address parsing, subject trimming and `[Preview]` prefix removal, flag alias normalization, `References` whitespace normalization, nullable absent EmailId `id`, MailSo-compatible 100-entry email collection caps, server-side UID selection with pre-pagination `UNDELETED` filtering, accurate filtered totals, stable paging in server sort order, exact-`INBOX` new-message probing with RFC 2047 subject/sender decoding plus MailSo-compatible declared/default header charset handling, thread-view `newMessages` suppression, the internal legacy collection/message JSON adapter, PHP-compatible optional nested folder-info count/modseq/etag/permanent-flag/append-size fields, PHP-compatible best-effort Redis server-UID caching with main-account prefixes, SHA-1/index keying, folder-ETag payload validation, legacy flag-search exclusions, 12-hour expiry, bounded latency/cardinality/payloads, MULTISEARCH exclusion, exact `ThreadsMap`/`ThreadsOldUids` payload and key contracts, same-session conditional cache short-circuiting, MailSo-compatible RawKey cache-key/validation-state calculation, and RawKey HTTP cache validator/header emission. The read-only Rust action currently relies on the `SameSite=Lax` session cookie; legacy `XToken`/`X-SM-Token` validation remains a runtime-wide session migration boundary. |
| `Message` | `dev/Remote/User/Fetch.js` | native | Native for selected-account POST requests with `folder` and `uid`; reuses Rust IMAP body preview parsing and returns legacy `Object/Message` shape. The PHP-compatible array RawKey GET decoder (`folder`, `uid`, thread flag, account hash), PHP-compatible omission of empty `references`/body/thread fields, removal of the Rust-only `date` field, PHP timestamp source labeling with raw-message `Date` parsing and an `internal` zero fallback when no INTERNALDATE is available, RFC 8474 capability-gated and UID-correlated `EMAILID` parsing with PHP-compatible precedence over the capability-gated Gmail `X-GM-MSGID` fallback for `id`, nullable absent EmailId `id`, nullable absent/empty `preview`, `[Preview]` subject-prefix removal, raw-message fallback email collection, non-raw IMAP header/BODYSTRUCTURE metadata for subject, address/header collections, internal-date fallback, size, and attachments, ENVELOPE-only fallback for subject/message id/in-reply-to/address collections, MailSo-compatible comment/display-name/unbracketed/IDN address parsing, bounded MailSo-compatible aggregation of eligible plain/HTML/AMP BODYSTRUCTURE parts with PGP-payload and text-attachment fallbacks, shared/top-header charset fallback, transfer decoding, and eligible `format=flowed` joining without unbounded per-part MIME-header fetches, inline ASCII-armored OpenPGP signed/encrypted detection with bounded recipient key-id extraction, raw/header-derived spam metadata, raw/header-derived SPF/DKIM/DMARC auth-status metadata with DKIM status propagation, identity-header, read-receipt, attachment metadata population, raw-message header and parameter collection population, decoded raw scalar/address/text-list header values, top-level raw-message `multipart/encrypted` flagging, raw-message `draftInfo`, MailSo-compatible 100-entry email collection caps, normalized IMAP flag propagation, PHP-compatible Message HTTP cache validator/header emission, and BODYSTRUCTURE-derived `pgpSigned`/`pgpEncrypted`/`smimeSigned`/`smimeEncrypted` metadata are staged. **Thread support added: when `useThreads` is requested with `threadUid` and `threadAlgorithm`, returns `threads` (UIDs in the message's thread) and `threadUnseen` (unseen UIDs within that thread).** |
| `MessageSetSeenToAll` | `dev/View/User/MailBox/MessageList.js` | native | Uses selected Frickmail mail account; marks `1:*` by sequence for whole-folder updates and uses UID STORE when `threadUids` is supplied. |
| `MessageSetKeyword` | `dev/Model/Message.js` | native | Uses selected Frickmail mail account; stores safe ASCII IMAP keyword atoms, honors folder `PERMANENTFLAGS`, and no-ops unsafe or unsupported keywords like legacy PHP's skip-unsupported path. |
| `Folders` | `dev/Model/FolderCollection.js` | native | Uses the selected Frickmail mail account and returns the legacy folder collection shape with LIST/LSUB subscription discovery, LIST-STATUS-compatible folder counts and ETags, best-effort METADATA roles, RFC 2342 namespaces (including other-user/shared roots), storage quota bytes, filtered capabilities, and account-local checkable decoration. |
| `FolderInformation` | `dev/Common/Folders.js` | native | Uses the selected account and returns the legacy folder status shape with capability-gated `HIGHESTMODSEQ`, `APPENDLIMIT`, `STATUS=SIZE`, and base64 `MAILBOXID`, plus counts, UIDNEXT, UIDVALIDITY, permanent flags, PHP-compatible folder ETag, `messagesFlags` for `flagsUids`, and INBOX `newMessages` summaries when `uidNext` changes. |
| `FolderInformationMultiply` | `dev/Common/Folders.js` | native | Uses the selected account, fetches each requested folder's extended STATUS data, and skips per-folder failures like legacy PHP. |
| `FolderAppend` | `dev/Common/Folders.js` | native | Handles legacy multipart `appendFile` uploads when `FRICKMAIL__FRICKMAIL_USER__ALLOW_MESSAGE_APPEND=true`; uses selected Frickmail mail account and appends validated RFC822 data to IMAP without adding flags. |
| `FolderSubscribe` | `dev/View/Popup/Folder.js`, `dev/Settings/User/Folders.js` | native | Uses selected Frickmail mail account or explicit payload account, preserves PHP-style truthiness for `subscribe`, and maps IMAP subscribe/unsubscribe failures to legacy JSON errors. |
| `FolderClear` | `dev/View/Popup/FolderClear.js`, `dev/View/User/MailBox/MessageList.js` | native | Uses selected Frickmail mail account, marks all selected-folder messages deleted, and expunges like MailSo `FolderClear`. |
| `FolderDelete` | `dev/Settings/User/Folders.js` | native | Uses selected Frickmail mail account, rejects exact `INBOX` and non-empty folders like MailSo, unsubscribes, and deletes the mailbox. |
| `FolderCreate` | `dev/View/Popup/FolderCreate.js`, `dev/Settings/User/Folders.js` | native | Uses selected Frickmail mail account, mirrors MailSo parent delimiter resolution, creates and optionally subscribes the mailbox, then returns a legacy `Object/Folder` payload for frontend insertion. |
| `FolderRename` | `dev/View/Popup/Folder.js` | native | Uses selected Frickmail mail account, renames the mailbox and subscribed descendants, applies requested root subscription and Kolab metadata best-effort, and rewrites account-local checkable descendants. |
| `FolderCheckable` | `dev/Settings/User/Folders.js`, `dev/View/Popup/Folder.js` | native | Atomically adds/removes the folder in the selected account's legacy-compatible `CheckableFolder` setting while preserving unrelated settings. |
| `SystemFoldersUpdate` | `dev/Stores/User/Folder.js`, `dev/View/Popup/FolderSystem.js` | native | Uses the selected Frickmail mail account and persists legacy system folder names into account-local settings (`SentFolder`, `DraftsFolder`, `JunkFolder`, `TrashFolder`, `ArchiveFolder`). |
| `FolderSettings` | `dev/View/Popup/Folder.js` | native | Uses the selected Frickmail mail account, applies subscription and Kolab metadata best-effort after login, and persists the account-local checkable setting without letting its save result change the legacy success response. |
| `FolderSetMetadata` | `dev/Settings/User/Folders.js` | native | Uses the selected Frickmail mail account and safely emits a legacy-compatible IMAP `SETMETADATA`, including `NIL` removal for PHP-falsey values. |
| `FolderACL` | `dev/View/Popup/Folder.js` | native | Uses the selected Frickmail mail account, reads `MYRIGHTS`, and conditionally reads administrator-visible ACL entries into the legacy folder-rights collection shape. |
| `FolderSetACL`, `FolderDeleteACL` | `dev/View/Popup/FolderAcl.js`, `dev/View/Popup/Folder.js` | native | Use the selected Frickmail mail account and safely quote capability-gated IMAP ACL mutations. |
| `FolderIdentifierRights` | dormant code in `dev/View/Popup/FolderAcl.js` | compat-known | The only frontend call is commented out and the legacy PHP actions expose no matching handler; retained as a compatibility-known name pending removal or historical verification. |
| `AttachmentsActions` | `dev/Common/UtilsUser.js` | compat-known | The bounded ZIP Raw-download prototype remains deliberately undispatched pending completion of its separate download/temp-file contract. |
| `MessageUploadAttachments` | `dev/View/Popup/Compose.js` | native | Fetches forwarded MIME parts from the selected account, decodes base64/quoted-printable transfer encodings, and stages them under account-scoped capability tokens. Raw keys, IMAP partials, parser literals, decoded output, concurrency, memory, files, and deadlines are bounded; account selection is resolved once. |
| `Upload` service route | `dev/View/Popup/Compose.js` | native | Accepts only the legacy `/?/Upload/` multipart route, authenticates account ownership, and atomically stages one bounded upload with private directory/file permissions. Query/body action aliases are rejected so they cannot bypass the smaller body limit. |
| `SendMessage` | `dev/View/Popup/Compose.js` | partial-native | Native bounded compose and asynchronous SMTP delivery for password-backed selected accounts. Migrated behavior includes display-name-preserving From/To/Cc/Bcc/Reply-To with bare de-duplicated envelopes; plain/HTML alternatives and MailSo-compatible fallback; threading, priority, read receipts, JSON-LD, `TLS-Required: No`, verified sender-bound Autocrypt, capability-gated DSN/REQUIRETLS, stable transport/Sent identity headers, and definitive-versus-unknown delivery handling. HTML is parser-sanitized in a deadline-bounded blocking pool. Canonical `data:image/<alphanumeric>;base64,...` sources become deduplicated CID-linked MIME parts; effective WHATWG data-scheme detection removes obfuscated, non-image, and noncanonical data URLs. Valid padded/unpadded Base64 with ASCII whitespace is accepted under shared attachment count, byte, and memory admission. Staged regular, inline, CID-linked, and raw-message attachments use MailSo-compatible related/mixed nesting; successful delivery deletes exact staged capabilities while SMTP failures and saved drafts retain them. Remaining compose gaps are PGP assembly and S/MIME encryption (S/MIME signing, OAuth SMTP, and data-x-src/data-x-style-url transformations are all supported). |
| `SaveMessage` | `dev/View/Popup/Compose.js` | partial-native | Natively saves a selected-account draft with `\Seen`, a stable generated `Message-ID`, UID lookup fallback, PHP-compatible `{folder, uid}`/`true` response shapes, and delete-after-append cleanup of the prior draft. It shares the migrated basic compose, JSON-LD, strictly validated Autocrypt headers, staged regular/inline/CID attachments, embedded data-image conversion, MailSo-compatible related/mixed MIME nesting, and raw `message/rfc822` handling. Saved drafts retain staged capabilities for later retries. Crypto parity is coupled to SendMessage (S/MIME signing, OAuth SMTP, and data-x-src/data-x-style-url transformations are all supported). |

HTML compose now follows MailSo's multipart fallback rule for both actions:
when `plain` is omitted or PHP-falsey, Rust derives a bounded text/plain part
from the sanitized canonical HTML and still emits `multipart/alternative`.
Client-supplied PHP-truthy plain text remains authoritative.

Detailed native `Message` responses also populate the nullable RFC 8970
`preview` field through a capability-gated, UID-correlated `PREVIEW` fetch;
unsolicited responses and `NIL` values cannot populate another message.

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
| Have I Been Pwned | `HibpCheck` (native) |
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

1. Complete `SendMessage` parity: remaining legacy
   `data-x-src*`/`data-x-style-url` transformations, PGP/S-MIME
   `signed`/`encrypted` payloads, OAuth-backed SMTP, and S/MIME certificate
   selection by `identityID`.
2. Complete `SaveMessage` crypto and remaining transformed-inline MIME parity
   alongside `SendMessage`.
3. Complete `Message` parity: remaining message/header details and detailed
   message payloads.
4. Migrate the legacy connection-token/CSRF contract as part of the Rust-only
   session and runtime cutover.
