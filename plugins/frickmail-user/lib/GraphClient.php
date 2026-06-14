<?php
namespace Frickmail\User;

/**
 * GraphClient — thin wrapper around Microsoft Graph API v1.0.
 *
 * Uses the same OAuth2 refresh token as the IMAP bridge (incremental consent):
 * Microsoft allows requesting Graph scopes from an existing refresh token
 * as long as those scopes are registered as Delegated permissions in Azure AD.
 *
 * IMPORTANT — Azure AD app registration:
 *   The app must have these Delegated permissions added in the Azure portal:
 *   Mail.Read, Mail.ReadWrite, Mail.Send (Microsoft Graph).
 *   Without them the token exchange will succeed but API calls will return 403.
 */
class GraphClient
{
    const BASE = 'https://graph.microsoft.com/v1.0';

    /**
     * Graph scopes requested during token exchange.
     * Combined with the IMAP scopes already present in the refresh token;
     * Microsoft issues a new token covering the union.
     */
    const SCOPES = 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send offline_access';

    private string $accessToken;

    public function __construct(string $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Exchange a refresh token for a Graph access token.
     *
     * Uses the login-oauth2 OAuth2\Client library already bundled with Frickmail.
     * The refresh token is the same one used for IMAP; Microsoft issues a new
     * access token scoped to Graph when the incremental-consent scopes are included.
     */
    public static function fromRefreshToken(
        string $refreshToken,
        string $clientId,
        string $clientSecret,
        string $tenant = 'common'
    ): self {
        require_once \APP_PLUGINS_PATH . 'login-oauth2/OAuth2/Client.php';

        $tokenUri = "https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token";
        $oClient  = new \OAuth2\Client($clientId, $clientSecret);
        $aResp    = $oClient->getAccessToken($tokenUri, 'refresh_token', [
            'refresh_token' => $refreshToken,
            'scope'         => self::SCOPES,
        ]);

        if (200 !== (int) ($aResp['code'] ?? 0) || empty($aResp['result']['access_token'])) {
            $desc = $aResp['result']['error_description']
                ?? $aResp['result']['error']
                ?? 'unknown error';
            throw new \RuntimeException('Graph token exchange failed: ' . $desc);
        }

        return new self((string) $aResp['result']['access_token']);
    }

    /* ------------------------------------------------------------------ */
    /*  Folder / message listing                                             */
    /* ------------------------------------------------------------------ */

    /**
     * List messages in a mail folder.
     *
     * @param string      $folder    Folder name or well-known name (e.g. 'inbox', 'sentitems')
     * @param int         $top       Max number of messages to return
     * @param string|null $deltaLink If non-null, used as the full URL (delta follow-up request)
     */
    public function listMessages(
        string $folder = 'inbox',
        int $top = 50,
        ?string $deltaLink = null
    ): array {
        if ($deltaLink !== null) {
            return $this->request('GET', self::assertGraphUrl($deltaLink));
        }
        $select = 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments';
        $url    = self::BASE . '/me/mailFolders/' . \rawurlencode($folder)
            . '/messages?$top=' . $top
            . '&$select=' . \rawurlencode($select)
            . '&$orderby=' . \rawurlencode('receivedDateTime desc');
        return $this->request('GET', $url);
    }

    /**
     * Get a single message with full body.
     */
    public function getMessage(string $messageId): array
    {
        $select = 'id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,isRead,hasAttachments';
        $url    = self::BASE . '/me/messages/' . \rawurlencode($messageId)
            . '?$select=' . \rawurlencode($select);
        return $this->request('GET', $url);
    }

    /**
     * Search messages across all folders using Graph $search.
     *
     * Note: $search requires the account to have an Exchange Online mailbox;
     * it also does not support $orderby when combined with $search.
     */
    public function searchMessages(string $query, int $top = 50): array
    {
        $select = 'id,subject,from,receivedDateTime,isRead,bodyPreview,parentFolderId';
        // $search value must be wrapped in double-quotes per Graph spec
        $escapedQuery = '"' . \str_replace('"', '\\"', $query) . '"';
        $url = self::BASE . '/me/messages'
            . '?$search=' . \rawurlencode($escapedQuery)
            . '&$top=' . $top
            . '&$select=' . \rawurlencode($select);
        return $this->request('GET', $url);
    }

    /**
     * List mail folders for the current user.
     */
    public function listFolders(): array
    {
        $url = self::BASE . '/me/mailFolders?$select=id,displayName,unreadItemCount,totalItemCount&$top=50';
        return $this->request('GET', $url);
    }

    /* ------------------------------------------------------------------ */
    /*  Send / mutate                                                         */
    /* ------------------------------------------------------------------ */

    /**
     * Send a message via /me/sendMail.
     *
     * @param array       $toRecipients  Array of email address strings
     * @param string      $subject
     * @param string      $bodyHtml      HTML body
     * @param string|null $bodyText      Optional plain-text alternative (ignored if null)
     */
    public function sendMail(
        array $toRecipients,
        string $subject,
        string $bodyHtml,
        ?string $bodyText = null
    ): void {
        $recipients = \array_map(
            fn(string $addr) => ['emailAddress' => ['address' => $addr]],
            $toRecipients
        );

        $message = [
            'subject' => $subject,
            'body'    => [
                'contentType' => 'HTML',
                'content'     => $bodyHtml,
            ],
            'toRecipients' => $recipients,
        ];

        $body = [
            'message'         => $message,
            'saveToSentItems' => true,
        ];

        // sendMail returns 202 Accepted with empty body — request() handles that.
        $this->request('POST', self::BASE . '/me/sendMail', $body);
    }

    /**
     * Mark a message as read or unread.
     */
    public function markRead(string $messageId, bool $isRead): void
    {
        $this->request(
            'PATCH',
            self::BASE . '/me/messages/' . \rawurlencode($messageId),
            ['isRead' => $isRead]
        );
    }

    /**
     * Move a message to a different folder.
     */
    public function move(string $messageId, string $destinationFolderId): array
    {
        return $this->request(
            'POST',
            self::BASE . '/me/messages/' . \rawurlencode($messageId) . '/move',
            ['destinationId' => $destinationFolderId]
        );
    }

    /**
     * Delete a message (moves to Deleted Items; use permanent delete for hard delete).
     */
    public function deleteMessage(string $messageId): void
    {
        $this->request('DELETE', self::BASE . '/me/messages/' . \rawurlencode($messageId));
    }

    /* ------------------------------------------------------------------ */
    /*  Delta sync                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Get a delta (changes since last sync) for a folder.
     *
     * On the first call pass $deltaToken = null — the response will contain
     * a @odata.deltaLink URL with an embedded token. Pass that token on
     * subsequent calls to get only changes since the last sync.
     *
     * @param string      $folderId   Folder well-known name or ID (e.g. 'inbox')
     * @param string|null $deltaToken Opaque token from a previous getDelta response
     */
    public function getDelta(string $folderId = 'inbox', ?string $deltaToken = null): array
    {
        if ($deltaToken !== null) {
            // deltaToken may be a full URL or just the token value
            if (\str_starts_with($deltaToken, 'https://')) {
                $url = self::assertGraphUrl($deltaToken);
            } else {
                $url = self::BASE . '/me/mailFolders/' . \rawurlencode($folderId)
                    . '/messages/delta?$deltatoken=' . \rawurlencode($deltaToken);
            }
        } else {
            $select = 'id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments';
            $url    = self::BASE . '/me/mailFolders/' . \rawurlencode($folderId)
                . '/messages/delta?$select=' . \rawurlencode($select);
        }
        return $this->request('GET', $url);
    }

    private static function assertGraphUrl(string $url): string
    {
        $parts  = \parse_url($url);
        $scheme = \strtolower((string) ($parts['scheme'] ?? ''));
        $host   = \strtolower((string) ($parts['host'] ?? ''));
        $path   = (string) ($parts['path'] ?? '');
        if ('https' !== $scheme || 'graph.microsoft.com' !== $host || !\str_starts_with($path, '/v1.0/')) {
            throw new \RuntimeException('Invalid Graph delta URL');
        }
        return $url;
    }

    /* ------------------------------------------------------------------ */
    /*  HTTP transport                                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Execute a Graph API request using file_get_contents + stream context.
     * Returns the decoded JSON body (or an empty array for 204/202 responses).
     * Throws RuntimeException on HTTP 4xx/5xx.
     */
    private function request(string $method, string $url, ?array $body = null): array
    {
        $headers = implode("\r\n", [
            'Authorization: Bearer ' . $this->accessToken,
            'Content-Type: application/json',
            'Accept: application/json',
        ]) . "\r\n";

        $opts = [
            'http' => [
                'method'        => $method,
                'header'        => $headers,
                'timeout'       => 15,
                'ignore_errors' => true,
            ],
        ];

        if ($body !== null) {
            $opts['http']['content'] = \json_encode($body);
        }

        $ctx    = \stream_context_create($opts);
        $raw    = \file_get_contents($url, false, $ctx);
        $status = 0;

        // $http_response_header is set by file_get_contents in the local scope
        if (!empty($http_response_header)) {
            \preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $m);
            $status = (int) ($m[1] ?? 0);
        }

        if ($status >= 400) {
            $err = \json_decode((string) $raw, true);
            $msg = $err['error']['message'] ?? ((string) $raw);
            throw new \RuntimeException('Graph API error ' . $status . ': ' . $msg);
        }

        // 202 Accepted (sendMail) and 204 No Content (delete/markRead) have empty bodies
        if ('' === (string) $raw || null === $raw) {
            return [];
        }

        $decoded = \json_decode((string) $raw, true);
        return \is_array($decoded) ? $decoded : [];
    }
}
