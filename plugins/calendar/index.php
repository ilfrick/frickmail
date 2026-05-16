<?php
/**
 * Frickmail calendar — embeds a calendar tab into SnappyMail Settings,
 * showing events from Google Calendar (primary) and Microsoft Graph (/me/events).
 * Uses the OAuth2 refresh tokens stored in session by login-gmail / login-o365.
 */

use RainLoop\Providers\Storage\Enumerations\StorageType;

class CalendarPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Calendar',
		VERSION  = '0.2',
		RELEASE  = '2026-05-16',
		REQUIRED = '2.36.1',
		CATEGORY = 'Calendar',
		DESCRIPTION = 'Frickmail: embedded calendar showing Google Calendar / Microsoft Graph events for the linked OAuth2 account.';

	const GMAIL_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token';
	const O365_TOKEN_URI  = 'https://login.microsoftonline.com/{{tenant}}/oauth2/v2.0/token';

	public function Init() : void
	{
		$this->UseLangs(false);
		$this->addJs('js/CalendarSettings.js');
		$this->addJs('js/CalendarSidebar.js');
		$this->addCss('css/calendar.css');
		$this->addTemplate('templates/CalendarSettingsTab.html');
		$this->addJsonHook('JsonCalendarEvents', 'JsonCalendarEvents');
		$this->addJsonHook('JsonCalendarList',   'JsonCalendarList');
		$this->addJsonHook('JsonCalendarSave',   'JsonCalendarSave');
		$this->addJsonHook('JsonCalendarDelete', 'JsonCalendarDelete');
	}

	private function currentAccount() : ?\RainLoop\Model\Account
	{
		return \RainLoop\Api::Actions()->getMainAccountFromToken(false);
	}

	private function loadAuth(\RainLoop\Model\Account $oAccount) : array
	{
		// Primary source: SnappyMail session storage.
		$aAuth = null;
		try {
			$raw = \RainLoop\Api::Actions()->StorageProvider()->Get($oAccount, StorageType::SESSION, \RainLoop\Utils::GetSessionToken());
			if ($raw) {
				$aAuth = \SnappyMail\Crypt::DecryptFromJSON($raw, $oAccount->CryptKey());
			}
		} catch (\Throwable $e) {
			$aAuth = null;
		}

		// Fallback: read directly from Frickmail DB via Bridge.
		if (empty($aAuth['refresh_token'])) {
			$aAuth = $this->loadFrickmailAuth($oAccount->Email()) ?? $aAuth;
		}

		if (!\is_array($aAuth) || empty($aAuth['refresh_token'])) {
			throw new \RuntimeException('No OAuth2 refresh token — sign in with Gmail/Microsoft via the OAuth2 popup first.');
		}
		return $aAuth;
	}

	private function loadFrickmailAuth(string $sEmail) : ?array
	{
		$sBase = \APP_PLUGINS_PATH . 'frickmail-user/lib/';
		if (!\is_file($sBase . 'Bridge.php')) return null;
		try {
			require_once $sBase . 'Crypto.php';
			require_once $sBase . 'Db.php';
			require_once $sBase . 'Bridge.php';
			$uid = \Frickmail\User\Bridge::currentUserId();
			$key = \Frickmail\User\Bridge::currentCryptKey();
			if (!$uid || !$key) return null;
			$db = new \Frickmail\User\Db();
			foreach ($db->listMailAccounts($uid) as $row) {
				if (\strtolower((string) $row['email']) !== \strtolower($sEmail)) continue;
				$dec = $db->decryptedAccount($row, $key);
				if (empty($dec['oauth_refresh_token'])) continue;
				return ['refresh_token' => $dec['oauth_refresh_token']];
			}
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
		}
		return null;
	}

	private function detectProvider(string $sEmail) : string
	{
		$sEmail = \strtolower($sEmail);
		$aGmail = $this->whitespaceList($this->configFromPlugin('login-gmail', 'domains', 'gmail.com googlemail.com'));
		$aO365  = $this->whitespaceList($this->configFromPlugin('login-o365',  'domains', 'outlook.com hotmail.com live.com msn.com hotmail.it outlook.it live.it'));
		foreach ($aGmail as $d) if (\str_ends_with($sEmail, '@' . $d)) return 'gmail';
		foreach ($aO365  as $d) if (\str_ends_with($sEmail, '@' . $d)) return 'o365';
		return '';
	}

	private function configFromPlugin(string $sPlugin, string $sKey, string $sDefault) : string
	{
		static $aConfigs = [];
		if (!isset($aConfigs[$sPlugin])) {
			try {
				$oCfg = new \RainLoop\Config\Plugin($sPlugin);
				$oCfg->Load();
				$aConfigs[$sPlugin] = $oCfg;
			} catch (\Throwable $e) {
				$aConfigs[$sPlugin] = null;
			}
		}
		$oCfg = $aConfigs[$sPlugin];
		if ($oCfg) {
			$v = (string) $oCfg->Get('plugin', $sKey, $sDefault);
			if ('' !== \trim($v)) return $v;
		}
		return $sDefault;
	}

	private function whitespaceList(string $s) : array
	{
		$a = \preg_split('/\s+/', \strtolower(\trim($s))) ?: [];
		return \array_values(\array_filter(\array_map('trim', $a)));
	}

	private function envOrTrim(string $sValue, string $sEnv) : string
	{
		$sValue = \trim($sValue);
		if ('' === $sValue) {
			$v = \getenv($sEnv);
			if (\is_string($v)) $sValue = \trim($v);
		}
		return $sValue;
	}

	private function refreshToken(string $sTokenUri, string $sClientId, string $sClientSecret, string $sRefreshToken, ?string $sScope = null) : string
	{
		$oClient = new \OAuth2\Client($sClientId, $sClientSecret);
		$aParams = ['refresh_token' => $sRefreshToken];
		if (null !== $sScope) $aParams['scope'] = $sScope;
		$aResp = $oClient->getAccessToken($sTokenUri, 'refresh_token', $aParams);
		if (200 != $aResp['code'] || empty($aResp['result']['access_token'])) {
			$err = $aResp['result']['error_description'] ?? $aResp['result']['error'] ?? 'unknown';
			throw new \RuntimeException("refresh_token exchange failed: {$err}");
		}
		return (string) $aResp['result']['access_token'];
	}

	private function http(string $sMethod, string $sUrl, string $sBearer, ?array $aJsonBody = null) : array
	{
		$ch = \curl_init($sUrl);
		$aHeaders = ['Authorization: Bearer ' . $sBearer, 'Accept: application/json'];
		\curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $sMethod);
		\curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		\curl_setopt($ch, CURLOPT_TIMEOUT, 30);
		if (null !== $aJsonBody) {
			$aHeaders[] = 'Content-Type: application/json';
			\curl_setopt($ch, CURLOPT_POSTFIELDS, \json_encode($aJsonBody));
		}
		\curl_setopt($ch, CURLOPT_HTTPHEADER, $aHeaders);
		$body = \curl_exec($ch);
		$code = (int) \curl_getinfo($ch, CURLINFO_HTTP_CODE);
		\curl_close($ch);
		$j = \json_decode((string) $body, true);
		return ['code' => $code, 'result' => \is_array($j) ? $j : ['raw' => $body]];
	}

	private function gmailToken(array $aAuth) : string
	{
		$id = $this->envOrTrim($this->configFromPlugin('login-gmail', 'client_id', ''), 'FRICKMAIL_GMAIL_CLIENT_ID');
		$sec = $this->envOrTrim('', 'FRICKMAIL_GMAIL_CLIENT_SECRET');
		if (!$id) throw new \RuntimeException('Gmail client_id not configured');
		return $this->refreshToken(self::GMAIL_TOKEN_URI, $id, $sec, $aAuth['refresh_token']);
	}

	private function o365GraphToken(array $aAuth) : string
	{
		$id = $this->envOrTrim($this->configFromPlugin('login-o365', 'client_id', ''), 'FRICKMAIL_O365_CLIENT_ID');
		$sec = $this->envOrTrim('', 'FRICKMAIL_O365_CLIENT_SECRET');
		$tenant = $this->envOrTrim($this->configFromPlugin('login-o365', 'tenant', 'common'), 'FRICKMAIL_O365_TENANT') ?: 'common';
		if (!$id) throw new \RuntimeException('O365 client_id not configured');
		$uri = \str_replace('{{tenant}}', $tenant, self::O365_TOKEN_URI);
		return $this->refreshToken($uri, $id, $sec, $aAuth['refresh_token'],
			'https://graph.microsoft.com/Calendars.ReadWrite offline_access');
	}

	public function JsonCalendarList() : array
	{
		try {
			$oAccount = $this->currentAccount();
			if (!$oAccount) throw new \RuntimeException('not authenticated');
			$aAuth = $this->loadAuth($oAccount);
			$sProv = $this->detectProvider($oAccount->Email());
			$aCalendars = [];
			if ('gmail' === $sProv) {
				$sToken = $this->gmailToken($aAuth);
				$r = $this->http('GET', 'https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=100', $sToken);
				if (200 != $r['code']) {
					$err = $r['result']['error']['message'] ?? 'HTTP ' . $r['code'];
					throw new \RuntimeException('Google Calendar API: ' . $err . ' — make sure the Google Calendar API is enabled in your Google Cloud project.');
				}
				foreach (($r['result']['items'] ?? []) as $cal) {
					$aCalendars[] = [
						'id'      => (string) ($cal['id'] ?? ''),
						'name'    => (string) ($cal['summary'] ?? $cal['id'] ?? ''),
						'color'   => (string) ($cal['backgroundColor'] ?? '#4a90e2'),
						'primary' => !empty($cal['primary']),
					];
				}
			} elseif ('o365' === $sProv) {
				$sToken = $this->o365GraphToken($aAuth);
				$r = $this->http('GET', 'https://graph.microsoft.com/v1.0/me/calendars?$top=50', $sToken);
				if (200 != $r['code']) {
					$err = $r['result']['error']['message'] ?? 'HTTP ' . $r['code'];
					throw new \RuntimeException('Microsoft Graph: ' . $err);
				}
				foreach (($r['result']['value'] ?? []) as $cal) {
					$aCalendars[] = [
						'id'      => (string) ($cal['id'] ?? ''),
						'name'    => (string) ($cal['name'] ?? $cal['id'] ?? ''),
						'color'   => '#4a90e2',
						'primary' => !empty($cal['isDefaultCalendar']),
					];
				}
			} else {
				throw new \RuntimeException('Calendar requires a Gmail or Office 365 account');
			}
			return $this->jsonResponse(__FUNCTION__, ['calendars' => $aCalendars, 'provider' => $sProv]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['error' => $e->getMessage()]);
		}
	}

	public function JsonCalendarEvents() : array
	{
		try {
			$oAccount = $this->currentAccount();
			if (!$oAccount) throw new \RuntimeException('not authenticated');
			$aAuth = $this->loadAuth($oAccount);
			$sStart = (string) ($this->jsonParam('start') ?: \gmdate('Y-m-d\T00:00:00\Z', \strtotime('first day of this month')));
			$sEnd   = (string) ($this->jsonParam('end')   ?: \gmdate('Y-m-d\T23:59:59\Z', \strtotime('last day of next month')));
			// calendar_ids: JSON-encoded array sent from JS; defaults to ['primary']
			$sCalIds = (string) ($this->jsonParam('calendar_ids') ?: '');
			$aCalIds = $sCalIds ? \json_decode($sCalIds, true) : null;
			if (!\is_array($aCalIds) || empty($aCalIds)) $aCalIds = ['primary'];
			$aCalIds = \array_values(\array_filter(\array_map('strval', $aCalIds)));

			$sProv = $this->detectProvider($oAccount->Email());
			$aEvents = [];
			if ('gmail' === $sProv) {
				$sToken = $this->gmailToken($aAuth);
				$sQuery = \http_build_query([
					'timeMin' => $sStart, 'timeMax' => $sEnd,
					'singleEvents' => 'true', 'orderBy' => 'startTime', 'maxResults' => 250
				]);
				foreach ($aCalIds as $sCalId) {
					$sUrl = 'https://www.googleapis.com/calendar/v3/calendars/' . \rawurlencode($sCalId) . '/events?' . $sQuery;
					$r = $this->http('GET', $sUrl, $sToken);
					if (200 != $r['code']) {
						$err = $r['result']['error']['message'] ?? 'HTTP ' . $r['code'];
						throw new \RuntimeException('Google Calendar API (' . $sCalId . '): ' . $err . ' — make sure the Google Calendar API is enabled in your Google Cloud project and the token has the calendar scope (re-authorize if needed).');
					}
					foreach (($r['result']['items'] ?? []) as $e) {
						$aEvents[] = [
							'id'          => $sCalId . ':' . ($e['id'] ?? ''),
							'_raw_id'     => (string) ($e['id'] ?? ''),
							'_calendar'   => $sCalId,
							'title'       => (string) ($e['summary'] ?? '(no title)'),
							'start'       => (string) ($e['start']['dateTime'] ?? $e['start']['date'] ?? ''),
							'end'         => (string) ($e['end']['dateTime']   ?? $e['end']['date']   ?? ''),
							'allDay'      => isset($e['start']['date']) && !isset($e['start']['dateTime']),
							'description' => (string) ($e['description'] ?? ''),
							'location'    => (string) ($e['location'] ?? ''),
							'provider'    => 'gmail',
						];
					}
				}
			} elseif ('o365' === $sProv) {
				$sToken = $this->o365GraphToken($aAuth);
				if (\count($aCalIds) === 1 && 'primary' === $aCalIds[0]) {
					// default: use /me/calendarview
					$sUrl = 'https://graph.microsoft.com/v1.0/me/calendarview?'
						. \http_build_query(['startDateTime' => $sStart, 'endDateTime' => $sEnd, '$top' => 250, '$orderby' => 'start/dateTime']);
					$r = $this->http('GET', $sUrl, $sToken);
					if (200 != $r['code']) throw new \RuntimeException('Graph calendarview: HTTP ' . $r['code']);
					foreach (($r['result']['value'] ?? []) as $e) {
						$aEvents[] = $this->graphEventToArray($e, 'primary');
					}
				} else {
					foreach ($aCalIds as $sCalId) {
						$sUrl = 'https://graph.microsoft.com/v1.0/me/calendars/' . \rawurlencode($sCalId) . '/calendarview?'
							. \http_build_query(['startDateTime' => $sStart, 'endDateTime' => $sEnd, '$top' => 250]);
						$r = $this->http('GET', $sUrl, $sToken);
						if (200 != $r['code']) throw new \RuntimeException('Graph calendarview (' . $sCalId . '): HTTP ' . $r['code']);
						foreach (($r['result']['value'] ?? []) as $e) {
							$aEvents[] = $this->graphEventToArray($e, $sCalId);
						}
					}
				}
			} else {
				throw new \RuntimeException('Calendar requires a Gmail or Office 365 account');
			}
			// Sort merged events from multiple calendars by start time
			\usort($aEvents, fn($a, $b) => strcmp($a['start'], $b['start']));
			return $this->jsonResponse(__FUNCTION__, ['events' => $aEvents, 'provider' => $sProv]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['error' => $e->getMessage()]);
		}
	}

	private function graphEventToArray(array $e, string $calId) : array
	{
		return [
			'id'          => $calId . ':' . ($e['id'] ?? ''),
			'_raw_id'     => (string) ($e['id'] ?? ''),
			'_calendar'   => $calId,
			'title'       => (string) ($e['subject'] ?? '(no title)'),
			'start'       => (string) ($e['start']['dateTime'] ?? ''),
			'end'         => (string) ($e['end']['dateTime']   ?? ''),
			'allDay'      => (bool) ($e['isAllDay'] ?? false),
			'description' => (string) (\strip_tags((string) ($e['bodyPreview'] ?? ''))),
			'location'    => (string) ($e['location']['displayName'] ?? ''),
			'provider'    => 'o365',
		];
	}

	public function JsonCalendarSave() : array
	{
		try {
			$oAccount = $this->currentAccount();
			if (!$oAccount) throw new \RuntimeException('not authenticated');
			$aAuth = $this->loadAuth($oAccount);
			$sId    = (string) ($this->jsonParam('id') ?: '');
			$sTitle = (string) $this->jsonParam('title');
			$sStart = (string) $this->jsonParam('start');
			$sEnd   = (string) $this->jsonParam('end');
			$sDesc  = (string) ($this->jsonParam('description') ?: '');
			$sLoc   = (string) ($this->jsonParam('location') ?: '');
			$bAll   = (bool)   ($this->jsonParam('allDay') ?: false);
			if ('' === $sTitle || '' === $sStart || '' === $sEnd) throw new \RuntimeException('title/start/end required');

			// id format from JsonCalendarEvents: "calendarId:eventId" — split it
			$sRawId  = (string) ($this->jsonParam('_raw_id') ?: $sId);
			$sCalId  = (string) ($this->jsonParam('_calendar') ?: 'primary');
			// Legacy: if _raw_id not sent, fall back to splitting composite id
			if ('' === $sRawId && \str_contains($sId, ':')) {
				[$sCalId, $sRawId] = \explode(':', $sId, 2);
			}
			if ('' === $sRawId) $sRawId = $sId;

			$sProv = $this->detectProvider($oAccount->Email());
			if ('gmail' === $sProv) {
				$sToken = $this->gmailToken($aAuth);
				$body = ['summary' => $sTitle, 'description' => $sDesc, 'location' => $sLoc];
				if ($bAll) {
					$body['start'] = ['date' => \substr($sStart, 0, 10)];
					$body['end']   = ['date' => \substr($sEnd, 0, 10)];
				} else {
					$body['start'] = ['dateTime' => $sStart];
					$body['end']   = ['dateTime' => $sEnd];
				}
				$base = 'https://www.googleapis.com/calendar/v3/calendars/' . \rawurlencode($sCalId) . '/events';
				$r = $sRawId
					? $this->http('PATCH', $base . '/' . \urlencode($sRawId), $sToken, $body)
					: $this->http('POST',  $base, $sToken, $body);
			} elseif ('o365' === $sProv) {
				$sToken = $this->o365GraphToken($aAuth);
				$body = [
					'subject' => $sTitle,
					'body' => ['contentType' => 'text', 'content' => $sDesc],
					'location' => ['displayName' => $sLoc],
					'isAllDay' => $bAll,
					'start' => ['dateTime' => $sStart, 'timeZone' => 'UTC'],
					'end'   => ['dateTime' => $sEnd,   'timeZone' => 'UTC']
				];
				$base = 'https://graph.microsoft.com/v1.0/me/events';
				$r = $sId
					? $this->http('PATCH', $base . '/' . \urlencode($sId), $sToken, $body)
					: $this->http('POST',  $base, $sToken, $body);
			} else {
				throw new \RuntimeException('Calendar requires a Gmail or Office 365 account');
			}
			if ($r['code'] >= 300) {
				$err = $r['result']['error']['message'] ?? $r['result']['error_description'] ?? 'HTTP ' . $r['code'];
				throw new \RuntimeException($err);
			}
			return $this->jsonResponse(__FUNCTION__, ['ok' => true, 'id' => $r['result']['id'] ?? $sId]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['error' => $e->getMessage()]);
		}
	}

	public function JsonCalendarDelete() : array
	{
		try {
			$oAccount = $this->currentAccount();
			if (!$oAccount) throw new \RuntimeException('not authenticated');
			$aAuth = $this->loadAuth($oAccount);
			$sId    = (string) $this->jsonParam('id');
			$sRawId = (string) ($this->jsonParam('_raw_id') ?: '');
			$sCalId = (string) ($this->jsonParam('_calendar') ?: 'primary');
			if ('' === $sRawId && \str_contains($sId, ':')) {
				[$sCalId, $sRawId] = \explode(':', $sId, 2);
			}
			if ('' === $sRawId) $sRawId = $sId;
			if ('' === $sRawId) throw new \RuntimeException('id required');
			$sProv = $this->detectProvider($oAccount->Email());
			if ('gmail' === $sProv) {
				$r = $this->http('DELETE',
					'https://www.googleapis.com/calendar/v3/calendars/' . \rawurlencode($sCalId) . '/events/' . \urlencode($sRawId),
					$this->gmailToken($aAuth));
			} elseif ('o365' === $sProv) {
				$r = $this->http('DELETE', 'https://graph.microsoft.com/v1.0/me/events/' . \urlencode($sRawId),
					$this->o365GraphToken($aAuth));
			} else {
				throw new \RuntimeException('Calendar requires a Gmail or Office 365 account');
			}
			if ($r['code'] >= 300 && 410 !== $r['code']) {
				throw new \RuntimeException('HTTP ' . $r['code']);
			}
			return $this->jsonResponse(__FUNCTION__, ['ok' => true]);
		} catch (\Throwable $e) {
			\RainLoop\Api::Actions()->Logger()->WriteException($e, \LOG_ERR);
			return $this->jsonResponse(__FUNCTION__, ['error' => $e->getMessage()]);
		}
	}
}
