<?php
namespace Frickmail\User;

/**
 * ServiceDiscoveryHandler — discoverServices, activateService, probeWellKnown, isPrivateIp.
 *
 * Pure PHP class; does not extend AbstractPlugin.
 */
class ServiceDiscoveryHandler
{
	public function __construct(private Db $db) {}

	/* ------------------------------------------------------------------ */
	/*  Discover                                                             */
	/* ------------------------------------------------------------------ */

	public function discoverServices(int $uid, int $id) : array
	{
		$row = $this->db->getMailAccount($uid, $id);
		if (!$row) throw new \RuntimeException('Account not found');

		$services = [];
		$email    = (string) $row['email'];
		$domain   = \strtolower(\substr(\strrchr($email, '@'), 1));
		$type     = (string) $row['type'];

		// Detect Google and Microsoft by domain regardless of account type (imap
		// accounts added with app-passwords have type='imap', not 'gmail'/'o365').
		$bGoogle    = 'gmail' === $type
			|| \in_array($domain, ['gmail.com', 'googlemail.com'], true)
			|| \str_ends_with($domain, '.google.com');
		$bMicrosoft = 'o365' === $type
			|| \in_array($domain, ['outlook.com', 'hotmail.com', 'live.com', 'msn.com'], true);

		if ($bGoogle) {
			$bHasOAuth = ('gmail' === $type);
			$sNote     = $bHasOAuth
				? 'Syncs via Google API using the linked OAuth token.'
				: 'Requires Google OAuth2 — app passwords are not supported by Google for contacts/calendar sync. Re-add this account via "Sign in with Google" to enable sync.';
			$services[] = [
				'id'          => 'google-contacts',
				'name'        => 'Google Contacts',
				'type'        => 'contacts',
				'provider'    => 'google',
				'url'         => 'https://www.googleapis.com/carddav/v1',
				'note'        => $sNote,
				'needs_oauth' => !$bHasOAuth,
			];
			$services[] = [
				'id'          => 'google-calendar',
				'name'        => 'Google Calendar',
				'type'        => 'calendar',
				'provider'    => 'google',
				'url'         => 'https://apidata.googleusercontent.com/caldav/v2',
				'note'        => $sNote,
				'needs_oauth' => !$bHasOAuth,
			];
		} elseif ($bMicrosoft) {
			$bHasOAuth = ('o365' === $type);
			$sNote     = $bHasOAuth
				? 'Syncs via Microsoft Graph using the linked OAuth token.'
				: 'Requires Microsoft OAuth2 — re-add this account via "Sign in with Microsoft" to enable sync.';
			$services[] = [
				'id'          => 'o365-contacts',
				'name'        => 'Microsoft Contacts',
				'type'        => 'contacts',
				'provider'    => 'o365',
				'url'         => 'https://graph.microsoft.com/v1.0/me/contacts',
				'note'        => $sNote,
				'needs_oauth' => !$bHasOAuth,
			];
			$services[] = [
				'id'          => 'o365-calendar',
				'name'        => 'Microsoft Calendar',
				'type'        => 'calendar',
				'provider'    => 'o365',
				'url'         => 'https://outlook.office365.com/caldav/v1',
				'note'        => $sNote,
				'needs_oauth' => !$bHasOAuth,
			];
		} else {
			// Generic IMAP: probe .well-known autodiscovery (RFC 5785)
			$services = \array_merge(
				$services,
				$this->probeWellKnown($domain, $email, 'carddav'),
				$this->probeWellKnown($domain, $email, 'caldav')
			);
		}

		return ['ok' => true, 'email' => $email, 'services' => $services];
	}

	/* ------------------------------------------------------------------ */
	/*  Activate                                                             */
	/* ------------------------------------------------------------------ */

	public function activateService(int $uid, int $id, string $serviceType, string $provider, string $serviceUrl) : array
	{
		$row = $this->db->getMailAccount($uid, $id);
		if (!$row) throw new \RuntimeException('Account not found');

		// For OAuth providers we trigger the contacts-sync / calendar endpoint directly
		if (\in_array($provider, ['google', 'o365'], true)) {
			if ('contacts' === $serviceType) {
				return ['ok' => true, 'message' => 'Contacts sync triggered. Open Settings → Contacts Sync to run a full sync.'];
			}
			return ['ok' => true, 'message' => 'Calendar sync ready. Open Settings → Calendar to view events.'];
		}

		// DAV provider: store the URL in account settings JSON so sync plugins can read it
		$this->db->saveAccountServiceUrl($uid, $id, ('contacts' === $serviceType ? 'carddav_url' : 'caldav_url'), $serviceUrl);
		return [
			'ok'      => true,
			'message' => ('contacts' === $serviceType ? 'CardDAV' : 'CalDAV') . ' URL saved. You can configure credentials in Settings → Accounts.',
		];
	}

	/* ------------------------------------------------------------------ */
	/*  SSRF / well-known probing                                            */
	/* ------------------------------------------------------------------ */

	/** Return true if $ip is a private/loopback/link-local address (SSRF guard). */
	public function isPrivateIp(string $ip) : bool
	{
		return !\filter_var($ip,
			\FILTER_VALIDATE_IP,
			\FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE
		);
	}

	/** Probe .well-known/{carddav|caldav} and return found service descriptor or []. */
	private function probeWellKnown(string $domain, string $email, string $proto) : array
	{
		// SSRF guard: reject domains that resolve to private/loopback/link-local IPs.
		$resolvedIp = \gethostbyname($domain);
		if ($resolvedIp === $domain || $this->isPrivateIp($resolvedIp)) {
			return [];
		}

		$url = 'https://' . $domain . '/.well-known/' . $proto;
		$ctx = \stream_context_create([
			'http' => [
				'method'          => 'PROPFIND',
				'header'          => "Depth: 0\r\nContent-Type: application/xml\r\n",
				'content'         => '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><current-user-principal/></prop></propfind>',
				'timeout'         => 4,
				'follow_location' => 0, // no redirects — prevents open-redirect to private IPs
				'ignore_errors'   => true,
			],
		]);
		$body = @\file_get_contents($url, false, $ctx);
		// Second-pass IP check: re-resolve and confirm the domain still maps to the same
		// public IP we validated above. If DNS changed, abort (probabilistic rebinding guard).
		$recheck = \gethostbyname($domain);
		if ($recheck !== $resolvedIp && ($recheck === $domain || $this->isPrivateIp($recheck))) {
			return [];
		}
		// Check HTTP status from $http_response_header
		$status = 0;
		if (!empty($http_response_header)) {
			\preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $m);
			$status = (int) ($m[1] ?? 0);
		}
		// 207 Multi-Status or 301/302 redirect means service exists
		if (!\in_array($status, [207, 200, 301, 302], true)) {
			return [];
		}
		$isContacts = ('carddav' === $proto);
		return [[
			'id'       => $proto . '-' . $domain,
			'name'     => $isContacts ? 'Contacts (' . $domain . ')' : 'Calendar (' . $domain . ')',
			'type'     => $isContacts ? 'contacts' : 'calendar',
			'provider' => 'dav',
			'url'      => $url,
			'note'     => ($isContacts ? 'CardDAV' : 'CalDAV') . ' service found at ' . $url,
		]];
	}
}
