<?php
/**
 * https://haveibeenpwned.com/API/v3
 */

use RainLoop\Model\Account;
use MailSo\Imap\ImapClient;
use MailSo\Imap\Settings as ImapSettings;
use MailSo\Sieve\SieveClient;
use MailSo\Sieve\Settings as SieveSettings;
use MailSo\Smtp\SmtpClient;
use MailSo\Smtp\Settings as SmtpSettings;
use MailSo\Mime\Message as MimeMessage;

class HaveibeenpwnedPlugin extends \RainLoop\Plugins\AbstractPlugin
{
//	use \MailSo\Log\Inherit;

	const
		NAME     = 'Have i been pwned',
		AUTHOR   = 'SnappyMail',
		URL      = 'https://snappymail.eu/',
		VERSION  = '0.1',
		RELEASE  = '2024-04-22',
		REQUIRED = '2.14.0',
		CATEGORY = 'General',
		LICENSE  = 'MIT',
		DESCRIPTION = 'Check if your passphrase or email address is in a data breach';

	public function Init() : void
	{
//		$this->UseLangs(true);
		$this->addJs('hibp.js');
		$this->addJsonHook('HibpCheck');
	}

	public function HibpCheck()
	{
//		$oAccount = $this->Manager()->Actions()->GetAccount();
		$oAccount = $this->Manager()->Actions()->getAccountFromToken();
//		$oAccount = \RainLoop\Api::Actions()->getAccountFromToken();

		$HTTP = \SnappyMail\HTTP\Request::factory();

		$breached = null;
		$api_key = \trim($this->Config()->Get('plugin', 'hibp-api-key', ''));
		if ($api_key) {
			$breached = $HTTP->doRequest('GET', "https://haveibeenpwned.com/api/v3/breachedaccount/{$oAccount->Email()}", null, [
				'hibp-api-key' => $api_key
			]);
		}

		$pass = \sha1($oAccount->ImapPass());
		$prefix = \substr($pass, 0, 5);
		$suffix = \substr($pass, 5);
		$response = $HTTP->doRequest('GET', "https://api.pwnedpasswords.com/range/{$prefix}");
		$passwords = [];
		foreach (\preg_split('/\\R/', $response->body) as $entry) {
			if ($entry) {
				$entry = \explode(':', $entry);
				$passwords[$entry[0]] = (int) $entry[1];
			}
		}

		return $this->jsonResponse(__FUNCTION__, array(
			'pwned' => isset($passwords[$suffix]) ? $passwords[$suffix] : 0,
			'breached' => $breached ? [
				'request_uri' => $breached->request_uri,
				'final_uri' => $breached->final_uri,
				'status' => $breached->status,
				'headers' => $breached->headers,
				'body' => $breached->body
			] : []
		));
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance("hibp-api-key")
				->SetLabel('API key')
				->SetDescription('https://haveibeenpwned.com/API/Key')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
		];
	}
}
