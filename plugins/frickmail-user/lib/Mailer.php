<?php
namespace Frickmail\User;

/**
 * Thin SMTP sender for transactional Frickmail emails (password-reset link, …).
 * Reads connection details from FRICKMAIL_SMTP_* env-vars; falls back to
 * PHP's mail() if FRICKMAIL_SMTP_HOST is empty (development convenience).
 */
class Mailer
{
	public static function smtpHost() : string  { return (string) (\getenv('FRICKMAIL_SMTP_HOST') ?: ''); }
	public static function smtpPort() : int     { return (int) (\getenv('FRICKMAIL_SMTP_PORT') ?: 587); }
	public static function smtpSecure() : string { return \strtolower((string) (\getenv('FRICKMAIL_SMTP_SECURE') ?: 'tls')); }
	public static function smtpUser() : string  { return (string) (\getenv('FRICKMAIL_SMTP_USER') ?: ''); }
	public static function smtpPassword() : string { return (string) (\getenv('FRICKMAIL_SMTP_PASSWORD') ?: ''); }
	public static function smtpFrom() : string  { return (string) (\getenv('FRICKMAIL_SMTP_FROM') ?: 'no-reply@frickmail.local'); }

	public static function isConfigured() : bool
	{
		return '' !== self::smtpHost();
	}

	public static function send(string $sTo, string $sSubject, string $sBody) : void
	{
		if (!\filter_var($sTo, \FILTER_VALIDATE_EMAIL)) {
			throw new \RuntimeException('Recipient email is invalid');
		}
		$sFrom = self::smtpFrom();
		$sMessage = self::buildRfc5322Message($sFrom, $sTo, $sSubject, $sBody);

		if (!self::isConfigured()) {
			// Fallback: PHP mail(). Useful when the container has a local sendmail.
			$ok = \mail($sTo, $sSubject, $sBody, "From: {$sFrom}\r\nContent-Type: text/plain; charset=utf-8\r\n");
			if (!$ok) {
				throw new \RuntimeException('SMTP not configured and PHP mail() failed');
			}
			return;
		}

		$oSettings = new \MailSo\Smtp\Settings();
		$oSettings->host = self::smtpHost();
		$oSettings->port = self::smtpPort();
		$oSettings->type = match (self::smtpSecure()) {
			'ssl', 'tls' => \MailSo\Net\Enumerations\ConnectionSecurityType::SSL,
			'starttls'   => \MailSo\Net\Enumerations\ConnectionSecurityType::STARTTLS,
			default      => \MailSo\Net\Enumerations\ConnectionSecurityType::NONE,
		};
		$oSettings->Ehlo = \gethostname() ?: 'frickmail';
		$oSettings->useAuth = '' !== self::smtpUser();
		$oSettings->username = self::smtpUser();
		$oSettings->passphrase = self::smtpPassword();

		$oSmtp = new \MailSo\Smtp\SmtpClient();
		$oSmtp->Connect($oSettings);
		if ($oSettings->useAuth) {
			$oSmtp->Login($oSettings);
		}
		$oSmtp->MailFrom($sFrom);
		$oSmtp->Rcpt($sTo);
		$oSmtp->Data($sMessage);
		$oSmtp->Logout();
		$oSmtp->Disconnect();
	}

	private static function buildRfc5322Message(string $sFrom, string $sTo, string $sSubject, string $sBody) : string
	{
		$aHeaders = [
			'Date' => \gmdate('r'),
			'From' => $sFrom,
			'To' => $sTo,
			'Subject' => '=?UTF-8?B?' . \base64_encode($sSubject) . '?=',
			'MIME-Version' => '1.0',
			'Content-Type' => 'text/plain; charset=UTF-8',
			'Content-Transfer-Encoding' => '8bit',
			'X-Mailer' => 'Frickmail',
		];
		$sLines = [];
		foreach ($aHeaders as $k => $v) {
			$sLines[] = "{$k}: {$v}";
		}
		return \implode("\r\n", $sLines) . "\r\n\r\n" . $sBody;
	}
}
