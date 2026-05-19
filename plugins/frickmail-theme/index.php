<?php
/**
 * Frickmail Theme — complete visual overhaul matching the UI mockups.
 * Implements dark / light / system themes with CSS variables and injects
 * the Gmail-style icon navigation column via JS.
 */
class FrickmailThemePlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME        = 'Frickmail Theme',
		VERSION     = '2.0',
		RELEASE     = '2026-05-19',
		REQUIRED    = '2.36.1',
		CATEGORY    = 'Appearance',
		DESCRIPTION = 'Frickmail: Gmail-style UI with dark/light/system themes.';

	public function Init() : void
	{
		$this->UseLangs(false);
		// User UI: tokens → layout → components → login
		$this->addCss('css/tokens.css');
		$this->addCss('css/layout.css');
		$this->addCss('css/components.css');
		$this->addCss('css/login.css');
		$this->addJs('js/ThemeSwitcher.js');
		// Admin UI: tokens + admin-specific overrides
		$this->addCss('css/tokens.css',          true);
		$this->addCss('css/admin-overrides.css', true);
	}
}
