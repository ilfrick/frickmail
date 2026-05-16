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
		VERSION     = '1.4',
		RELEASE     = '2026-05-16',
		REQUIRED    = '2.36.1',
		CATEGORY    = 'Appearance',
		DESCRIPTION = 'Frickmail: Gmail-style UI with dark/light/system themes.';

	public function Init() : void
	{
		$this->UseLangs(false);
		// Load CSS in order: tokens first, then layout, then components, login last
		$this->addCss('css/tokens.css');
		$this->addCss('css/layout.css');
		$this->addCss('css/components.css');
		$this->addCss('css/login.css');
		$this->addJs('js/ThemeSwitcher.js');
	}
}
