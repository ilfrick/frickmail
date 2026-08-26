import { cp, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const root = process.cwd();
const outputRoot = path.resolve(process.argv[2] ?? 'frickmail-static');
let staticRoot = path.join(root, 'snappymail/v/0.0.0/static');
const templatesRoot = path.join(root, 'snappymail/v/0.0.0/app/templates/Views');
const themesRoot = path.join(root, 'snappymail/v/0.0.0/themes');

for (const directory of [staticRoot, themesRoot]) {
  await mkdir(directory, { recursive: true });
}

await mkdir(path.join(outputRoot, 'js/min'), { recursive: true });
await cp(staticRoot, outputRoot, { recursive: true });
await cp(path.join(root, 'snappymail/v/0.0.0/themes'), path.join(outputRoot, 'themes'), {
  recursive: true,
});

const pluginFiles = [
  ['plugins/login-oidc/LoginOIDC.js', false],
  ['plugins/frickmail-theme/js/ThemeSwitcher.js', false],
  ['plugins/frickmail-theme/js/KeyboardShortcuts.js', false],
  ['plugins/frickmail-user/js/utils.js', false],
  ['plugins/frickmail-user/js/Login.js', false],
  ['plugins/frickmail-user/js/AccountSwitcher.js', false],
  ['plugins/frickmail-user/js/MailAccountsSettings.js', false],
  ['plugins/frickmail-user/js/TwoFactorSettings.js', false],
  ['plugins/frickmail-user/js/Search.js', false],
  ['plugins/frickmail-user/js/UnifiedInbox.js', false],
  ['plugins/frickmail-user/js/IdentitySettings.js', false],
  ['plugins/frickmail-user/js/Rules.js', false],
  ['plugins/frickmail-user/js/UserPrefs.js', false],
  ['plugins/frickmail-user/js/Notifications.js', false],
  ['plugins/frickmail-user/js/ImportExport.js', false],
  ['plugins/frickmail-user/js/Tasks.js', false],
  ['plugins/frickmail-user/js/SmimeSettings.js', false],
  ['plugins/frickmail-user/js/GraphMailbox.js', false],
];

let plugins = '';
for (const [file] of pluginFiles) {
  plugins += `${await readFile(path.join(root, file), 'utf8')}\n;\n`;
}
for (const directory of ['plugins/calendar/js', 'plugins/contacts-sync/js']) {
  const entries = (await readdir(path.join(root, directory))).filter((entry) => entry.endsWith('.js')).sort();
  for (const entry of entries) {
    plugins += `${await readFile(path.join(root, directory, entry), 'utf8')}\n;\n`;
  }
}

await writeFile(path.join(outputRoot, 'frickmail-plugins.js'), plugins);

const templateEntries = [
  ...(await readdir(templatesRoot, { recursive: true })).filter((entry) => entry.endsWith('.html')),
].sort();
let templates = '';
for (const entry of templateEntries) {
  if (/\/Admin(?:Login|Menu|Pane|Settings[^/]*)\.html$/.test(entry.replace(/\\/g, '/'))) {
    continue;
  }
  const id = path.basename(entry, '.html').replace(/[^a-zA-Z0-9]/g, '');
  const source = await readFile(path.join(templatesRoot, entry), 'utf8');
  const safeSource = source.replace(/<(\/?)script/gi, '<$1x-script');
  templates += `<template id="${id}">${safeSource}</template>`;
}

for (const file of [
  'FrickmailMailAccountsSettings.html',
  'FrickmailTwoFactorSettingsTab.html',
  'FrickmailUserPrefsTab.html',
  'FrickmailIdentitySettings.html',
  'FrickmailRulesSettings.html',
  'FrickmailSmimeSettings.html',
  'FrickmailImportExportTab.html',
]) {
  const source = await readFile(
    path.join(root, 'plugins/frickmail-user/templates', file),
    'utf8',
  );
  const safeSource = source.replace(/<(\/?)script/gi, '<$1x-script');
  templates += `<template id="${path.basename(file, '.html')}">${safeSource}</template>`;
}

const themeFiles = [
  'plugins/frickmail-theme/css/tokens.css',
  'plugins/frickmail-theme/css/layout.css',
  'plugins/frickmail-theme/css/components.css',
  'plugins/frickmail-theme/css/login.css',
];
let themeCss = '';
for (const file of themeFiles) {
  themeCss += `${await readFile(path.join(root, file), 'utf8')}\n`;
}
themeCss += await readFile(
  path.join(root, 'snappymail/v/0.0.0/themes/Default/styles.css'),
  'utf8',
);
if (!templates.includes('<template id="Login">')) throw new Error('Core Login template missing');

const localizationRoot = path.join(root, 'snappymail/v/0.0.0/app/localization');
const langs = JSON.parse(await readFile(path.join(localizationRoot, 'langs.json'), 'utf8'));
const mergeValue = (target, source) => {
  for (const [key, value] of Object.entries(source)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      target[key] ??= {};
      mergeValue(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
};
let language = mergeValue({}, langs);
language = mergeValue(language, JSON.parse(await readFile(path.join(localizationRoot, 'en/user.json'), 'utf8')));
language = mergeValue(language, JSON.parse(await readFile(path.join(localizationRoot, 'en/admin.json'), 'utf8')));
const relativeTime = (
  await readFile(path.join(localizationRoot, 'en/relativetimeformat.js'), 'utf8')
).trim();
const bootLanguage = `document.documentElement.lang='en';rl.I18N=${JSON.stringify(language)};rl.relativeTime=${relativeTime};`;
await writeFile(path.join(outputRoot, 'frickmail-boot-language.js'), bootLanguage);

const bootScript = await readFile(
  path.join(root, 'snappymail/v/0.0.0/static/js/min/boot.min.js'),
  'utf8',
);
const indexHtml = `<!doctype html>
<html lang="en" class="rl-started-trigger">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>Frickmail</title>
<link rel="manifest" href="/static/manifest.json"><link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/static/css/app.min.css"><link rel="stylesheet" href="/static/frickmail-theme.css"></head>
<body id="rl-app" data-admin="0" spellcheck="false">
<div id="rl-loading"><div id="rl-loading-desc">Frickmail</div><i class="icon-spinner"></i></div>
<div id="rl-loading-error" hidden="">An error occurred.</div>
<div id="rl-BadBrowser" hidden="">Unsupported browser</div>
<div id="rl-NoCookie" hidden="">Cookies required</div>
<div id="rl-content" hidden=""><div id="rl-left"></div><div id="rl-right"></div></div>
<div id="rl-popups"></div>
${templates}
<script>${bootScript}${bootLanguage}</script>
<script src="/static/js/min/libs.min.js"></script>
<script src="/static/js/min/app.min.js"></script>
<script src="/static/js/min/openpgp.min.js"></script>
<script src="/static/frickmail-plugins.js"></script>
</body></html>`;

await writeFile(path.join(outputRoot, 'index.html'), indexHtml);
