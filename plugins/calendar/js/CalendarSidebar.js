// Injects a calendar icon button in the MailFolderList left sidebar,
// next to the contacts button. Clicking it navigates to the calendar
// settings tab (same tab used for the full calendar view).

addEventListener('rl-view-model', e => {
	if (e.detail?.viewModelTemplateID !== 'MailFolderList') return;
	const dom = e.detail.viewModelDom;
	if (!dom) return;

	setTimeout(() => {
		const contactsBtn = dom.querySelector('.buttonContacts');
		if (!contactsBtn || dom.querySelector('.buttonCalendar')) return;

		const btn = document.createElement('a');
		btn.className = 'btn buttonCalendar fontastic';
		btn.title = 'Calendar';
		btn.href = '#';
		btn.textContent = '📅';
		btn.addEventListener('click', e => {
			e.preventDefault();
			// Navigate to the calendar settings tab
			location.hash = '#/settings/calendar';
		});

		contactsBtn.insertAdjacentElement('afterend', btn);
	}, 0);
});
