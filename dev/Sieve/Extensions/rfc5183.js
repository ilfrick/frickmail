/**
 * https://tools.ietf.org/html/rfc5183
 */

import {
	GrammarQuotedString,
	GrammarStringList,
	TestCommand
} from 'Sieve/Grammar';

export class EnvironmentTest extends TestCommand
{
	constructor()
	{
		super();
		this._name    = new GrammarQuotedString;
		this.key_list = new GrammarStringList;
	}

	get name() { return this._name.value; }
	set name(v) { this._name.value = v; }

	get require() { return 'environment'; }

	toString()
	{
		return 'environment'
			+ (this.comparator ? ' :comparator ' + this.comparator : '')
			+ ' ' + this.match_type
			+ ' ' + this._name
			+ ' ' + this.key_list;
	}

	pushArguments(args)
	{
		this.key_list = args.pop();
		this._name    = args.pop();
	}
}
