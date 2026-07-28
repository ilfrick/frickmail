//! RFC 4731 ESEARCH response with RFC 7377 mailbox correlators.

use std::borrow::Cow;

use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1},
    character::streaming::{char, one_of},
    combinator::{map, map_res, opt, recognize, value},
    multi::{many0, separated_list1},
    sequence::{delimited, pair, preceded, tuple},
    IResult,
};

use crate::{
    parser::core::{is_astring_char, is_quoted_specials, is_text_char, literal, number, number_64},
    types::{ESearchResult, ESearchSequenceRange, ESearchSequenceValue, MailboxDatum},
};

enum Correlator<'a> {
    Tag(Cow<'a, str>),
    Mailbox(Cow<'a, str>),
    UidValidity(u32),
}

enum ReturnData {
    All(Vec<ESearchSequenceRange>),
    Min(u32),
    Max(u32),
    Count(u32),
    ModSeq(u64),
}

fn nz_number(i: &[u8]) -> IResult<&[u8], u32> {
    map_res(
        recognize(pair(
            one_of("123456789"),
            take_while(|byte: u8| byte.is_ascii_digit()),
        )),
        |bytes| {
            std::str::from_utf8(bytes)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(())
        },
    )(i)
}

fn unescape_quoted(value: &[u8]) -> Result<Cow<'_, str>, std::str::Utf8Error> {
    let value = std::str::from_utf8(value)?;
    if !value.as_bytes().contains(&b'\\') {
        return Ok(Cow::Borrowed(value));
    }

    let mut unescaped = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character == '\\' {
            if let Some(escaped) = chars.next() {
                unescaped.push(escaped);
            }
        } else {
            unescaped.push(character);
        }
    }
    Ok(Cow::Owned(unescaped))
}

fn correlator_astring(i: &[u8]) -> IResult<&[u8], Cow<'_, str>> {
    alt((
        map_res(
            delimited(
                char('"'),
                recognize(many0(alt((
                    take_while1(|byte| {
                        (is_text_char(byte) || byte >= 0x80) && !is_quoted_specials(byte)
                    }),
                    recognize(pair(char('\\'), one_of("\\\""))),
                )))),
                char('"'),
            ),
            unescape_quoted,
        ),
        map_res(literal, |value| {
            std::str::from_utf8(value).map(Cow::Borrowed)
        }),
        map_res(take_while1(is_astring_char), |value| {
            std::str::from_utf8(value).map(Cow::Borrowed)
        }),
    ))(i)
}

fn sequence_value(i: &[u8]) -> IResult<&[u8], ESearchSequenceValue> {
    alt((
        value(ESearchSequenceValue::Star, tag("*")),
        map(nz_number, ESearchSequenceValue::Number),
    ))(i)
}

fn sequence_range(i: &[u8]) -> IResult<&[u8], ESearchSequenceRange> {
    map(
        pair(sequence_value, opt(preceded(tag(":"), sequence_value))),
        |(start, end)| ESearchSequenceRange {
            end: end.unwrap_or_else(|| start.clone()),
            start,
        },
    )(i)
}

fn sequence_set(i: &[u8]) -> IResult<&[u8], Vec<ESearchSequenceRange>> {
    separated_list1(tag(","), sequence_range)(i)
}

fn correlator(i: &[u8]) -> IResult<&[u8], Correlator<'_>> {
    alt((
        map(
            preceded(tag_no_case("TAG "), correlator_astring),
            Correlator::Tag,
        ),
        map(
            preceded(tag_no_case("MAILBOX "), correlator_astring),
            Correlator::Mailbox,
        ),
        map(
            preceded(tag_no_case("UIDVALIDITY "), nz_number),
            Correlator::UidValidity,
        ),
    ))(i)
}

fn correlators(i: &[u8]) -> IResult<&[u8], Vec<Correlator<'_>>> {
    delimited(tag("("), separated_list1(tag(" "), correlator), tag(")"))(i)
}

fn return_data(i: &[u8]) -> IResult<&[u8], ReturnData> {
    alt((
        map(preceded(tag_no_case("ALL "), sequence_set), ReturnData::All),
        map(preceded(tag_no_case("MIN "), nz_number), ReturnData::Min),
        map(preceded(tag_no_case("MAX "), nz_number), ReturnData::Max),
        map(preceded(tag_no_case("COUNT "), number), ReturnData::Count),
        map(
            preceded(tag_no_case("MODSEQ "), number_64),
            ReturnData::ModSeq,
        ),
    ))(i)
}

pub(crate) fn mailbox_data_esearch(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map_res(
        tuple((
            tag_no_case("ESEARCH"),
            opt(preceded(tag(" "), correlators)),
            opt(preceded(tag(" "), value((), tag_no_case("UID")))),
            many0(preceded(tag(" "), return_data)),
        )),
        |(_, correlators, uid, data)| {
            let mut result = ESearchResult {
                tag: None,
                mailbox: None,
                uid_validity: None,
                uid: uid.is_some(),
                all: Vec::new(),
                min: None,
                max: None,
                count: None,
                mod_seq: None,
            };
            for correlator in correlators.into_iter().flatten() {
                match correlator {
                    Correlator::Tag(tag) => {
                        if result.tag.replace(tag).is_some() {
                            return Err(());
                        }
                    }
                    Correlator::Mailbox(mailbox) => {
                        if result.mailbox.replace(mailbox).is_some() {
                            return Err(());
                        }
                    }
                    Correlator::UidValidity(uid_validity) => {
                        if result.uid_validity.replace(uid_validity).is_some() {
                            return Err(());
                        }
                    }
                }
            }
            for data in data {
                match data {
                    ReturnData::All(all) => result.all = all,
                    ReturnData::Min(min) => result.min = Some(min),
                    ReturnData::Max(max) => result.max = Some(max),
                    ReturnData::Count(count) => result.count = Some(count),
                    ReturnData::ModSeq(mod_seq) => result.mod_seq = Some(mod_seq),
                }
            }
            Ok(MailboxDatum::ESearch(result))
        },
    )(i)
}
