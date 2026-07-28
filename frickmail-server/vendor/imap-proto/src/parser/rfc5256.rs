//!
//! https://tools.ietf.org/html/rfc5256
//!
//! SORT extension
//!

use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::{map, opt, verify},
    multi::{many0, many1},
    sequence::{delimited, pair, preceded, terminated},
    IResult,
};

use crate::{
    parser::core::number,
    types::{MailboxDatum, Thread, ThreadMember},
};

/// BASE.7.2.SORT. SORT Response
///
/// Data:       zero or more numbers
///
/// The SORT response occurs as a result of a SORT or UID SORT
/// command.  The number(s) refer to those messages that match the
/// search criteria.  For SORT, these are message sequence numbers;
/// for UID SORT, these are unique identifiers.  Each number is
/// delimited by a space.
///
/// Example:
///
/// ```ignore
///     S: * SORT 2 3 6
/// ```
///
/// [RFC5256 - 4 Additional Responses](https://tools.ietf.org/html/rfc5256#section-4)
pub(crate) fn mailbox_data_sort(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        // Technically, trailing whitespace is not allowed for the SEARCH command,
        // but multiple email servers in the wild seem to have it anyway (see #34, #108).
        // Since the SORT command extends the SEARCH command, the trailing whitespace
        // is exceptionnaly allowed here (as for the SEARCH command).
        terminated(
            preceded(
                preceded(
                    opt(terminated(tag_no_case(b"UID"), tag(" "))),
                    tag_no_case(b"SORT"),
                ),
                many0(preceded(tag(" "), number)),
            ),
            opt(tag(" ")),
        ),
        MailboxDatum::Sort,
    )(i)
}

fn thread_message(i: &[u8]) -> IResult<&[u8], ThreadMember> {
    map(verify(number, |number| *number > 0), ThreadMember::Message)(i)
}

fn thread_members(i: &[u8]) -> IResult<&[u8], Thread> {
    let (i, first) = thread_message(i)?;
    let (i, rest) = many0(preceded(tag(" "), thread_message))(i)?;
    let (i, nested) = opt(preceded(tag(" "), thread_nested))(i)?;

    let mut members =
        Vec::with_capacity(1 + rest.len() + nested.as_ref().map(Vec::len).unwrap_or_default());
    members.push(first);
    members.extend(rest);
    if let Some(nested) = nested {
        members.extend(nested.into_iter().map(ThreadMember::Nested));
    }
    Ok((i, Thread { members }))
}

fn thread_nested(i: &[u8]) -> IResult<&[u8], Vec<Thread>> {
    let (i, (first, second)) = pair(thread_list, thread_list)(i)?;
    let (i, rest) = many0(thread_list)(i)?;
    let mut threads = Vec::with_capacity(2 + rest.len());
    threads.push(first);
    threads.push(second);
    threads.extend(rest);
    Ok((i, threads))
}

fn thread_list(i: &[u8]) -> IResult<&[u8], Thread> {
    delimited(
        tag("("),
        alt((
            thread_members,
            map(thread_nested, |threads| Thread {
                members: threads.into_iter().map(ThreadMember::Nested).collect(),
            }),
        )),
        tag(")"),
    )(i)
}

/// BASE.7.2.THREAD. THREAD Response
pub(crate) fn mailbox_data_thread(i: &[u8]) -> IResult<&[u8], MailboxDatum<'_>> {
    map(
        preceded(
            preceded(
                opt(terminated(tag_no_case(b"UID"), tag(" "))),
                tag_no_case(b"THREAD"),
            ),
            opt(preceded(tag(" "), many1(thread_list))),
        ),
        |threads| MailboxDatum::Thread(threads.unwrap_or_default()),
    )(i)
}
