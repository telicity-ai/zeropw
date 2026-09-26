//! The subset of CPython 3.12's `argparse` (and the `textwrap` wrapping its
//! help formatter uses) that the administrator and agent CLIs are built from.
//!
//! The Python CLIs are the specification of their own command-line contract:
//! which tokens are options, which subparser reports an error, the exact
//! usage/help text (wrapped to the terminal width like `HelpFormatter`), and
//! every error message. Rather than approximating that per command, this
//! module ports the algorithms themselves -- `_parse_known_args`,
//! `_parse_optional`/`_get_option_tuples`, the nargs patterns, `_get_values`,
//! `HelpFormatter._format_usage`/`_format_action` and
//! `textwrap.TextWrapper._split`/`_wrap_chunks` -- for the features those
//! CLIs use: long options plus `-h`, `store`/`store_true`/`append`/`help`
//! actions, `type=int` (CPython `int()` grammar via [`crate::pystr`]),
//! custom type checks, `choices`, `required`, defaults, `metavar`,
//! (required) mutually exclusive groups, positionals with `nargs=None`, and
//! nested required subparsers.
//!
//! Parsing never prints: it returns [`Outcome`], and the caller writes help or
//! the error in its own format (`admin_cli` emits JSON, `agent_cli` argparse's
//! `prog: error: message`).
use std::collections::BTreeMap;

use regex::Regex;

use crate::pystr;

const SUPPRESS: &str = "==SUPPRESS==";

/// A value in the parsed namespace.
#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    None,
    Str(String),
    Int(i128),
    Bool(bool),
    List(Vec<String>),
}

impl Val {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// `argparse.Namespace`.
pub type Namespace = BTreeMap<String, Val>;

/// A `type=` conversion. `Err(Some(msg))` is an `ArgumentTypeError(msg)`;
/// `Err(None)` a `ValueError`, reported as `invalid <name> value: <repr>`.
#[derive(Clone, Copy)]
pub struct TypeFn {
    pub name: &'static str,
    pub convert: fn(&str) -> Result<Val, Option<String>>,
}

/// `type=int`. CPython's `int()` is arbitrary precision; a magnitude
/// beyond `i128` saturates (callers narrow further, see `DEVIATIONS.md`).
pub const INT: TypeFn = TypeFn {
    name: "int",
    convert: |s| pystr::int_from_str(s).map(Val::Int).ok_or(None),
};

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Store,
    StoreTrue,
    Append,
    Help,
    Subparsers,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Nargs {
    /// `nargs=None`: exactly one.
    One,
    /// `nargs=0` (flags and help).
    Zero,
    /// `nargs=PARSER` (`A...`), the subparsers action.
    Parser,
}

/// One `add_argument` call.
#[derive(Clone)]
pub struct Arg {
    option_strings: Vec<String>,
    dest: String,
    kind: Kind,
    nargs: Nargs,
    required: bool,
    choices: Option<Vec<String>>,
    ty: Option<TypeFn>,
    default: Val,
    metavar: Option<String>,
    help: Option<String>,
}

impl Arg {
    /// `add_argument("--long", ...)` storing one value.
    pub fn opt(name: &str) -> Self {
        let dest = name.trim_start_matches('-').replace('-', "_");
        Self {
            option_strings: vec![name.to_owned()],
            dest,
            kind: Kind::Store,
            nargs: Nargs::One,
            required: false,
            choices: None,
            ty: None,
            default: Val::None,
            metavar: None,
            help: None,
        }
    }
    /// `add_argument("name")`: a required positional.
    pub fn positional(name: &str) -> Self {
        Self {
            option_strings: Vec::new(),
            dest: name.to_owned(),
            kind: Kind::Store,
            nargs: Nargs::One,
            required: true,
            choices: None,
            ty: None,
            default: Val::None,
            metavar: None,
            help: None,
        }
    }
    /// `action="store_true"`.
    pub fn flag(mut self) -> Self {
        self.kind = Kind::StoreTrue;
        self.nargs = Nargs::Zero;
        self.default = Val::Bool(false);
        self
    }
    /// `action="append"`.
    pub fn append(mut self) -> Self {
        self.kind = Kind::Append;
        self
    }
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub fn choices(mut self, choices: &[&str]) -> Self {
        self.choices = Some(choices.iter().map(|c| (*c).to_owned()).collect());
        self
    }
    pub fn ty(mut self, ty: TypeFn) -> Self {
        self.ty = Some(ty);
        self
    }
    pub fn default(mut self, value: Val) -> Self {
        self.default = value;
        self
    }
    pub fn metavar(mut self, metavar: &str) -> Self {
        self.metavar = Some(metavar.to_owned());
        self
    }
    pub fn dest(mut self, dest: &str) -> Self {
        self.dest = dest.to_owned();
        self
    }
    pub fn help(mut self, help: &str) -> Self {
        self.help = Some(help.to_owned());
        self
    }
    fn is_optional(&self) -> bool {
        !self.option_strings.is_empty()
    }
}

struct Subparsers {
    /// `(name, parser)` in `add_parser` order (`_name_parser_map`).
    parsers: Vec<(String, Parser)>,
    /// `_ChoicesPseudoAction`s: `(name, help)` for parsers added with `help=`.
    choice_help: Vec<(String, Option<String>)>,
}

/// `argparse.ArgumentParser`.
pub struct Parser {
    prog: String,
    description: Option<String>,
    allow_abbrev: bool,
    actions: Vec<Arg>,
    /// `(required, action indices)` for each mutually exclusive group.
    groups: Vec<(bool, Vec<usize>)>,
    subparsers: Option<(usize, Subparsers)>,
}

/// What parsing produced, in place of argparse's printing and `sys.exit`.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Parsed(Namespace, Vec<String>),
    /// `-h`/`--help`: this text goes to stdout, exit status 0.
    Help(String),
    /// `parser.error(message)` on the parser whose `prog` and usage are given.
    Error {
        prog: String,
        usage: String,
        message: String,
    },
}

enum Stop {
    Help(String),
    Error {
        prog: String,
        usage: String,
        message: String,
    },
}

impl Parser {
    pub fn new(prog: &str, description: Option<&str>, allow_abbrev: bool) -> Self {
        let help = Arg {
            option_strings: vec!["-h".into(), "--help".into()],
            dest: SUPPRESS.into(),
            kind: Kind::Help,
            nargs: Nargs::Zero,
            required: false,
            choices: None,
            ty: None,
            default: Val::None,
            metavar: None,
            help: Some("show this help message and exit".into()),
        };
        Self {
            prog: prog.to_owned(),
            description: description.map(str::to_owned),
            allow_abbrev,
            actions: vec![help],
            groups: Vec::new(),
            subparsers: None,
        }
    }

    pub fn arg(&mut self, arg: Arg) -> &mut Self {
        self.actions.push(arg);
        self
    }

    /// `add_mutually_exclusive_group(required=...)` holding `args`.
    pub fn exclusive(&mut self, required: bool, args: Vec<Arg>) -> &mut Self {
        let start = self.actions.len();
        let indices = (start..start + args.len()).collect();
        self.actions.extend(args);
        self.groups.push((required, indices));
        self
    }

    /// `add_subparsers(dest=..., required=True, metavar=...)`.
    pub fn subparsers(&mut self, dest: &str, metavar: Option<&str>) -> &mut Self {
        let index = self.actions.len();
        self.actions.push(Arg {
            option_strings: Vec::new(),
            dest: dest.to_owned(),
            kind: Kind::Subparsers,
            nargs: Nargs::Parser,
            required: true,
            choices: Some(Vec::new()),
            ty: None,
            default: Val::None,
            metavar: metavar.map(str::to_owned),
            help: None,
        });
        self.subparsers = Some((
            index,
            Subparsers {
                parsers: Vec::new(),
                choice_help: Vec::new(),
            },
        ));
        self
    }

    /// The prefix `add_subparsers` gives its parsers' `prog`: this parser's
    /// usage restricted to positionals, without `usage: `.
    fn subparser_prog_prefix(&self) -> String {
        let positionals: Vec<&Arg> = self
            .actions
            .iter()
            .filter(|a| !a.is_optional() && a.kind != Kind::Subparsers)
            .collect();
        if positionals.is_empty() {
            return self.prog.clone();
        }
        let usage = format_actions_usage(&positionals, &[]);
        format!("{} {usage}", self.prog)
    }

    /// `subparsers.add_parser(name, help=help, description=description)`;
    /// returns the new parser for further `arg` calls.
    pub fn add_parser(
        &mut self,
        name: &str,
        help: Option<&str>,
        description: Option<&str>,
    ) -> &mut Parser {
        let prog = format!("{} {name}", self.subparser_prog_prefix());
        let allow_abbrev = self.allow_abbrev;
        let (index, subs) = self
            .subparsers
            .as_mut()
            .expect("add_subparsers() before add_parser()");
        if let Some(choices) = self.actions[*index].choices.as_mut() {
            choices.push(name.to_owned());
        }
        if help.is_some() {
            subs.choice_help
                .push((name.to_owned(), help.map(str::to_owned)));
        }
        subs.parsers.push((
            name.to_owned(),
            Parser::new(&prog, description, allow_abbrev),
        ));
        &mut subs.parsers.last_mut().expect("just pushed").1
    }

    /// The parser registered under `path` (subcommand names), for tests.
    pub fn find(&self, path: &[&str]) -> Option<&Parser> {
        match path.split_first() {
            None => Some(self),
            Some((head, rest)) => self
                .subparsers
                .as_ref()?
                .1
                .parsers
                .iter()
                .find(|(name, _)| name == head)?
                .1
                .find(rest),
        }
    }

    /// Every option string registered anywhere in this tree
    /// (`_Parser._registered_options` in `admin_cli.py`).
    pub fn registered_options(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .actions
            .iter()
            .flat_map(|a| a.option_strings.iter().cloned())
            .collect();
        if let Some((_, subs)) = &self.subparsers {
            for (_, parser) in &subs.parsers {
                out.extend(parser.registered_options());
            }
        }
        out
    }

    // ------------------------------------------------------------ parsing

    /// `parse_known_args(args)`, formatting any usage/help for the current
    /// terminal width.
    pub fn parse_known_args(&self, args: &[String]) -> Outcome {
        self.parse_known_args_at(args, terminal_columns())
    }

    /// [`Parser::parse_known_args`] with an explicit `shutil.get_terminal_size().columns`.
    pub fn parse_known_args_at(&self, args: &[String], columns: usize) -> Outcome {
        let mut namespace = Namespace::new();
        match self.parse_known_into(args, &mut namespace, columns) {
            Ok(extras) => Outcome::Parsed(namespace, extras),
            Err(Stop::Help(text)) => Outcome::Help(text),
            Err(Stop::Error {
                prog,
                usage,
                message,
            }) => Outcome::Error {
                prog,
                usage,
                message,
            },
        }
    }

    /// `_parse_known_args2`: defaults, then parsing; an `ArgumentError`
    /// becomes this parser's `error()`.
    fn parse_known_into(
        &self,
        args: &[String],
        namespace: &mut Namespace,
        columns: usize,
    ) -> Result<Vec<String>, Stop> {
        for action in &self.actions {
            if action.dest != SUPPRESS && !namespace.contains_key(&action.dest) {
                namespace.insert(action.dest.clone(), action.default.clone());
            }
        }
        let mut unrecognized = Vec::new();
        match self.parse_known_inner(args, namespace, &mut unrecognized, columns) {
            Ok(mut extras) => {
                extras.extend(unrecognized);
                Ok(extras)
            }
            Err(Failure::Stop(stop)) => Err(stop),
            Err(Failure::Argument(message)) => Err(Stop::Error {
                prog: self.prog.clone(),
                usage: self.format_usage_at(columns),
                message,
            }),
        }
    }

    /// `_parse_optional`.
    fn parse_optional(&self, arg: &str) -> Option<Vec<OptionTuple>> {
        let first = arg.chars().next()?;
        if first != '-' {
            return None;
        }
        if let Some(i) = self.option_index(arg) {
            return Some(vec![(Some(i), arg.to_owned(), None, None)]);
        }
        if arg.chars().count() == 1 {
            return None;
        }
        if let Some((option, explicit)) = arg.split_once('=')
            && let Some(i) = self.option_index(option)
        {
            return Some(vec![(
                Some(i),
                option.to_owned(),
                Some("=".to_owned()),
                Some(explicit.to_owned()),
            )]);
        }
        let tuples = self.option_tuples(arg);
        if !tuples.is_empty() {
            return Some(tuples);
        }
        if negative_number(arg) {
            // No parser here registers negative-number-like options.
            return None;
        }
        if arg.contains(' ') {
            return None;
        }
        Some(vec![(None, arg.to_owned(), None, None)])
    }

    fn option_index(&self, option: &str) -> Option<usize> {
        self.actions
            .iter()
            .position(|a| a.option_strings.iter().any(|s| s == option))
    }

    /// Option strings in `_option_string_actions` insertion order.
    fn option_strings(&self) -> impl Iterator<Item = (usize, &String)> {
        self.actions
            .iter()
            .enumerate()
            .flat_map(|(i, a)| a.option_strings.iter().map(move |s| (i, s)))
    }

    /// `_get_option_tuples`.
    fn option_tuples(&self, option: &str) -> Vec<OptionTuple> {
        let mut result = Vec::new();
        let mut chars = option.chars();
        let (Some(c0), Some(c1)) = (chars.next(), chars.next()) else {
            return result;
        };
        let (prefix, sep, explicit) = match option.split_once('=') {
            Some((p, e)) => (p, Some("=".to_owned()), Some(e.to_owned())),
            None => (option, None, None),
        };
        if c0 == '-' && c1 == '-' {
            if self.allow_abbrev {
                for (i, candidate) in self.option_strings() {
                    if candidate.starts_with(prefix) {
                        result.push((Some(i), candidate.clone(), sep.clone(), explicit.clone()));
                    }
                }
            }
        } else if c0 == '-' {
            let short_prefix: String = option.chars().take(2).collect();
            let short_explicit: String = option.chars().skip(2).collect();
            for (i, candidate) in self.option_strings() {
                if *candidate == short_prefix {
                    result.push((
                        Some(i),
                        candidate.clone(),
                        Some(String::new()),
                        Some(short_explicit.clone()),
                    ));
                } else if self.allow_abbrev && candidate.starts_with(prefix) {
                    result.push((Some(i), candidate.clone(), sep.clone(), explicit.clone()));
                }
            }
        }
        result
    }

    fn parse_known_inner(
        &self,
        args: &[String],
        namespace: &mut Namespace,
        unrecognized: &mut Vec<String>,
        columns: usize,
    ) -> Result<Vec<String>, Failure> {
        // Map each mutually exclusive action to the actions it conflicts with.
        let mut conflicts: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (_, members) in &self.groups {
            for (i, member) in members.iter().enumerate() {
                let entry = conflicts.entry(*member).or_default();
                entry.extend(&members[..i]);
                entry.extend(&members[i + 1..]);
            }
        }
        // The 'O'/'A'/'-' pattern of the argument strings.
        let mut option_indices: BTreeMap<usize, Vec<OptionTuple>> = BTreeMap::new();
        let mut pattern = String::new();
        let mut after_dashes = false;
        for (i, arg) in args.iter().enumerate() {
            if after_dashes {
                pattern.push('A');
            } else if arg == "--" {
                pattern.push('-');
                after_dashes = true;
            } else if let Some(tuples) = self.parse_optional(arg) {
                option_indices.insert(i, tuples);
                pattern.push('O');
            } else {
                pattern.push('A');
            }
        }

        let mut state = ParseState {
            parser: self,
            args,
            pattern: &pattern,
            namespace,
            unrecognized,
            seen: Vec::new(),
            seen_non_default: Vec::new(),
            conflicts,
            extras: Vec::new(),
            columns,
            positionals: self
                .actions
                .iter()
                .enumerate()
                .filter(|(_, a)| !a.is_optional())
                .map(|(i, _)| i)
                .collect(),
        };

        let max_option = option_indices.keys().next_back().copied();
        let mut start = 0usize;
        if let Some(max_option) = max_option {
            while start <= max_option {
                let next_option = *option_indices
                    .range(start..)
                    .next()
                    .map(|(i, _)| i)
                    .expect("an option index at or after start");
                if start != next_option {
                    let end = state.consume_positionals(start)?;
                    if end > start {
                        start = end;
                        continue;
                    }
                    start = end;
                }
                if !option_indices.contains_key(&start) {
                    state
                        .extras
                        .extend(args[start..next_option].iter().cloned());
                    start = next_option;
                }
                start = state.consume_optional(start, &option_indices[&start])?;
            }
        }
        let stop = state.consume_positionals(start)?;
        state.extras.extend(args[stop..].iter().cloned());

        // Required actions, then required groups.
        let mut required = Vec::new();
        for (i, action) in self.actions.iter().enumerate() {
            if !state.seen.contains(&i) {
                if action.required {
                    required.push(action_name(action));
                } else if let (Val::Str(default), Some(ty)) = (&action.default, action.ty)
                    && state.namespace.get(&action.dest) == Some(&action.default)
                {
                    let value = convert(action, ty, default)?;
                    state.namespace.insert(action.dest.clone(), value);
                }
            }
        }
        if !required.is_empty() {
            return Err(Failure::Argument(format!(
                "the following arguments are required: {}",
                required.join(", ")
            )));
        }
        for (group_required, members) in &self.groups {
            if *group_required && !members.iter().any(|m| state.seen_non_default.contains(m)) {
                let names: Vec<String> = members
                    .iter()
                    .map(|m| action_name(&self.actions[*m]))
                    .collect();
                return Err(Failure::Argument(format!(
                    "one of the arguments {} is required",
                    names.join(" ")
                )));
            }
        }
        Ok(state.extras)
    }

    // ------------------------------------------------------------ help

    /// `format_usage()`.
    pub fn format_usage(&self) -> String {
        self.format_usage_at(terminal_columns())
    }

    pub fn format_usage_at(&self, columns: usize) -> String {
        let formatter = Formatter::new(&self.prog, columns);
        finish(&formatter.format_usage(&self.actions.iter().collect::<Vec<_>>(), &self.groups, 0))
    }

    /// `format_help()`.
    pub fn format_help(&self) -> String {
        self.format_help_at(terminal_columns())
    }

    pub fn format_help_at(&self, columns: usize) -> String {
        let formatter = Formatter::new(&self.prog, columns);
        let actions: Vec<&Arg> = self.actions.iter().collect();
        let mut out = String::new();
        out.push_str(&formatter.format_usage(&actions, &self.groups, 0));
        if let Some(description) = &self.description {
            out.push_str(&formatter.format_text(description, 0));
        }
        // Invocation widths across every section (`_action_max_length`).
        let mut max_length = 0usize;
        let mut rows: Vec<(usize, &Arg)> = Vec::new();
        for action in self.actions.iter().filter(|a| !a.is_optional()) {
            rows.push((0, action));
        }
        let positional_count = rows.len();
        for action in self.actions.iter().filter(|a| a.is_optional()) {
            rows.push((1, action));
        }
        let pseudo: Vec<Arg> = self
            .subparsers
            .as_ref()
            .map(|(_, subs)| {
                subs.choice_help
                    .iter()
                    .map(|(name, help)| {
                        let mut a = Arg::positional(name);
                        a.metavar = Some(name.clone());
                        a.help = help.clone();
                        a
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (_, action) in &rows {
            max_length = max_length.max(invocation(action).chars().count() + 2);
            if action.kind == Kind::Subparsers {
                for sub in &pseudo {
                    max_length = max_length.max(invocation(sub).chars().count() + 4);
                }
            }
        }
        for (heading, section) in [
            ("positional arguments", &rows[..positional_count]),
            ("options", &rows[positional_count..]),
        ] {
            let mut body = String::new();
            for (_, action) in section {
                body.push_str(&formatter.format_action(action, 2, max_length));
                if action.kind == Kind::Subparsers {
                    for sub in &pseudo {
                        body.push_str(&formatter.format_action(sub, 4, max_length));
                    }
                }
            }
            if !body.is_empty() {
                out.push_str(&format!("\n{heading}:\n{body}\n"));
            }
        }
        finish(&out)
    }
}

/// `(action index, option string, sep, explicit argument)`.
type OptionTuple = (Option<usize>, String, Option<String>, Option<String>);

enum Failure {
    /// `ArgumentError`: reported by the parser currently parsing.
    Argument(String),
    /// Help printed, or a nested parser already reported its error.
    Stop(Stop),
}

struct ParseState<'a> {
    parser: &'a Parser,
    args: &'a [String],
    pattern: &'a str,
    namespace: &'a mut Namespace,
    unrecognized: &'a mut Vec<String>,
    seen: Vec<usize>,
    seen_non_default: Vec<usize>,
    conflicts: BTreeMap<usize, Vec<usize>>,
    extras: Vec<String>,
    columns: usize,
    positionals: Vec<usize>,
}

impl ParseState<'_> {
    fn take_action(
        &mut self,
        index: usize,
        strings: &[String],
        _option: Option<&str>,
    ) -> Result<(), Failure> {
        let parser = self.parser;
        let action = &parser.actions[index];
        self.seen.push(index);
        let value = get_values(action, strings)?;
        if action.is_optional() || !strings.is_empty() {
            self.seen_non_default.push(index);
            if let Some(conflicting) = self.conflicts.get(&index) {
                for other in conflicting {
                    if self.seen_non_default.contains(other) {
                        return Err(argument_error(
                            action,
                            &format!(
                                "not allowed with argument {}",
                                action_name(&parser.actions[*other])
                            ),
                        ));
                    }
                }
            }
        }
        match action.kind {
            Kind::Store => {
                self.namespace.insert(action.dest.clone(), value);
            }
            Kind::StoreTrue => {
                self.namespace.insert(action.dest.clone(), Val::Bool(true));
            }
            Kind::Append => {
                let mut items = match self.namespace.get(&action.dest) {
                    Some(Val::List(items)) => items.clone(),
                    _ => Vec::new(),
                };
                if let Val::Str(s) = value {
                    items.push(s);
                } else if let Val::Int(int) = value {
                    items.push(int.to_string());
                }
                self.namespace.insert(action.dest.clone(), Val::List(items));
            }
            Kind::Help => {
                return Err(Failure::Stop(Stop::Help(
                    parser.format_help_at(self.columns),
                )));
            }
            Kind::Subparsers => {
                let name = strings.first().cloned().unwrap_or_default();
                self.namespace
                    .insert(action.dest.clone(), Val::Str(name.clone()));
                let (_, subs) = parser.subparsers.as_ref().expect("subparsers action");
                let sub = &subs
                    .parsers
                    .iter()
                    .find(|(n, _)| *n == name)
                    .expect("checked against choices")
                    .1;
                let mut sub_namespace = Namespace::new();
                let extras = sub
                    .parse_known_into(&strings[1..], &mut sub_namespace, self.columns)
                    .map_err(Failure::Stop)?;
                self.namespace.extend(sub_namespace);
                self.unrecognized.extend(extras);
            }
        }
        Ok(())
    }

    /// `consume_optional`.
    fn consume_optional(&mut self, start: usize, tuples: &[OptionTuple]) -> Result<usize, Failure> {
        let parser = self.parser;
        if tuples.len() > 1 {
            let options: Vec<&str> = tuples.iter().map(|t| t.1.as_str()).collect();
            return Err(Failure::Argument(format!(
                "ambiguous option: {} could match {}",
                self.args[start],
                options.join(", ")
            )));
        }
        let (mut action, mut option_string, mut sep, mut explicit) = tuples[0].clone();
        let mut action_tuples: Vec<(usize, Vec<String>, String)> = Vec::new();
        let stop;
        loop {
            let Some(index) = action else {
                self.extras.push(self.args[start].clone());
                return Ok(start + 1);
            };
            let current = &parser.actions[index];
            if let Some(arg) = explicit.clone() {
                let count = match_argument(current, "A")?;
                let second = option_string.chars().nth(1);
                if count == 0 && second != Some('-') && !arg.is_empty() {
                    if sep.as_deref().is_some_and(|s| !s.is_empty()) || arg.starts_with('-') {
                        return Err(argument_error(
                            current,
                            &format!("ignored explicit argument {}", pystr::repr_str(&arg)),
                        ));
                    }
                    action_tuples.push((index, Vec::new(), option_string.clone()));
                    let first = arg.chars().next().expect("non-empty");
                    option_string = format!("-{first}");
                    if let Some(next) = parser.option_index(&option_string) {
                        action = Some(next);
                        let rest: String = arg.chars().skip(1).collect();
                        if rest.is_empty() {
                            sep = None;
                            explicit = None;
                        } else if let Some(r) = rest.strip_prefix('=') {
                            sep = Some("=".into());
                            explicit = Some(r.to_owned());
                        } else {
                            sep = Some(String::new());
                            explicit = Some(rest);
                        }
                    } else {
                        self.extras.push(format!("-{arg}"));
                        stop = start + 1;
                        break;
                    }
                } else if count == 1 {
                    stop = start + 1;
                    action_tuples.push((index, vec![arg], option_string.clone()));
                    break;
                } else {
                    return Err(argument_error(
                        current,
                        &format!("ignored explicit argument {}", pystr::repr_str(&arg)),
                    ));
                }
            } else {
                let begin = start + 1;
                let count = match_argument(current, &self.pattern[begin..])?;
                stop = begin + count;
                action_tuples.push((
                    index,
                    self.args[begin..stop].to_vec(),
                    option_string.clone(),
                ));
                break;
            }
        }
        for (index, strings, option) in action_tuples {
            self.take_action(index, &strings, Some(&option))?;
        }
        Ok(stop)
    }

    /// `consume_positionals`.
    fn consume_positionals(&mut self, mut start: usize) -> Result<usize, Failure> {
        let parser = self.parser;
        let selected = &self.pattern[start..];
        let counts = match_partial(
            &self
                .positionals
                .iter()
                .map(|i| &parser.actions[*i])
                .collect::<Vec<_>>(),
            selected,
        );
        let taken: Vec<usize> = self.positionals[..counts.len()].to_vec();
        for (index, count) in taken.iter().zip(&counts) {
            let mut strings = self.args[start..start + count].to_vec();
            let action = &parser.actions[*index];
            if action.nargs == Nargs::Parser {
                if self.pattern.as_bytes().get(start) == Some(&b'-') {
                    strings.remove(0);
                }
            } else if self.pattern[start..start + count].contains('-')
                && let Some(p) = strings.iter().position(|s| s == "--")
            {
                strings.remove(p);
            }
            start += count;
            self.take_action(*index, &strings, None)?;
        }
        self.positionals.drain(..counts.len());
        Ok(start)
    }
}

fn negative_number(arg: &str) -> bool {
    static NEGATIVE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    NEGATIVE
        .get_or_init(|| Regex::new(r"^-\d+$|^-\d*\.\d+$").expect("static regex"))
        .is_match(arg)
}

/// `_get_nargs_pattern`.
fn nargs_pattern(action: &Arg) -> &'static str {
    match (action.nargs, action.is_optional()) {
        (Nargs::One, true) => "([A])",
        (Nargs::One, false) => "(-*A-*)",
        (Nargs::Zero, true) => "()",
        (Nargs::Zero, false) => "(-*)",
        (Nargs::Parser, true) => "(A[AO]*)",
        (Nargs::Parser, false) => "(-*A[-AO]*)",
    }
}

/// `_match_argument`.
fn match_argument(action: &Arg, pattern: &str) -> Result<usize, Failure> {
    let re = Regex::new(&format!("^{}", nargs_pattern(action))).expect("nargs pattern");
    match re.captures(pattern) {
        Some(captures) => Ok(captures.get(1).map_or(0, |m| m.len())),
        None => {
            let message = match action.nargs {
                Nargs::One => "expected one argument".to_owned(),
                Nargs::Zero => "expected 0 arguments".to_owned(),
                Nargs::Parser => "expected A... arguments".to_owned(),
            };
            Err(argument_error(action, &message))
        }
    }
}

/// `_match_arguments_partial`.
fn match_partial(actions: &[&Arg], pattern: &str) -> Vec<usize> {
    for i in (1..=actions.len()).rev() {
        let joined: String = actions[..i].iter().map(|a| nargs_pattern(a)).collect();
        let re = Regex::new(&format!("^{joined}")).expect("nargs pattern");
        if let Some(captures) = re.captures(pattern) {
            let mut result: Vec<usize> = (1..captures.len())
                .map(|g| captures.get(g).map_or(0, |m| m.len()))
                .collect();
            let end = captures.get(0).map_or(0, |m| m.end());
            if end < pattern.len() && pattern.as_bytes()[end] == b'O' {
                while result.last() == Some(&0) {
                    result.pop();
                }
            }
            return result;
        }
    }
    Vec::new()
}

/// `_get_values` for the nargs this module supports.
fn get_values(action: &Arg, strings: &[String]) -> Result<Val, Failure> {
    match action.nargs {
        Nargs::Zero => Ok(Val::None),
        Nargs::One => {
            let value = match action.ty {
                Some(ty) => convert(action, ty, &strings[0])?,
                None => Val::Str(strings[0].clone()),
            };
            check_value(action, &value)?;
            Ok(value)
        }
        Nargs::Parser => {
            check_value(action, &Val::Str(strings[0].clone()))?;
            Ok(Val::List(strings.to_vec()))
        }
    }
}

/// `_get_value`.
fn convert(action: &Arg, ty: TypeFn, text: &str) -> Result<Val, Failure> {
    (ty.convert)(text).map_err(|message| match message {
        Some(message) => argument_error(action, &message),
        None => argument_error(
            action,
            &format!("invalid {} value: {}", ty.name, pystr::repr_str(text)),
        ),
    })
}

/// `_check_value`.
fn check_value(action: &Arg, value: &Val) -> Result<(), Failure> {
    let Some(choices) = &action.choices else {
        return Ok(());
    };
    let text = match value {
        Val::Str(s) => s.clone(),
        Val::Int(int) => int.to_string(),
        _ => return Ok(()),
    };
    if choices.contains(&text) {
        return Ok(());
    }
    Err(argument_error(
        action,
        &format!(
            "invalid choice: {} (choose from {})",
            pystr::repr_str(&text),
            choices.join(", ")
        ),
    ))
}

/// `_get_action_name`.
fn action_name(action: &Arg) -> String {
    if action.is_optional() {
        action.option_strings.join("/")
    } else if let Some(metavar) = &action.metavar {
        metavar.clone()
    } else {
        action.dest.clone()
    }
}

/// `ArgumentError(action, message)`, rendered by `str()`.
fn argument_error(action: &Arg, message: &str) -> Failure {
    Failure::Argument(format!("argument {}: {message}", action_name(action)))
}

// ---------------------------------------------------------------- formatter

/// `shutil.get_terminal_size().columns`.
pub fn terminal_columns() -> usize {
    if let Ok(text) = std::env::var("COLUMNS")
        && let Some(columns) = pystr::int_from_str_checked(&text)
        && columns > 0
    {
        return usize::try_from(columns).unwrap_or(usize::MAX);
    }
    match rustix::termios::tcgetwinsize(std::io::stdout()) {
        Ok(size) if size.ws_col > 0 => usize::from(size.ws_col),
        _ => 80,
    }
}

struct Formatter {
    prog: String,
    width: usize,
    max_help_position: usize,
}

/// `HelpFormatter.format_help()`'s final clean-up of the joined parts.
fn finish(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let mut collapsed = String::new();
    let mut newlines = 0usize;
    for c in text.chars() {
        if c == '\n' {
            newlines += 1;
            continue;
        }
        if newlines > 0 {
            collapsed.push_str(if newlines >= 3 {
                "\n\n"
            } else {
                &"\n\n"[..newlines]
            });
            newlines = 0;
        }
        collapsed.push(c);
    }
    let trimmed = collapsed.trim_matches('\n');
    format!("{trimmed}\n")
}

/// `_format_actions_usage`.
fn format_actions_usage(actions: &[&Arg], groups: &[(bool, Vec<&Arg>)]) -> String {
    let mut in_group: Vec<*const Arg> = Vec::new();
    let mut inserts: BTreeMap<usize, String> = BTreeMap::new();
    for (required, members) in groups {
        let Some(start) = actions.iter().position(|a| std::ptr::eq(*a, members[0])) else {
            continue;
        };
        let end = start + members.len();
        if end > actions.len()
            || !actions[start..end]
                .iter()
                .zip(members)
                .all(|(a, b)| std::ptr::eq(*a, *b))
        {
            continue;
        }
        in_group.extend(members.iter().map(|m| *m as *const Arg));
        let (open, close) = if !required {
            ("[", "]")
        } else if members.len() > 1 {
            ("(", ")")
        } else {
            ("", "")
        };
        if !open.is_empty() {
            inserts
                .entry(start)
                .and_modify(|s| s.push_str(&format!(" {open}")))
                .or_insert_with(|| open.to_owned());
            inserts
                .entry(end)
                .and_modify(|s| s.push_str(close))
                .or_insert_with(|| close.to_owned());
        }
        for i in start + 1..end {
            inserts.insert(i, "|".to_owned());
        }
    }
    let mut parts: Vec<String> = Vec::new();
    for action in actions {
        let grouped = in_group.contains(&(*action as *const Arg));
        if !action.is_optional() {
            let mut part = format_args(action, &action.dest);
            if grouped && part.starts_with('[') && part.ends_with(']') {
                part = part[1..part.len() - 1].to_owned();
            }
            parts.push(part);
        } else {
            let option = &action.option_strings[0];
            let mut part = if action.nargs == Nargs::Zero {
                option.clone()
            } else {
                format!(
                    "{option} {}",
                    format_args(action, &action.dest.to_uppercase())
                )
            };
            if !action.required && !grouped {
                part = format!("[{part}]");
            }
            parts.push(part);
        }
    }
    for (i, insert) in inserts.iter().rev() {
        parts.insert(*i, insert.clone());
    }
    let text = parts.join(" ");
    static OPEN: std::sync::OnceLock<[Regex; 3]> = std::sync::OnceLock::new();
    let [open, close, empty] = OPEN.get_or_init(|| {
        [
            Regex::new(r"([\[(]) ").expect("static regex"),
            Regex::new(r" ([\])])").expect("static regex"),
            Regex::new(r"[\[(] *[\])]").expect("static regex"),
        ]
    });
    let text = open.replace_all(&text, "$1");
    let text = close.replace_all(&text, "$1");
    let text = empty.replace_all(&text, "");
    text.trim().to_owned()
}

/// `_metavar_formatter(action, default)(1)`.
fn metavar(action: &Arg, default: &str) -> String {
    if let Some(m) = &action.metavar {
        m.clone()
    } else if let Some(choices) = &action.choices {
        format!("{{{}}}", choices.join(","))
    } else {
        default.to_owned()
    }
}

/// `_format_args`.
fn format_args(action: &Arg, default: &str) -> String {
    let m = metavar(action, default);
    match action.nargs {
        Nargs::One => m,
        Nargs::Zero => String::new(),
        Nargs::Parser => format!("{m} ..."),
    }
}

/// `_format_action_invocation`.
fn invocation(action: &Arg) -> String {
    if !action.is_optional() {
        return metavar(action, &action.dest);
    }
    if action.nargs == Nargs::Zero {
        return action.option_strings.join(", ");
    }
    let args = format_args(action, &action.dest.to_uppercase());
    action
        .option_strings
        .iter()
        .map(|o| format!("{o} {args}"))
        .collect::<Vec<_>>()
        .join(", ")
}

impl Formatter {
    fn new(prog: &str, columns: usize) -> Self {
        let width = columns.saturating_sub(2);
        Self {
            prog: prog.to_owned(),
            width,
            max_help_position: 24.min(width.saturating_sub(20).max(4)),
        }
    }

    /// `_format_usage` with the default `usage: ` prefix.
    fn format_usage(
        &self,
        actions: &[&Arg],
        groups: &[(bool, Vec<usize>)],
        indent: usize,
    ) -> String {
        let prefix = "usage: ";
        let group_refs: Vec<(bool, Vec<&Arg>)> = groups
            .iter()
            .map(|(required, members)| {
                (
                    *required,
                    members
                        .iter()
                        .filter_map(|i| actions.get(*i).copied())
                        .collect(),
                )
            })
            .collect();
        if actions.is_empty() {
            return format!("{prefix}{}\n\n", self.prog);
        }
        let optionals: Vec<&Arg> = actions
            .iter()
            .copied()
            .filter(|a| a.is_optional())
            .collect();
        let positionals: Vec<&Arg> = actions
            .iter()
            .copied()
            .filter(|a| !a.is_optional())
            .collect();
        let all: Vec<&Arg> = optionals.iter().chain(&positionals).copied().collect();
        let action_usage = format_actions_usage(&all, &group_refs);
        let mut usage = [self.prog.as_str(), action_usage.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        let text_width = self.width.saturating_sub(indent);
        let len = |s: &str| s.chars().count();
        if len(prefix) + len(&usage) > text_width {
            let opt_parts = usage_parts(&format_actions_usage(&optionals, &group_refs));
            let pos_parts = usage_parts(&format_actions_usage(&positionals, &group_refs));
            let get_lines = |parts: &[String], indent: &str, prefix: Option<&str>| -> Vec<String> {
                let mut lines = Vec::new();
                let mut line: Vec<&str> = Vec::new();
                let indent_length = len(indent);
                let mut line_len: isize = match prefix {
                    Some(p) => len(p) as isize - 1,
                    None => indent_length as isize - 1,
                };
                for part in parts {
                    if line_len + 1 + len(part) as isize > text_width as isize && !line.is_empty() {
                        lines.push(format!("{indent}{}", line.join(" ")));
                        line.clear();
                        line_len = indent_length as isize - 1;
                    }
                    line.push(part);
                    line_len += len(part) as isize + 1;
                }
                if !line.is_empty() {
                    lines.push(format!("{indent}{}", line.join(" ")));
                }
                if prefix.is_some()
                    && let Some(first) = lines.first_mut()
                {
                    *first = first.chars().skip(indent_length).collect();
                }
                lines
            };
            let prog = self.prog.clone();
            let lines = if (len(prefix) + len(&prog)) as f64 <= 0.75 * text_width as f64 {
                let indent = " ".repeat(len(prefix) + len(&prog) + 1);
                if !opt_parts.is_empty() {
                    let mut first = vec![prog.clone()];
                    first.extend(opt_parts.iter().cloned());
                    let mut lines = get_lines(&first, &indent, Some(prefix));
                    lines.extend(get_lines(&pos_parts, &indent, None));
                    lines
                } else if !pos_parts.is_empty() {
                    let mut first = vec![prog.clone()];
                    first.extend(pos_parts.iter().cloned());
                    get_lines(&first, &indent, Some(prefix))
                } else {
                    vec![prog.clone()]
                }
            } else {
                let indent = " ".repeat(len(prefix));
                let parts: Vec<String> = opt_parts.iter().chain(&pos_parts).cloned().collect();
                let mut lines = get_lines(&parts, &indent, None);
                if lines.len() > 1 {
                    lines = get_lines(&opt_parts, &indent, None);
                    lines.extend(get_lines(&pos_parts, &indent, None));
                }
                let mut all = vec![prog.clone()];
                all.extend(lines);
                all
            };
            usage = lines.join("\n");
        }
        format!("{prefix}{usage}\n\n")
    }

    /// `_format_text`.
    fn format_text(&self, text: &str, indent: usize) -> String {
        let width = self.width.saturating_sub(indent).max(11);
        let pad = " ".repeat(indent);
        format!("{}\n\n", fill(&normalize(text), width, &pad, &pad))
    }

    /// `_format_action` at `indent`, given `_action_max_length`.
    fn format_action(&self, action: &Arg, indent: usize, max_length: usize) -> String {
        let help_position = (max_length + 2).min(self.max_help_position);
        let help_width = self.width.saturating_sub(help_position).max(11);
        let action_width = help_position.saturating_sub(indent + 2);
        let header = invocation(action);
        let pad = " ".repeat(indent);
        let help = action.help.as_deref().filter(|h| !h.is_empty());
        let (mut out, indent_first) = match help {
            None => (format!("{pad}{header}\n"), 0),
            Some(_) if header.chars().count() <= action_width => {
                (format!("{pad}{header:<action_width$}  "), 0)
            }
            Some(_) => (format!("{pad}{header}\n"), help_position),
        };
        match help {
            Some(help) if !help.trim().is_empty() => {
                let lines = wrap(&normalize(help), help_width, "", "");
                if let Some((first, rest)) = lines.split_first() {
                    out.push_str(&format!("{}{first}\n", " ".repeat(indent_first)));
                    for line in rest {
                        out.push_str(&format!("{}{line}\n", " ".repeat(help_position)));
                    }
                }
            }
            _ => {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
        }
        out
    }
}

/// The `part_regexp` split of a usage string into wrappable parts.
fn usage_parts(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut parts = Vec::new();
    let mut i = 0;
    let bracketed = |i: usize, open: char, close: char| -> Option<usize> {
        if chars.get(i) != Some(&open) {
            return None;
        }
        // `\(.*?\)+(?=\s|$)`: lazily extend until a run of closers is
        // followed by whitespace or the end.
        let mut j = i + 1;
        while j < n {
            if chars[j] == '\n' {
                return None;
            }
            if chars[j] == close {
                let mut k = j;
                while k < n && chars[k] == close {
                    k += 1;
                }
                if k == n || chars[k].is_whitespace() {
                    return Some(k);
                }
            }
            j += 1;
        }
        None
    };
    while i < n {
        let end = bracketed(i, '(', ')')
            .or_else(|| bracketed(i, '[', ']'))
            .or_else(|| {
                if chars[i].is_whitespace() {
                    None
                } else {
                    let mut k = i;
                    while k < n && !chars[k].is_whitespace() {
                        k += 1;
                    }
                    Some(k)
                }
            });
        match end {
            Some(end) => {
                parts.push(chars[i..end].iter().collect());
                i = end;
            }
            None => i += 1,
        }
    }
    parts
}

// ---------------------------------------------------------------- textwrap

/// `HelpFormatter._whitespace_matcher.sub(' ', text).strip()` (ASCII `\s`).
fn normalize(text: &str) -> String {
    let mut out = String::new();
    let mut in_space = false;
    for c in text.chars() {
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c') {
            in_space = true;
        } else {
            if in_space && !out.is_empty() {
                out.push(' ');
            }
            in_space = false;
            out.push(c);
        }
    }
    out
}

/// `textwrap.fill`.
fn fill(text: &str, width: usize, initial: &str, subsequent: &str) -> String {
    wrap(text, width, initial, subsequent).join("\n")
}

fn is_textwrap_space(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' ')
}
/// Python `\w` in a `str` pattern.
fn is_word(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}
/// `[^\d\W]`.
fn is_letter(c: char) -> bool {
    is_word(c) && pystr::unicode_decimal_digit(c).is_none()
}
/// `[\w!"\'&.,?]`.
fn is_word_punct(c: char) -> bool {
    is_word(c) || matches!(c, '!' | '"' | '\'' | '&' | '.' | ',' | '?')
}

/// One match of `TextWrapper.wordsep_re` at `i`, as its end index.
fn wordsep_match(t: &[char], i: usize) -> Option<usize> {
    let n = t.len();
    let at = |k: usize| t.get(k).copied();
    let em_dash_at = |k: usize| -> bool {
        // `-{2,}\w` starting at k
        let mut j = k;
        while at(j) == Some('-') {
            j += 1;
        }
        j - k >= 2 && at(j).is_some_and(is_word)
    };
    // whitespace run
    if is_textwrap_space(t[i]) {
        let mut j = i;
        while j < n && is_textwrap_space(t[j]) {
            j += 1;
        }
        return Some(j);
    }
    // em-dash between words
    if i > 0 && is_word_punct(t[i - 1]) && em_dash_at(i) {
        let mut j = i;
        while at(j) == Some('-') {
            j += 1;
        }
        return Some(j);
    }
    // word, possibly hyphenated (lazy)
    let mut k = i + 1;
    while k <= n {
        if k > i && is_textwrap_space(t[k - 1]) {
            break;
        }
        // hyphenated word: '-' at k with letter lookbehind and lookahead
        if at(k) == Some('-') {
            let behind = (k >= 2 && is_letter(t[k - 2]) && is_letter(t[k - 1]))
                || (k >= 3 && is_letter(t[k - 3]) && t[k - 2] == '-' && is_letter(t[k - 1]));
            let ahead = at(k + 1).is_some_and(is_letter)
                && (at(k + 2).is_some_and(is_letter)
                    || (at(k + 2) == Some('-') && at(k + 3).is_some_and(is_letter)));
            if behind && ahead {
                return Some(k + 1);
            }
        }
        // end of word
        if k == n || is_textwrap_space(t[k]) {
            return Some(k);
        }
        // before an em-dash
        if is_word_punct(t[k - 1]) && em_dash_at(k) {
            return Some(k);
        }
        k += 1;
    }
    None
}

/// `TextWrapper._split`: `wordsep_re.split(text)` without empty strings.
fn split_chunks(text: &str) -> Vec<String> {
    let t: Vec<char> = text.chars().collect();
    let mut chunks = Vec::new();
    let mut pending = String::new();
    let mut i = 0;
    while i < t.len() {
        match wordsep_match(&t, i) {
            Some(end) if end > i => {
                if !pending.is_empty() {
                    chunks.push(std::mem::take(&mut pending));
                }
                chunks.push(t[i..end].iter().collect());
                i = end;
            }
            _ => {
                pending.push(t[i]);
                i += 1;
            }
        }
    }
    if !pending.is_empty() {
        chunks.push(pending);
    }
    chunks
}

/// `textwrap.wrap` with the default options argparse uses.
fn wrap(text: &str, width: usize, initial: &str, subsequent: &str) -> Vec<String> {
    // expand_tabs + replace_whitespace
    let mut munged = String::new();
    let mut column = 0usize;
    for c in text.chars() {
        match c {
            '\t' => {
                let spaces = 8 - column % 8;
                munged.push_str(&" ".repeat(spaces));
                column += spaces;
            }
            '\n' | '\r' => {
                munged.push(' ');
                column = 0;
            }
            c if is_textwrap_space(c) => {
                munged.push(' ');
                column += 1;
            }
            c => {
                munged.push(c);
                column += 1;
            }
        }
    }
    let mut chunks = split_chunks(&munged);
    chunks.reverse();
    let len = |s: &str| s.chars().count();
    let blank = |s: &str| s.chars().all(|c| c.is_whitespace());
    let mut lines: Vec<String> = Vec::new();
    while !chunks.is_empty() {
        let mut line: Vec<String> = Vec::new();
        let mut cur = 0usize;
        let indent = if lines.is_empty() {
            initial
        } else {
            subsequent
        };
        let line_width = width.saturating_sub(len(indent));
        if chunks.last().is_some_and(|c| blank(c)) && !lines.is_empty() {
            chunks.pop();
        }
        while let Some(chunk) = chunks.last() {
            let l = len(chunk);
            if cur + l <= line_width {
                cur += l;
                line.push(chunks.pop().expect("non-empty"));
            } else {
                break;
            }
        }
        if chunks.last().is_some_and(|c| len(c) > line_width) {
            // _handle_long_word
            let space_left = if line_width < 1 { 1 } else { line_width - cur };
            let chunk: Vec<char> = chunks.last().expect("non-empty").chars().collect();
            let mut end = space_left;
            if chunk.len() > space_left {
                let hyphen = chunk[..space_left.min(chunk.len())]
                    .iter()
                    .rposition(|c| *c == '-');
                if let Some(h) = hyphen
                    && h > 0
                    && chunk[..h].iter().any(|c| *c != '-')
                {
                    end = h + 1;
                }
            }
            let end = end.min(chunk.len());
            line.push(chunk[..end].iter().collect());
            *chunks.last_mut().expect("non-empty") = chunk[end..].iter().collect();
            cur = line.iter().map(|s| len(s)).sum();
        }
        if line.last().is_some_and(|c| blank(c)) {
            line.pop();
        }
        if !line.is_empty() {
            lines.push(format!("{indent}{}", line.concat()));
        }
        let _ = cur;
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(abbrev: bool) -> Parser {
        let mut p = Parser::new("prog", Some("A tool (trusted; JSON output)."), abbrev);
        p.arg(
            Arg::opt("--state-dir")
                .required()
                .metavar("DIR")
                .help("trusted state directory (0700)"),
        );
        p.subparsers("command", Some("COMMAND"));
        let put = p.add_parser(
            "put",
            Some("store a new secret version; value via --value-file or --stdin only"),
            Some("store a new secret version; value via --value-file or --stdin only"),
        );
        put.arg(Arg::opt("--id").required());
        put.arg(
            Arg::opt("--kind")
                .required()
                .choices(&["api_key", "password"]),
        );
        put.arg(Arg::opt("--version").ty(INT));
        put.arg(Arg::opt("--staged").flag().help("store without activating"));
        put.exclusive(
            true,
            vec![
                Arg::opt("--value-file")
                    .metavar("PATH")
                    .help("read the secret value from this file (delete it afterwards)"),
                Arg::opt("--stdin")
                    .flag()
                    .help("read the secret value from standard input"),
            ],
        );
        let join = p.add_parser(
            "join",
            Some("dial the inviter, prove the invite, and join"),
            None,
        );
        join.arg(Arg::positional("invite"));
        join.arg(
            Arg::opt("--project").help("local project name (default: derived from the inviter)"),
        );
        p
    }

    const SAMPLE_PY: &str = r#"
import argparse, sys, io, contextlib, json
class NoAbbrev(argparse.ArgumentParser):
    # Like admin_cli._Parser: every (sub)parser disables abbreviation.
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)
def build(allow):
    cls = argparse.ArgumentParser if allow else NoAbbrev
    p = cls(prog="prog", description="A tool (trusted; JSON output).")
    p.add_argument("--state-dir", required=True, metavar="DIR", help="trusted state directory (0700)")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")
    put = sub.add_parser("put", help="store a new secret version; value via --value-file or --stdin only", description="store a new secret version; value via --value-file or --stdin only")
    put.add_argument("--id", required=True)
    put.add_argument("--kind", required=True, choices=("api_key", "password"))
    put.add_argument("--version", type=int)
    put.add_argument("--staged", action="store_true", help="store without activating")
    g = put.add_mutually_exclusive_group(required=True)
    g.add_argument("--value-file", metavar="PATH", help="read the secret value from this file (delete it afterwards)")
    g.add_argument("--stdin", action="store_true", help="read the secret value from standard input")
    join = sub.add_parser("join", help="dial the inviter, prove the invite, and join")
    join.add_argument("invite")
    join.add_argument("--project", help="local project name (default: derived from the inviter)")
    return p
"#;

    fn run_python(argv: &[&str], columns: usize, abbrev: bool) -> String {
        let script = format!(
            "{SAMPLE_PY}\nimport os\nos.environ['COLUMNS']='{columns}'\nargv={}\nout=io.StringIO(); err=io.StringIO()\ncode=None\nwith contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):\n    try:\n        ns, extras = build({abbrev}).parse_known_args(argv)\n        print(json.dumps(sorted((k, v) for k, v in vars(ns).items() if k != 'handler')), extras)\n    except SystemExit as e:\n        code = e.code\nsys.stdout.write(json.dumps([code, out.getvalue(), err.getvalue()]))\n",
            serde_json::to_string(argv).unwrap(),
            abbrev = if abbrev { "True" } else { "False" },
        );
        crate::oracle::python(&script)
    }

    fn run_rust(argv: &[&str], columns: usize, abbrev: bool) -> (Option<i32>, String, String) {
        let args: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
        match sample(abbrev).parse_known_args_at(&args, columns) {
            Outcome::Help(text) => (Some(0), text, String::new()),
            Outcome::Error {
                prog,
                usage,
                message,
            } => (
                Some(2),
                String::new(),
                format!("{usage}{prog}: error: {message}\n"),
            ),
            Outcome::Parsed(ns, extras) => {
                let items: Vec<Value> = ns
                    .iter()
                    .map(|(k, v)| {
                        serde_json::json!([
                            k,
                            match v {
                                Val::None => Value::Null,
                                Val::Str(s) => Value::String(s.clone()),
                                Val::Int(n) => serde_json::json!(*n as i64),
                                Val::Bool(b) => Value::Bool(*b),
                                Val::List(l) => serde_json::json!(l),
                            }
                        ])
                    })
                    .collect();
                let extras_repr = pystr::repr_value(&serde_json::json!(extras));
                (
                    None,
                    format!(
                        "{} {extras_repr}\n",
                        crate::pyjson::dumps(
                            &Value::Array(items),
                            crate::pyjson::DumpOptions::plain()
                        )
                        .unwrap()
                    ),
                    String::new(),
                )
            }
        }
    }

    use serde_json::Value;

    #[test]
    fn parsing_help_and_errors_match_python_argparse() {
        let cases: &[&[&str]] = &[
            &[],
            &["-h"],
            &["--state-dir", "s", "put", "-h"],
            &["--state-dir", "s", "put"],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "nope",
                "--stdin",
            ],
            &["--state-dir", "s", "put", "--id", "x", "--kind", "api_key"],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin",
                "--value-file",
                "f",
            ],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin",
                "--version",
                " 5_0",
            ],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin",
                "--version",
                "abc",
            ],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "-x",
                "--kind",
                "api_key",
                "--stdin",
            ],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind=api_key",
                "--stdin",
                "--value",
                "v",
            ],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--stdin=1",
            ],
            &["--state-dir", "s", "join"],
            &["--state-dir", "s", "join", "a", "b"],
            &["--state-dir", "s", "join", "--", "-a"],
            &["--state-dir", "s", "join", "-5"],
            &["--state-dir", "s", "join", "x", "-hfoo"],
            &["--state-dir", "s", "bogus"],
            &["put"],
            &["--state-dir"],
            &["--state-dir=s", "join", "a b", "--project", ""],
            &["--state", "s", "join", "a", "--proj", "p"],
            &[
                "--state-dir",
                "s",
                "put",
                "--i",
                "x",
                "--k",
                "api_key",
                "--st",
            ],
            &[
                "--state-dir",
                "s",
                "put",
                "--id",
                "x",
                "--kind",
                "api_key",
                "--s",
            ],
        ];
        for abbrev in [false, true] {
            for columns in [80, 40, 120, 25] {
                for argv in cases {
                    let expected: Value =
                        serde_json::from_str(&run_python(argv, columns, abbrev)).unwrap();
                    let (code, out, err) = run_rust(argv, columns, abbrev);
                    assert_eq!(
                        serde_json::json!([code, out, err]),
                        expected,
                        "argv {argv:?} at COLUMNS={columns} abbrev={abbrev}"
                    );
                }
            }
        }
    }

    #[test]
    fn textwrap_matches_python_for_hyphenated_and_long_words() {
        let texts = [
            "start team sync on a separate LAN/VPN-facing socket (default: team sync off)",
            "open an incident: lock down the given scope (docs/compromise-response.md §4)",
            "a very-long-hyphenated-compound-word-that-must-break and x--y em -- dash --foo",
            "supercalifragilisticexpialidocious-and-more-words-here ok",
            "30m, 1h, 3600s, 86400 (default: 1h; max 30d)",
        ];
        for width in [5usize, 11, 17, 22, 30, 54] {
            for text in texts {
                let expected: Vec<String> = serde_json::from_str(&crate::oracle::python(&format!(
                    "import textwrap, json\nprint(json.dumps(textwrap.wrap({}, {width})))",
                    pystr::repr_str(text)
                )))
                .unwrap();
                assert_eq!(wrap(text, width, "", ""), expected, "{text:?} at {width}");
            }
        }
    }
}
