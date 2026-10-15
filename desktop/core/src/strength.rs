//! Passphrase strength (`password_strength`, docs/desktop-app.md §7 steps 2–3): the zxcvbn
//! score (0–4), plus a short reason code for the UI's copy
//! table. `vault_init` enforces the same thresholds in Rust, so the webview's gauge is never
//! the only check.

use serde::Serialize;
use zxcvbn::feedback::Warning;

/// The CLI's own minimum (`passphrase_too_short`).
pub const MIN_CHARS: usize = 8;
/// Administrator passphrase: zxcvbn 3 (more than 10^8 guesses).
pub const ADMIN_MIN_SCORE: u8 = 3;
/// A recovery passphrase the user picks instead of the generated code: zxcvbn 4.
pub const RECOVERY_MIN_SCORE: u8 = 4;
/// Words that make a passphrase about this product weaker.
const PRODUCT_WORDS: [&str; 3] = ["zeropw", "zero", "vault"];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Strength {
    /// The zxcvbn score, 0 to 4.
    pub score: u8,
    /// Why the score is low (`too_short`, `common_password`, …); `null` when it is fine.
    pub reason: Option<&'static str>,
}

/// Score `value`; `related` are other inputs it must not resemble (the admin passphrase when
/// scoring a chosen recovery passphrase).
pub fn evaluate(value: &str, related: &[&str]) -> Strength {
    let mut inputs: Vec<&str> = PRODUCT_WORDS.to_vec();
    inputs.extend(related.iter().copied().filter(|s| !s.is_empty()));
    let entropy = zxcvbn::zxcvbn(value, &inputs);
    let score = u8::from(entropy.score());
    if value.chars().count() < MIN_CHARS {
        return Strength {
            score: score.min(1),
            reason: Some("too_short"),
        };
    }
    let warning = entropy.feedback().and_then(|f| f.warning()).map(reason_for);
    let reason = match warning {
        Some(reason) if score < RECOVERY_MIN_SCORE => Some(reason),
        _ if score < ADMIN_MIN_SCORE => Some("too_guessable"),
        _ => None,
    };
    Strength { score, reason }
}

fn reason_for(warning: Warning) -> &'static str {
    match warning {
        Warning::StraightRowsOfKeysAreEasyToGuess
        | Warning::ShortKeyboardPatternsAreEasyToGuess => "keyboard_pattern",
        Warning::RepeatsLikeAaaAreEasyToGuess
        | Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => "repeated",
        Warning::ThisIsATop10Password
        | Warning::ThisIsATop100Password
        | Warning::ThisIsACommonPassword => "common_password",
        Warning::ThisIsSimilarToACommonlyUsedPassword => "similar_to_common",
        Warning::SequencesLikeAbcAreEasyToGuess => "sequence",
        Warning::RecentYearsAreEasyToGuess | Warning::DatesAreOftenEasyToGuess => "date",
        Warning::AWordByItselfIsEasyToGuess => "single_word",
        Warning::NamesAndSurnamesByThemselvesAreEasyToGuess
        | Warning::CommonNamesAndSurnamesAreEasyToGuess => "name",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_values_are_capped_and_flagged() {
        let s = evaluate("x7#Qa9!", &[]);
        assert!(s.score <= 1);
        assert_eq!(s.reason, Some("too_short"));
        let empty = evaluate("", &[]);
        assert_eq!(empty.score, 0);
        assert_eq!(empty.reason, Some("too_short"));
    }

    #[test]
    fn common_passwords_score_low_with_a_reason() {
        let s = evaluate("password", &[]);
        assert!(s.score < ADMIN_MIN_SCORE);
        assert_eq!(s.reason, Some("common_password"));
        let s = evaluate("qwertyuiop", &[]);
        assert!(s.score < ADMIN_MIN_SCORE);
        assert!(s.reason.is_some());
        assert!(evaluate("zeropw2026", &[]).score < ADMIN_MIN_SCORE);
    }

    #[test]
    fn long_random_values_pass_both_thresholds() {
        let s = evaluate("velvet-ocean-27-quartz-lantern", &[]);
        assert!(s.score >= RECOVERY_MIN_SCORE, "{s:?}");
        assert_eq!(s.reason, None);
        let code = crate::recovery::generate().unwrap();
        assert_eq!(evaluate(code.passphrase.expose(), &[]).score, 4);
    }

    #[test]
    fn related_inputs_lower_the_score() {
        let admin = "velvet-ocean-27-quartz-lantern";
        assert!(evaluate(admin, &[admin]).score < evaluate(admin, &[]).score);
    }

    #[test]
    fn score_stays_within_zxcvbn_range() {
        for v in [
            "a",
            "abcdefgh",
            "Tr0ub4dor&3",
            "velvet-ocean-27-quartz-lantern",
        ] {
            assert!(evaluate(v, &[]).score <= 4);
        }
    }
}
