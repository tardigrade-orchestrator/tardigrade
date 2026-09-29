//! A registry's login line (ADR-0096, determination 3).
//!
//! Pure rule, without a registry and without a network: what
//! `RegistryLogin::parse` makes out of a line decides what the node logs in
//! with -- and the refusal paths are half of it. A line nobody understands
//! must yield `None` and not something that *almost* fits.

use tg_runtime::network::RegistryLogin;

/// **The first word names the form** -- otherwise a password without a user
/// name would not be distinguishable from a token.
#[test]
fn the_first_word_names_the_form() {
    assert_eq!(
        RegistryLogin::parse("basic robot:secret"),
        Some(RegistryLogin::Basic {
            user: "robot".to_owned(),
            password: "secret".to_owned(),
        })
    );
    assert_eq!(
        RegistryLogin::parse("bearer ey.JhbGci"),
        Some(RegistryLogin::Bearer {
            token: "ey.JhbGci".to_owned(),
        })
    );
}

/// **The first colon separates.** A registry user name contains none, a
/// password may -- and truncating a password would yield a login the registry
/// refuses without anybody seeing the reason.
#[test]
fn a_password_may_contain_colons() {
    assert_eq!(
        RegistryLogin::parse("basic robot:a:b:c"),
        Some(RegistryLogin::Basic {
            user: "robot".to_owned(),
            password: "a:b:c".to_owned(),
        })
    );
}

/// **Without a leading word nothing is guessed.**
///
/// The counter-check to everything above: a line that looks like a credential
/// but does not name the form yields `None` -- and thereby an anonymous pull
/// that fails at the registry (determination 6). A guess would give a login
/// nobody wrote.
#[test]
fn a_line_without_a_form_is_refused() {
    for line in [
        "robot:secret",
        "ey.JhbGci",
        "",
        "   ",
        "Basic robot:secret",
        "basicrobot:secret",
    ] {
        assert_eq!(RegistryLogin::parse(line), None, "'{line}' was guessed");
    }
}

/// **An empty part is no login.**
///
/// `basic :secret` has no user, `bearer ` no token -- both would be a header
/// the registry answers with a `401` while the node believes it has logged
/// in.
#[test]
fn an_empty_part_is_not_a_login() {
    assert_eq!(RegistryLogin::parse("basic :secret"), None);
    assert_eq!(RegistryLogin::parse("bearer "), None);
    assert_eq!(RegistryLogin::parse("bearer    "), None);
}

/// **An empty password is one**, and that is no contradiction to the test
/// above: a user without a password occurs at registries that keep the name as
/// a token. What may be missing is the second part; what must not be missing
/// is the first.
#[test]
fn an_empty_password_is_still_a_login() {
    assert_eq!(
        RegistryLogin::parse("basic robot:"),
        Some(RegistryLogin::Basic {
            user: "robot".to_owned(),
            password: String::new(),
        })
    );
}

/// **A password cannot end in white space -- leading space stays.**
///
/// Measured, and the direction is wanted: a secret comes from a file or from
/// `stdin` and carries a line ending (`tgctl cluster secret put ... -`).
/// Without the trim a `\n` would stand in every password filed that way, and
/// the registry would refuse with a `401` -- an error an operator would look
/// for in the password and that sits in the line ending.
///
/// The price is the **asymmetry**, and it stands here so that nobody takes it
/// for an oversight: what falls away at the back stays standing at the
/// front.
#[test]
fn a_password_cannot_end_in_whitespace_but_may_begin_with_it() {
    // What stands at the back falls away -- a line ending, a space, a tab.
    for line in [
        "basic robot:secret\n",
        "basic robot:secret ",
        "basic robot:secret\t",
        "basic robot:secret\r\n",
    ] {
        assert_eq!(
            RegistryLogin::parse(line),
            Some(RegistryLogin::Basic {
                user: "robot".to_owned(),
                password: "secret".to_owned(),
            }),
            "{line:?}"
        );
    }

    // The counter-direction: what stands at the front stays. Without it a
    // reader that trims the password on both sides would be green too -- and a
    // password that begins with a space would quietly be a different one.
    assert_eq!(
        RegistryLogin::parse("basic robot: secret"),
        Some(RegistryLogin::Basic {
            user: "robot".to_owned(),
            password: " secret".to_owned(),
        })
    );
}

/// **Our derivation and the puller's agree** (ADR-0125, D2).
///
/// From ADR-0125 on `registry_of` is the **one** place: `tg-consensus` needs
/// it for its hint and must link no HTTP client, `tg-runtime` for the pull.
/// This witness holds it against `oci_client::Reference`, for the **same**
/// library carries out the pull afterwards -- if the two diverged, we would
/// log in at a different registry from the one we talk to.
///
/// The comparison is case-blind: `oci_client` gives the reference's spelling
/// back unchanged (measured), `registry_of` writes it lower-case -- and
/// exactly that is determination 1, because a registry host is a DNS name.
#[test]
fn registry_of_agrees_with_the_client_that_pulls() {
    for reference in [
        "registry.example.com/api:1",
        "registry.example.com:5000/api:1",
        "localhost:5000/api:1",
        "localhost/api:1",
        "api:1",
        "library/api:1",
        "example/api:1",
        "ghcr.io/org/api:1",
        "REGISTRY.example.com/api:1",
        "registry.example.com/a/b/c:1",
        "registry.example.com/api@sha256:\
         0000000000000000000000000000000000000000000000000000000000000000",
    ] {
        let parsed: oci_client::Reference = reference.parse().expect("the reference");
        assert_eq!(
            tg_model::egress::registry_of(reference),
            parsed.registry().to_ascii_lowercase(),
            "'{reference}': our derivation deviates from the puller's"
        );
    }
}
