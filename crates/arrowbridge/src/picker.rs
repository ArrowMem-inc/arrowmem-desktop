//! The bridge model picker, client side. Pure logic: no network, no clock, no state.
//!
//! The list comes from the home machine router's model listing at run time, never from a constant. The router
//! answers `GET /v1/models` with a JSON body of this shape: `{"data":[{"id":"...","status":{"value":"loaded"}}]}`. The
//! `status` object is the router's own; a plain server that omits it is read as one loaded model.
//!
//! A pick that arrives while a coding job holds the coder: chat wins. The picker sends `PauseRequest::Pause`, the
//! coder side (a separate service, not built here) answers `paused` (a job was running and is now held) or `free` (no job).
//! Any other answer, or none, REFUSES the pick: the model is not switched, so the coder is never evicted without
//! the pause confirmed. When chat ends the picker sends `PauseRequest::Resume`.
//!
//! WORDS: `PAUSED` is the approved sentence, verbatim. `LIST_UNAVAILABLE` and `PICK_REFUSED` are
//! placeholder wording, UNCLEARED: the copy reviewer clears them before they ship in the UI.

use serde_json::{json, Value};

pub const MAX_MODELS: usize = 64;
pub const MAX_ID_LEN: usize = 200;

pub const PAUSED: &str = "The coding job is paused while you chat. It resumes when you are done.";
pub const LIST_UNAVAILABLE: &str = "The model list is unavailable. Only the loaded model is shown.";
pub const PICK_REFUSED: &str = "The coding job could not be paused, so the model was not changed. Try again.";

/// A body that is not what the contract says. One value for every way to be wrong: the caller fails closed on all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelEntry {
    pub id: String,
    pub loaded: bool,
}

fn id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_ID_LEN && !id.chars().any(|c| c.is_control())
}

/// The router listing. Unreadable when the body is not JSON, has no `data` array, holds an entry without a usable
/// `id`, holds a duplicate id, has more than `MAX_MODELS` entries, or is empty.
pub fn parse_listing(body: &str) -> Result<Vec<ModelEntry>, Unreadable> {
    let v: Value = serde_json::from_str(body).map_err(|_| Unreadable)?;
    let data = v.get("data").and_then(Value::as_array).ok_or(Unreadable)?;
    if data.is_empty() || data.len() > MAX_MODELS {
        return Err(Unreadable);
    }
    let mut out: Vec<ModelEntry> = Vec::with_capacity(data.len());
    for e in data {
        let id = e.get("id").and_then(Value::as_str).filter(|s| id_ok(s)).ok_or(Unreadable)?;
        if out.iter().any(|m| m.id == id) {
            return Err(Unreadable);
        }
        let loaded = match e.get("status").and_then(|s| s.get("value")).and_then(Value::as_str) {
            Some(s) => s == "loaded",
            None => data.len() == 1,
        };
        out.push(ModelEntry { id: id.to_string(), loaded });
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickerView {
    pub models: Vec<ModelEntry>,
    pub note: Option<&'static str>,
}

/// What the picker shows. When the listing cannot be read it shows the loaded model only (`loaded_now`, as the bridge
/// already knows it) and says the list is unavailable; with no known loaded model it shows nothing and says so.
pub fn picker_view(listing: Result<Vec<ModelEntry>, Unreadable>, loaded_now: Option<&str>) -> PickerView {
    match listing {
        Ok(models) => PickerView { models, note: None },
        Err(Unreadable) => PickerView {
            models: loaded_now.filter(|id| id_ok(id)).map(|id| ModelEntry { id: id.to_string(), loaded: true }).into_iter().collect(),
            note: Some(LIST_UNAVAILABLE),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseRequest {
    Pause { model: String },
    Resume,
}

impl PauseRequest {
    /// The body sent to the coder side: `{"action":"pause","model":"..."}` or `{"action":"resume"}`.
    pub fn to_json(&self) -> String {
        match self {
            PauseRequest::Pause { model } => json!({"action": "pause", "model": model}),
            PauseRequest::Resume => json!({"action": "resume"}),
        }
        .to_string()
    }
}

/// The request for a pick, or None when the id is not one the listing holds (a pick is never forwarded unlisted).
pub fn pick_request(models: &[ModelEntry], id: &str) -> Option<PauseRequest> {
    models.iter().any(|m| m.id == id).then(|| PauseRequest::Pause { model: id.to_string() })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReply {
    /// A coding job held the coder and is now paused.
    Paused,
    /// No job holds the coder (also the answer to a resume).
    Free,
}

/// `{"state":"paused"}` or `{"state":"free"}`; anything else is Unreadable.
pub fn parse_pause_reply(body: &str) -> Result<PauseReply, Unreadable> {
    let v: Value = serde_json::from_str(body).map_err(|_| Unreadable)?;
    match v.get("state").and_then(Value::as_str) {
        Some("paused") => Ok(PauseReply::Paused),
        Some("free") => Ok(PauseReply::Free),
        _ => Err(Unreadable),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickOutcome {
    /// Switch the model now; show the note if there is one.
    Go(Option<&'static str>),
    /// Do not switch; show the note.
    Refused(&'static str),
}

/// Fail closed: only a readable `paused` or `free` lets the model switch.
pub fn pick_outcome(reply: Result<PauseReply, Unreadable>) -> PickOutcome {
    match reply {
        Ok(PauseReply::Paused) => PickOutcome::Go(Some(PAUSED)),
        Ok(PauseReply::Free) => PickOutcome::Go(None),
        Err(Unreadable) => PickOutcome::Refused(PICK_REFUSED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: &str = r#"{"object":"list","data":[
        {"id":"model-a","object":"model","status":{"value":"unloaded"}},
        {"id":"model-b","object":"model","status":{"value":"loaded"}},
        {"id":"model-c","object":"model","status":{"value":"unloaded"}}]}"#;

    #[test]
    fn the_listing_holds_every_model_the_router_reports_and_marks_the_loaded_one() {
        let m = parse_listing(ROUTER).unwrap();
        assert_eq!(m.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), ["model-a", "model-b", "model-c"]);
        assert_eq!(m.iter().filter(|e| e.loaded).map(|e| e.id.as_str()).collect::<Vec<_>>(), ["model-b"]);
    }

    #[test]
    fn a_plain_server_with_one_entry_and_no_status_is_one_loaded_model() {
        let m = parse_listing(r#"{"data":[{"id":"only"}]}"#).unwrap();
        assert_eq!(m, vec![ModelEntry { id: "only".into(), loaded: true }]);
    }

    #[test]
    fn two_entries_without_status_are_listed_but_none_is_claimed_loaded() {
        let m = parse_listing(r#"{"data":[{"id":"a"},{"id":"b"}]}"#).unwrap();
        assert!(m.iter().all(|e| !e.loaded));
    }

    #[test]
    fn every_malformed_listing_is_unreadable() {
        let many = format!(r#"{{"data":[{}]}}"#, (0..=MAX_MODELS).map(|i| format!(r#"{{"id":"m{i}"}}"#)).collect::<Vec<_>>().join(","));
        let long = format!(r#"{{"data":[{{"id":"{}"}}]}}"#, "x".repeat(MAX_ID_LEN + 1));
        for bad in [
            "", "not json", "[]", "{}", r#"{"data":[]}"#, r#"{"data":{}}"#, r#"{"data":[{}]}"#, r#"{"data":[{"id":""}]}"#,
            r#"{"data":[{"id":7}]}"#, r#"{"data":[{"id":"a\nb"}]}"#, r#"{"data":[{"id":"a"},{"id":"a"}]}"#, many.as_str(), long.as_str(),
        ] {
            assert_eq!(parse_listing(bad), Err(Unreadable), "{bad}");
        }
    }

    #[test]
    fn a_readable_listing_is_shown_whole_with_no_note() {
        let v = picker_view(parse_listing(ROUTER), Some("model-b"));
        assert_eq!(v.models.len(), 3);
        assert_eq!(v.note, None);
    }

    #[test]
    fn an_unreadable_listing_shows_the_loaded_model_only_and_says_the_list_is_unavailable() {
        let v = picker_view(parse_listing("garbage"), Some("model-b"));
        assert_eq!(v.models, vec![ModelEntry { id: "model-b".into(), loaded: true }]);
        assert_eq!(v.note, Some(LIST_UNAVAILABLE));
        assert!(LIST_UNAVAILABLE.contains("unavailable"));
    }

    #[test]
    fn an_unreadable_listing_with_no_known_loaded_model_shows_nothing_and_still_says_so() {
        for loaded in [None, Some(""), Some("bad\nid")] {
            let v = picker_view(Err(Unreadable), loaded);
            assert!(v.models.is_empty());
            assert_eq!(v.note, Some(LIST_UNAVAILABLE));
        }
    }

    #[test]
    fn a_pick_is_forwarded_only_when_the_listing_holds_it() {
        let m = parse_listing(ROUTER).unwrap();
        assert_eq!(pick_request(&m, "model-c"), Some(PauseRequest::Pause { model: "model-c".into() }));
        assert_eq!(pick_request(&m, "model-z"), None);
        assert_eq!(pick_request(&m, ""), None);
    }

    #[test]
    fn the_requests_are_the_two_documented_bodies_and_escape_the_id() {
        assert_eq!(PauseRequest::Pause { model: "model-c".into() }.to_json(), r#"{"action":"pause","model":"model-c"}"#);
        assert_eq!(PauseRequest::Resume.to_json(), r#"{"action":"resume"}"#);
        let v: Value = serde_json::from_str(&PauseRequest::Pause { model: "a\"b".into() }.to_json()).unwrap();
        assert_eq!(v["model"], "a\"b");
    }

    #[test]
    fn the_two_replies_parse_and_anything_else_is_unreadable() {
        assert_eq!(parse_pause_reply(r#"{"state":"paused"}"#), Ok(PauseReply::Paused));
        assert_eq!(parse_pause_reply(r#"{"state":"free"}"#), Ok(PauseReply::Free));
        for bad in ["", "paused", "{}", r#"{"state":"busy"}"#, r#"{"state":"PAUSED"}"#, r#"{"state":1}"#, r#"["paused"]"#] {
            assert_eq!(parse_pause_reply(bad), Err(Unreadable), "{bad}");
        }
    }

    #[test]
    fn busy_coder_says_the_operators_words_and_the_pick_goes() {
        let o = pick_outcome(parse_pause_reply(r#"{"state":"paused"}"#));
        assert_eq!(o, PickOutcome::Go(Some("The coding job is paused while you chat. It resumes when you are done.")));
    }

    #[test]
    fn a_free_coder_picks_with_no_note() {
        assert_eq!(pick_outcome(parse_pause_reply(r#"{"state":"free"}"#)), PickOutcome::Go(None));
    }

    #[test]
    fn no_confirmed_pause_refuses_the_pick_so_the_coder_is_never_evicted() {
        assert_eq!(pick_outcome(parse_pause_reply("")), PickOutcome::Refused(PICK_REFUSED));
        assert_eq!(pick_outcome(Err(Unreadable)), PickOutcome::Refused(PICK_REFUSED));
    }

    #[test]
    fn the_words_are_plain_ascii_with_no_dash() {
        for w in [PAUSED, LIST_UNAVAILABLE, PICK_REFUSED] {
            assert!(w.is_ascii() && !w.contains('-'), "{w}");
        }
    }
}
