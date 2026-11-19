// The three pet and person patterns, copied from the cloud mvf_urgent.py. tests/pet_person.rs asserts each equals its source in tests/vectors/urgent_pet_person.json.
use super::patterns_gen::Pat;

#[cfg(test)]
mod tests {
    /// The cloud source spells accents as `é`; this file carries the letter (as patterns_gen.rs does). Same pattern, so the two are compared decoded.
    fn decoded(s: &str) -> String {
        let (mut out, mut rest) = (String::new(), s);
        while let Some(i) = rest.find("\\u") {
            out.push_str(&rest[..i]);
            out.push(char::from_u32(u32::from_str_radix(&rest[i + 2..i + 6], 16).unwrap()).unwrap());
            rest = &rest[i + 6..];
        }
        out + rest
    }

    #[test]
    fn each_pattern_is_the_source_the_cloud_gate_is_asserted_against() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../tests/vectors/urgent_pet_person.json")).expect("json");
        for p in [super::PET_DOSE, super::SELF_INTENT, super::PERSON_NOPOSS] {
            assert_eq!(decoded(v["patterns"][p.name].as_str().unwrap()), decoded(p.text), "{}", p.name);
            assert_eq!(p.flags, "i");
        }
        assert_eq!(v["patterns"].as_object().unwrap().len(), 3);
    }
}

pub const PET_DOSE: Pat = Pat { name: "_PET_DOSE", flags: "i", text: r####"\b(?:(?:lethal|fatal|deadly)\W++)?(?:overdos\w*|surdose|dose|poison\w*|empoisonn\w*|toxic|toxique|how (?:much|many)|combien)\W++(?:\w++(?:'\w++)?\W++){0,6}?(?:a|an|my|the|our|for|to|un|une|mon|ma|notre|pour)\W++(?:\w++(?:'\w++)?\W++)?(?:dog|dogs|puppy|pup|cat|cats|kitten|pet|horse|rabbit|bunny|ferret|parrot|bird|hamster|guinea pig|chien\w*|chiot|chat|chats|chaton|animal|lapin|cheval|oiseau)\b"#### };
pub const SELF_INTENT: Pat = Pat { name: "_SELF_INTENT", flags: "i", text: r####"\b(?:want|wanna|going to|gonna|plan|planning|thinking|considering|about to|veux|voudrais|vais|pense [àa])\b\W++(?:\w++(?:'\w++)?\W++){0,4}?(?:overdos\w*|surdoses?|(?:lethal|fatal|deadly)\W+(?:dose|amount|quantity)s?|(?:dose|quantit[ée])s?\W+(?:l[ée]tales?|mortelles?|fatales?))\b"#### };
pub const PERSON_NOPOSS: Pat = Pat { name: "_PERSON_NOPOSS", flags: "i", text: r####"\b(?:i|i'm|im|i've|ive|me|he|she|he's|she's|they|they're|we|someone|somebody|friend|mother|father|brother|sister|son|daughter|partner|wife|husband|kid|child|baby|patient|je|j|moi|il|elle|ils|elles|nous|quelqu'un|ami|amie|m[èe]re|p[èe]re|fr[èe]re|s[œo]e?ur|fils|fille|enfant)\b\W++(?:\w++(?:'\w++)?\W++){0,3}?(?:overdos\w*|surdoses?|(?:lethal|fatal|deadly)\W+(?:dose|amount|quantity)s?|(?:dose|quantit[ée])s?\W+(?:l[ée]tales?|mortelles?|fatales?))\b|\b(?:overdos\w*|surdoses?|(?:lethal|fatal|deadly)\W+(?:dose|amount|quantity)s?|(?:dose|quantit[ée])s?\W+(?:l[ée]tales?|mortelles?|fatales?))\W++(?:\w++(?:'\w++)?\W++){0,3}?(?:i|i'm|im|i've|ive|me|he|she|he's|she's|they|they're|we|someone|somebody|friend|mother|father|brother|sister|son|daughter|partner|wife|husband|kid|child|baby|patient|je|j|moi|il|elle|ils|elles|nous|quelqu'un|ami|amie|m[èe]re|p[èe]re|fr[èe]re|s[œo]e?ur|fils|fille|enfant)\b"#### };
