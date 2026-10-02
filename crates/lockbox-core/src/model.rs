use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped when the encrypted JSON layout changes; part of the item AAD.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    SecureNote,
    CreditCard,
    Identity,
    Password,
    ApiCredential,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Username,
    Password,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FieldValue {
    Text(String),
    Concealed(String),
    Email(String),
    Url(String),
    /// Unix seconds.
    Date(i64),
    /// YYYYMM, e.g. 202712.
    MonthYear(u32),
    /// An `otpauth://` URI or a bare base32 secret.
    Totp(String),
    Phone(String),
}

impl FieldValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(s) | Self::Concealed(s) | Self::Email(s) | Self::Url(s) | Self::Totp(s)
            | Self::Phone(s) => Some(s),
            Self::Date(_) | Self::MonthYear(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub id: String,
    pub label: String,
    pub value: FieldValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Purpose>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub id: String,
    pub title: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub value: String,
    pub changed_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub id: Uuid,
    pub name: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Login only; the first one is primary.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Built-in fields (username/password carry a `purpose`).
    #[serde(default)]
    pub fields: Vec<Field>,
    /// Custom sections, like 1Password's.
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub notes: String,
    /// Newest first.
    #[serde(default)]
    pub password_history: Vec<HistoryEntry>,
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Item {
    pub fn new(vault_id: Uuid, kind: ItemKind, title: &str, now: i64) -> Self {
        Self {
            id: Uuid::new_v4(),
            vault_id,
            kind,
            title: title.to_owned(),
            tags: Vec::new(),
            favorite: false,
            urls: Vec::new(),
            fields: Vec::new(),
            sections: Vec::new(),
            notes: String::new(),
            password_history: Vec::new(),
            attachments: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn username(&self) -> Option<&str> {
        self.purpose_value(Purpose::Username)
    }

    pub fn password(&self) -> Option<&str> {
        self.purpose_value(Purpose::Password)
    }

    /// First TOTP field, built-in or in a section.
    pub fn totp(&self) -> Option<&str> {
        self.fields
            .iter()
            .chain(self.sections.iter().flat_map(|s| s.fields.iter()))
            .find_map(|f| match &f.value {
                FieldValue::Totp(s) => Some(s.as_str()),
                _ => None,
            })
    }

    /// Sets the password, pushing a changed non-empty old value into history.
    pub fn set_password(&mut self, new: &str, now: i64) {
        match self.fields.iter_mut().find(|f| f.purpose == Some(Purpose::Password)) {
            Some(field) => {
                let old = field.value.as_str().unwrap_or_default().to_owned();
                if old == new {
                    return;
                }
                field.value = FieldValue::Concealed(new.to_owned());
                if !old.is_empty() {
                    self.password_history.insert(0, HistoryEntry { value: old, changed_at: now });
                }
            }
            None => self.fields.push(Field {
                id: "password".into(),
                label: "password".into(),
                value: FieldValue::Concealed(new.to_owned()),
                purpose: Some(Purpose::Password),
            }),
        }
        self.updated_at = now;
    }

    pub fn overview(&self) -> ItemOverview {
        ItemOverview {
            id: self.id,
            vault_id: self.vault_id,
            kind: self.kind,
            title: self.title.clone(),
            subtitle: self.username().unwrap_or_default().to_owned(),
            urls: self.urls.clone(),
            tags: self.tags.clone(),
            favorite: self.favorite,
            updated_at: self.updated_at,
        }
    }

    fn purpose_value(&self, purpose: Purpose) -> Option<&str> {
        self.fields.iter().find(|f| f.purpose == Some(purpose)).and_then(|f| f.value.as_str())
    }
}

/// What lists and search need; no secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemOverview {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub subtitle: String,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub updated_at: i64,
}

impl ItemOverview {
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        std::iter::once(&self.title)
            .chain(std::iter::once(&self.subtitle))
            .chain(self.urls.iter())
            .chain(self.tags.iter())
            .any(|s| s.to_lowercase().contains(&q))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: Uuid,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Item {
        let mut item = Item::new(Uuid::new_v4(), ItemKind::Login, "GitHub", 100);
        item.urls.push("https://github.com/login".into());
        item.tags.push("dev".into());
        item.fields.push(Field {
            id: "username".into(),
            label: "username".into(),
            value: FieldValue::Text("ivan".into()),
            purpose: Some(Purpose::Username),
        });
        item.set_password("first", 100);
        item.sections.push(Section {
            id: "s1".into(),
            title: "".into(),
            fields: vec![Field {
                id: "otp".into(),
                label: "one-time password".into(),
                value: FieldValue::Totp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
                purpose: None,
            }],
        });
        item
    }

    #[test]
    fn accessors_find_purpose_fields_and_totp_in_sections() {
        let item = login();
        assert_eq!(item.username(), Some("ivan"));
        assert_eq!(item.password(), Some("first"));
        assert_eq!(item.totp(), Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn set_password_records_history_newest_first() {
        let mut item = login();
        item.set_password("second", 200);
        item.set_password("third", 300);
        assert_eq!(item.password(), Some("third"));
        let history: Vec<_> = item.password_history.iter().map(|h| (h.value.as_str(), h.changed_at)).collect();
        assert_eq!(history, vec![("second", 300), ("first", 200)]);
        assert_eq!(item.updated_at, 300);
    }

    #[test]
    fn set_password_to_same_value_is_a_no_op() {
        let mut item = login();
        item.set_password("first", 500);
        assert!(item.password_history.is_empty());
        assert_eq!(item.updated_at, 100);
    }

    #[test]
    fn json_round_trip() {
        let item = login();
        let json = serde_json::to_string(&item).unwrap();
        assert_eq!(serde_json::from_str::<Item>(&json).unwrap(), item);
    }

    #[test]
    fn overview_search_is_case_insensitive_over_title_user_url_tags() {
        let o = login().overview();
        assert_eq!(o.subtitle, "ivan");
        for q in ["", "  ", "git", "IVAN", "github.com", "DEV"] {
            assert!(o.matches(q), "query {q:?} should match");
        }
        assert!(!o.matches("gitlab"));
    }
}
