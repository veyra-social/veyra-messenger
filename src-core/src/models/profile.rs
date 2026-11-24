use serde::{Deserialize, Serialize};

pub const PROFILE_VISIBILITY_CONTACTS: &str = "contacts";
pub const PROFILE_VISIBILITY_FAVORITES_ONLY: &str = "favorites_only";

pub const PROFILE_LINK_TYPE_WEBSITE: &str = "website";
pub const PROFILE_LINK_TYPE_TELEGRAM: &str = "telegram";
pub const PROFILE_LINK_TYPE_WHATSAPP: &str = "whatsapp";
pub const PROFILE_LINK_TYPE_VK: &str = "vk";
pub const PROFILE_LINK_TYPE_INSTAGRAM: &str = "instagram";
pub const PROFILE_LINK_TYPE_FACEBOOK: &str = "facebook";
pub const PROFILE_LINK_TYPE_YOUTUBE: &str = "youtube";
pub const PROFILE_LINK_TYPE_TIKTOK: &str = "tiktok";
pub const PROFILE_LINK_TYPE_OTHER: &str = "other";

pub const PROFILE_LINK_TYPES: &[&str] = &[
    PROFILE_LINK_TYPE_WEBSITE,
    PROFILE_LINK_TYPE_TELEGRAM,
    PROFILE_LINK_TYPE_WHATSAPP,
    PROFILE_LINK_TYPE_VK,
    PROFILE_LINK_TYPE_INSTAGRAM,
    PROFILE_LINK_TYPE_FACEBOOK,
    PROFILE_LINK_TYPE_YOUTUBE,
    PROFILE_LINK_TYPE_TIKTOK,
    PROFILE_LINK_TYPE_OTHER,
];

pub fn default_profile_visibility() -> String {
    PROFILE_VISIBILITY_CONTACTS.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileField {
    #[serde(default)]
    pub value: String,
    #[serde(default = "default_profile_visibility")]
    pub visibility: String,
}

impl Default for ProfileField {
    fn default() -> Self {
        Self {
            value: String::new(),
            visibility: default_profile_visibility(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileLink {
    #[serde(default, rename = "type")]
    pub link_type: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_profile_visibility")]
    pub visibility: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileExtensions {
    #[serde(default)]
    pub about: ProfileField,
    #[serde(default)]
    pub status: ProfileField,
    #[serde(default)]
    pub mood: ProfileField,
    #[serde(default)]
    pub email: ProfileField,
    #[serde(default)]
    pub phone: ProfileField,
    #[serde(default)]
    pub links: Vec<ProfileLink>,
}
