#![allow(dead_code)]
// Standard library imports
use std::time::Duration;

// External crate imports
use bytesize::{self, ByteSize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Default configuration constants
pub const DEFAULT_IDENTITY_TRAITS_SCHEMA_ID: &str = "default";
pub const DEFAULT_BROWSER_RETURN_URL: &str = "default_browser_return_url";
pub const DEFAULT_SQLITE_MEMORY_DSN: &str = "sqlite://file::memory:?_fk=true&cache=shared";
pub const DEFAULT_PASSWORD_HASHING_ALGORITHM: &str = "argon2";
pub const DEFAULT_CIPHER_ALGORITHM: &str = "noop";
pub const UNKNOWN_VERSION: &str = "unknown version";
pub const DSN: &str = "dsn";

// Configuration for Password Hashing Algorithms
pub const HIGHEST_AVAILABLE_AAL: &str = "highest available";
pub const ARGON2_DEFAULT_MEMORY: ByteSize = ByteSize::mb(128);
pub const ARGON2_DEFAULT_ITERATIONS: u32 = 1;
pub const ARGON2_DEFAULT_SALT_LENGTH: u32 = 16;
pub const ARGON2_DEFAULT_KEY_LENGTH: u32 = 32;
pub const ARGON2_DEFAULT_DURATION: Duration = Duration::from_millis(500);
pub const ARGON2_DEFAULT_DEVIATION: Duration = Duration::from_millis(500);
pub const ARGON2_DEFAULT_DEDICATED_MEMORY: ByteSize = ByteSize::gb(1);
pub const BCRYPT_DEFAULT_COST: u32 = 12;

// Default Session Cookie Name
pub const DEFAULT_SESSION_COOKIE_NAME: &str = "justid_session";

/// Configuration for Argon2 password hashing
///
/// # Fields
/// * `memory` - Amount of memory to use for hashing
/// * `iterations` - Number of iterations to perform
/// * `parallelism` - Degree of parallelism in computing
/// * `salt_length` - Length of salt in bytes
/// * `key_length` - Length of the generated hash in bytes
/// * `expected_duration` - Expected time to compute hash
/// * `expected_deviation` - Acceptable deviation from expected duration
/// * `dedicated_memory` - Memory dedicated to hashing operations
#[derive(Debug, Serialize, Deserialize)]
pub struct Argon2 {
    pub memory: ByteSize,
    pub iterations: u32,
    pub parallelism: u8,
    pub salt_length: u32,
    pub key_length: u32,
    pub expected_duration: Duration,
    pub expected_deviation: Duration,
    pub dedicated_memory: ByteSize,
}

/// Configuration for Bcrypt password hashing
///
/// # Fields
/// * `cost` - Work factor for Bcrypt algorithm
#[derive(Debug, Serialize, Deserialize)]
pub struct Bcrypt {
    pub cost: u32,
}

/// Configuration for self-service hooks
///
/// # Fields
/// * `name` - Name of the hook
/// * `config` - Hook configuration as JSON value
#[derive(Debug, Serialize, Deserialize)]
pub struct SelfServiceHook {
    pub name: String,
    pub config: Value,
}

/// Configuration for self-service authentication strategies
///
/// # Fields
/// * `enabled` - Whether the strategy is enabled
/// * `config` - Strategy configuration as JSON value
#[derive(Debug, Serialize, Deserialize)]
pub struct SelfServiceStrategy {
    pub enabled: bool,
    pub config: Value,
}

/// Extended self-service strategy configuration including passwordless and MFA options
///
/// # Fields
/// * `self_service_strategy` - Base strategy configuration
/// * `passwordless_enabled` - Whether passwordless authentication is enabled
/// * `mfa_enabled` - Whether multi-factor authentication is enabled
#[derive(Debug, Serialize, Deserialize)]
pub struct SelfServiceStrategyCode {
    pub self_service_strategy: SelfServiceStrategy,
    pub passwordless_enabled: bool,
    pub mfa_enabled: bool,
}

/// Schema definition for identity traits
///
/// # Fields
/// * `id` - Unique identifier for the schema
/// * `url` - URL where the schema is located
#[derive(Debug, Serialize, Deserialize)]
pub struct Schema {
    pub id: String,
    pub url: String,
}

/// Password policy configuration including HaveIBeenPwned integration
///
/// # Fields
/// * `have_i_been_pwned_host` - Host URL for HaveIBeenPwned API
/// * `have_i_been_pwned_enabled` - Whether HaveIBeenPwned check is enabled
/// * `max_breaches` - Maximum allowed number of breaches
/// * `ignore_network_errors` - Whether to ignore network errors during checks
/// * `min_password_length` - Minimum required password length
/// * `max_password_length` - Maximum allowed password length
/// * `identifier_similarity_check_enabled` - Whether to check password similarity with identifiers
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub have_i_been_pwned_host: String,
    pub have_i_been_pwned_enabled: bool,
    pub max_breaches: u8,
    pub ignore_network_errors: bool,
    pub min_password_length: u8,
    pub max_password_length: u8,
    pub identifier_similarity_check_enabled: bool,
}

/// Type alias for a collection of schemas
type Schemas = Vec<Schema>;
