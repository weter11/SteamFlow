//! Cover-art fetching, caching and state for the game detail poster.
//!
//! The poster slot in the UI is a fixed 250x375 (2:3) portrait box. This
//! module owns everything that decides *which* asset is fetched and *what* is
//! kept on disk, so `ui.rs` only has to ask for a cover and draw it.
//!
//! # Asset choice
//!
//! Steam's CDN exposes several artwork families per app, and only some of
//! them are portrait 2:3 art suitable for the poster slot.
//!
//! The order below is deliberate. The poster slot is 250x375 logical px, so
//! the sharpest useful art is 500x750 device px at 2x scaling:
//!
//! 1. [`CoverVariant::Portrait2x`] — `library_600x900_2x.jpg` (600x900, 2:3).
//!    The smallest asset that is sharp at 500x750. It is downscaled to
//!    exactly 500x750 on decode.
//! 2. [`CoverVariant::Portrait`] — `library_600x900.jpg` (300x450, 2:3).
//!    Same aspect ratio at 1x; used when the 2x art is absent.
//! 3. [`CoverVariant::Banner`] — `header.jpg` (460x215). Landscape, but it
//!    carries the game's logo, so it is the useful fallback for the many apps
//!    that publish no portrait art.
//! 4. [`CoverVariant::Hero`] — `library_hero.jpg` (1920x620). Last resort:
//!    landscape, no logo, and large.
//! 5. [`CoverVariant::StoreHeader`] — the store-published header image.
//!    Newer titles publish artwork only under a content-hashed CDN path
//!    whose hash is exposed by the store's app-details API, so this variant
//!    is what reaches art for them. It is landscape, like [`CoverVariant::Banner`].
//!
//! Landscape art is never stretched: it is drawn as a banner fitted to the
//! poster width, over the existing gradient card.
//!
//! # Requests
//!
//! Every request is a conditional GET. A per-(appid, variant) record in the
//! on-disk state file stores whether the asset is known to exist, its
//! `ETag`/`Last-Modified`, and when it was last checked. A fresh record plus a
//! decodable cached file means *zero* network traffic. A stale record means a
//! conditional request that answers `304 Not Modified` and leaves the file
//! untouched.
//!
//! A definitive `404` is remembered for a long TTL so the app stops probing an
//! asset that does not exist. Transient failures (timeout, 5xx, 429, DNS) are
//! never persisted as "absent": the existing cached file is kept and the
//! variant is retried later with an in-memory backoff.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Schema version of the per-appid cover state file.
///
/// A file written under any other version is discarded and rebuilt from the
/// cache, so an incompatible schema can never be read as current state.
pub const STATE_VERSION: u32 = 2;

/// How long a confirmed-missing asset is remembered before it is probed again.
///
/// Long on purpose: the set of apps without portrait art barely changes, and
/// re-probing every absent variant on every start is what produced the
/// "N x 7 requests" storm.
pub const ABSENT_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long a present asset is served from disk without contacting the CDN.
pub const PRESENT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a transient failure blocks a retry of the same variant.
pub const TRANSIENT_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// How long the caller should wait before asking for a cover again after an
/// ordinary attempt (a fresh download, or a definitive "no such asset").
pub const COVER_RECHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long the caller should wait after a transient failure before asking
/// again.
///
/// A timeout or a 5xx says nothing about the asset, so the cover must be
/// retried long before the ordinary recheck interval - otherwise one flaky
/// request blanks the poster for a day.
pub const COVER_TRANSIENT_RETRY: Duration = Duration::from_secs(5 * 60);

/// Poster slot size in logical pixels. The slot is 2:3.
pub const POSTER_SIZE: (u32, u32) = (250, 375);

/// Longest edge, in pixels, of a texture uploaded to the GPU.
///
/// The poster slot is 250x375 logical px, so the sharpest useful art is
/// 500x750 device px at 2x scaling. Decoded art is downscaled to this bound
/// before upload: `library_600x900_2x` (600x900) shrinks to exactly 500x750,
/// and `library_hero` (1920x620) to 750x242, which keeps the GPU footprint
/// of a library-sized texture set small.
pub const MAX_TEXTURE_EDGE: u32 = 750;

/// A cover-art asset family, in the order the poster prefers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CoverVariant {
    /// `library_600x900_2x.jpg` — 600x900, 2:3 portrait.
    Portrait2x,
    /// `library_600x900.jpg` — 300x450, 2:3 portrait.
    Portrait,
    /// `header.jpg` — 460x215 landscape, carries the game logo.
    Banner,
    /// `library_hero.jpg` — 1920x620 landscape, no logo.
    Hero,
    /// The store-published header image, fetched from a content-hashed CDN
    /// path that only the store's app-details endpoint reveals.
    StoreHeader,
}

impl CoverVariant {
    /// The CDN families that live on the plain, hash-free asset path, in the
    /// order the poster prefers them.
    pub const CDN: [CoverVariant; 4] = [
        CoverVariant::Portrait2x,
        CoverVariant::Portrait,
        CoverVariant::Banner,
        CoverVariant::Hero,
    ];

    /// Every variant the state file can hold, most preferred first.
    pub const ALL: [CoverVariant; 5] = [
        CoverVariant::Portrait2x,
        CoverVariant::Portrait,
        CoverVariant::Banner,
        CoverVariant::Hero,
        CoverVariant::StoreHeader,
    ];

    /// Stable identifier used in file names and in the state file.
    pub fn key(self) -> &'static str {
        match self {
            CoverVariant::Portrait2x => "portrait2x",
            CoverVariant::Portrait => "portrait",
            CoverVariant::Banner => "banner",
            CoverVariant::Hero => "hero",
            CoverVariant::StoreHeader => "store_header",
        }
    }

    /// The CDN file name for this variant, if it has a fixed one.
    ///
    /// [`CoverVariant::StoreHeader`] does not: its URL carries a per-asset
    /// content hash and is resolved through the store's app-details API.
    fn cdn_file(self) -> Option<&'static str> {
        match self {
            CoverVariant::Portrait2x => Some("library_600x900_2x"),
            CoverVariant::Portrait => Some("library_600x900"),
            CoverVariant::Banner => Some("header"),
            CoverVariant::Hero => Some("library_hero"),
            CoverVariant::StoreHeader => None,
        }
    }

    /// Whether this variant is portrait (2:3) art.
    ///
    /// Portrait art fills the poster slot; landscape art is drawn as a banner
    /// fitted to the slot width.
    pub fn is_portrait(self) -> bool {
        matches!(self, CoverVariant::Portrait | CoverVariant::Portrait2x)
    }

    /// The CDN URL for this variant and app, if the URL is fixed.
    ///
    /// Returns `None` for [`CoverVariant::StoreHeader`], whose URL is only
    /// known once the store's app-details response has been consulted.
    pub fn url(self, appid: u32) -> Option<String> {
        self.cdn_file()
            .map(|file| format!("https://cdn.akamai.steamstatic.com/steam/apps/{appid}/{file}.jpg"))
    }

    /// The cache file name (without directory) for this variant and app.
    pub fn cache_file(self, appid: u32) -> String {
        format!("{appid}_{}.jpg", self.key())
    }
}

/// What is known about one variant of one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariantState {
    /// The asset was fetched and the file is cached.
    Present {
        /// `ETag` from the last successful response.
        etag: Option<String>,
        /// `Last-Modified` from the last successful response.
        last_modified: Option<String>,
        /// Unix seconds when the asset was last confirmed present.
        checked_at: u64,
        /// Size of the cached file in bytes.
        bytes: u64,
    },
    /// The CDN answered 404: the asset does not exist.
    Absent {
        /// Unix seconds when the 404 was observed.
        checked_at: u64,
    },
}

impl VariantState {
    /// HTTP validators to send with a conditional request.
    fn validators(&self) -> (Option<&str>, Option<&str>) {
        match self {
            VariantState::Present {
                etag,
                last_modified,
                ..
            } => (etag.as_deref(), last_modified.as_deref()),
            VariantState::Absent { .. } => (None, None),
        }
    }
}

/// The on-disk state for one appid.
///
/// One file per appid, `<appid>_cover_state.json`, next to the cached
/// images.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverState {
    /// Schema version, see [`STATE_VERSION`].
    pub version: u32,
    /// The app this state belongs to.
    pub appid: u32,
    /// Per-variant records, keyed by [`CoverVariant::key`].
    pub variants: HashMap<String, VariantState>,
}

impl CoverState {
    /// An empty state for `appid`.
    pub fn new(appid: u32) -> Self {
        CoverState {
            version: STATE_VERSION,
            appid,
            variants: HashMap::new(),
        }
    }

    /// The record for `variant`, if any.
    pub fn get(&self, variant: CoverVariant) -> Option<&VariantState> {
        self.variants.get(variant.key())
    }

    /// The record for `variant`, creating it if absent.
    pub fn entry(&mut self, variant: CoverVariant) -> &mut VariantState {
        self.variants
            .entry(variant.key().to_string())
            .or_insert(VariantState::Absent { checked_at: 0 })
    }

    /// True when `variant` is known to be present and was checked recently
    /// enough that it does not need revalidating.
    fn is_fresh_present(&self, variant: CoverVariant, now: u64) -> bool {
        match self.get(variant) {
            Some(VariantState::Present { checked_at, .. }) => {
                now.saturating_sub(*checked_at) < PRESENT_TTL.as_secs()
            }
            _ => false,
        }
    }

    /// True when `variant` is known to be absent and the absence is still
    /// trusted, so it must not be re-probed.
    fn is_fresh_absent(&self, variant: CoverVariant, now: u64) -> bool {
        match self.get(variant) {
            Some(VariantState::Absent { checked_at }) => {
                now.saturating_sub(*checked_at) < ABSENT_TTL.as_secs()
            }
            _ => false,
        }
    }
}

/// Outcome of one conditional request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The asset changed; the body is the new content.
    Body {
        /// The raw image bytes.
        bytes: Vec<u8>,
        /// `ETag` of the response, if any.
        etag: Option<String>,
        /// `Last-Modified` of the response, if any.
        last_modified: Option<String>,
    },
    /// The asset did not change since the cached copy.
    NotModified {
        /// `ETag` of the response, if any.
        etag: Option<String>,
        /// `Last-Modified` of the response, if any.
        last_modified: Option<String>,
    },
    // `Body` and `NotModified` carry the same validators, so each variant
    // documents its own fields.
    /// The asset does not exist (HTTP 404). Definitive.
    NotFound,
    /// A transient failure: timeout, 5xx, 429, DNS error. Never persisted
    /// as "absent".
    Transient(String),
}

/// The result of a headers-only request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadOutcome {
    /// The asset exists. `bytes` is the body size the server reports.
    Present {
        /// `ETag` of the resource, if any.
        etag: Option<String>,
        /// `Last-Modified` of the resource, if any.
        last_modified: Option<String>,
        /// `Content-Length` of the resource, if the server reports one.
        bytes: Option<u64>,
    },
    /// The asset does not exist (HTTP 404).
    NotFound,
    /// A transient failure: timeout, 5xx, 429, DNS error.
    Transient(String),
}

/// The HTTP surface the cover pipeline needs.
///
/// Implemented for real by [`ReqwestCoverHttp`]; tests substitute an
/// in-memory fake so the whole pipeline can be exercised without a network.
#[async_trait::async_trait]
pub trait CoverHttp: Send + Sync {
    /// Fetch `url`, sending the supplied conditional headers when present.
    async fn get(&self, url: &str, etag: Option<&str>, last_modified: Option<&str>)
        -> FetchOutcome;

    /// Fetch only the headers of `url`.
    ///
    /// Used to compare a cached file against the server without downloading
    /// a body: when the server offers no validators, an unchanged
    /// `Content-Length` is enough evidence that the cached copy is current.
    async fn head(&self, url: &str) -> HeadOutcome;
}

/// What the store said about an app's published header image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOutcome {
    /// The store publishes a header image at this URL.
    Found(String),
    /// The app has no store page, so it publishes no artwork at all.
    /// Definitive, and safe to record.
    NoStorePage,
    /// The store could not be asked, or answered with something unusable.
    /// Says nothing about the app, so it must not be recorded.
    Unavailable(String),
}

/// Resolves the store-published header image URL for an app.
///
/// Steam moved newer titles off the hash-free `/steam/apps/<id>/<name>.jpg`
/// path onto a content-addressed one,
/// `/store_item_assets/steam/apps/<id>/<sha1>/<name>.jpg`, where the hash
/// differs per asset. The hash is published in exactly one place: the
/// `header_image` field of the store's app-details response. A resolver is
/// therefore the only way to reach artwork for those titles.
///
/// The three [`StoreOutcome`] answers are distinct on purpose: only a
/// `NoStorePage` answer may be persisted as "no art". A lookup that failed,
/// or whose body did not parse, must stay transient.
#[async_trait::async_trait]
pub trait StoreHeaderResolver: Send + Sync {
    /// Ask the store which header image, if any, `appid` publishes.
    async fn resolve(&self, appid: u32) -> StoreOutcome;
}

/// A [`CoverHttp`] that never serves anything.
///
/// Used when the HTTP client cannot be built: every request fails as
/// transient, so the cover is simply unavailable instead of the app
/// panicking at startup.
pub struct DisabledCoverHttp;

#[async_trait::async_trait]
impl CoverHttp for DisabledCoverHttp {
    async fn get(
        &self,
        _url: &str,
        _etag: Option<&str>,
        _last_modified: Option<&str>,
    ) -> FetchOutcome {
        FetchOutcome::Transient("cover art is disabled".to_string())
    }

    async fn head(&self, _url: &str) -> HeadOutcome {
        HeadOutcome::Transient("cover art is disabled".to_string())
    }
}

/// A [`StoreHeaderResolver`] that never resolves anything.
///
/// Used by tests and by callers that only want the hash-free CDN path. Every
/// app is reported as having no store page, which is true of this
/// configuration: it never looks one up.
pub struct NoStoreHeaderResolver;

#[async_trait::async_trait]
impl StoreHeaderResolver for NoStoreHeaderResolver {
    async fn resolve(&self, _appid: u32) -> StoreOutcome {
        StoreOutcome::NoStorePage
    }
}

/// A [`StoreHeaderResolver`] backed by the store's app-details API.
pub struct ReqwestStoreHeaderResolver {
    client: reqwest::Client,
}

impl ReqwestStoreHeaderResolver {
    /// Build a resolver with a connect and total timeout.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .context("failed to build store-header HTTP client")?;
        Ok(ReqwestStoreHeaderResolver { client })
    }
}

#[async_trait::async_trait]
impl StoreHeaderResolver for ReqwestStoreHeaderResolver {
    async fn resolve(&self, appid: u32) -> StoreOutcome {
        let url =
            format!("https://store.steampowered.com/api/appdetails?appids={appid}&filters=basic");
        let response = match self.client.get(url).send().await {
            Ok(response) => response,
            Err(err) => return StoreOutcome::Unavailable(err.to_string()),
        };
        let status = response.status();
        if !status.is_success() {
            return StoreOutcome::Unavailable(format!(
                "appdetails answered HTTP {}",
                status.as_u16()
            ));
        }
        let body = match response.bytes().await {
            Ok(body) => body,
            Err(err) => return StoreOutcome::Unavailable(err.to_string()),
        };
        // A 200 whose body does not parse as JSON is normally an HTML block
        // page, not an answer about the app: reading it as "no store page"
        // would record the app as art-less for a week.
        let json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(json) => json,
            Err(err) => {
                return StoreOutcome::Unavailable(format!("appdetails body was not JSON: {err}"))
            }
        };
        let Some(entry) = json.get(appid.to_string()) else {
            return StoreOutcome::Unavailable("appdetails named no app".to_string());
        };
        // The API answers `{"<id>": {"success": false}}` for apps with no
        // store page. Those apps have no published artwork at all.
        if entry.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
            return StoreOutcome::NoStorePage;
        }
        match entry
            .get("data")
            .and_then(|data| data.get("header_image"))
            .and_then(serde_json::Value::as_str)
        {
            Some(header) => {
                StoreOutcome::Found(header.split('?').next().unwrap_or(header).to_string())
            }
            // `success: true` without a `header_image` is a shape we do not
            // recognise; treat it as a failed lookup rather than as proof
            // that no art exists.
            None => StoreOutcome::Unavailable("appdetails had no header_image".to_string()),
        }
    }
}

/// A [`CoverHttp`] backed by `reqwest`.
pub struct ReqwestCoverHttp {
    client: reqwest::Client,
}

impl ReqwestCoverHttp {
    /// Build a client with connect and total timeouts.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .context("failed to build cover-art HTTP client")?;
        Ok(ReqwestCoverHttp { client })
    }
}

#[async_trait::async_trait]
impl CoverHttp for ReqwestCoverHttp {
    async fn get(
        &self,
        url: &str,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> FetchOutcome {
        let mut req = self.client.get(url);
        if let Some(etag) = etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
        }
        let response = match req.send().await {
            Ok(response) => response,
            Err(err) => return FetchOutcome::Transient(err.to_string()),
        };
        let status = response.status();
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let last_modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        match status.as_u16() {
            404 => FetchOutcome::NotFound,
            304 => FetchOutcome::NotModified {
                etag,
                last_modified,
            },
            code if !(200..300).contains(&code) => FetchOutcome::Transient(format!("HTTP {code}")),
            _ => match response.bytes().await {
                Ok(bytes) => FetchOutcome::Body {
                    bytes: bytes.to_vec(),
                    etag,
                    last_modified,
                },
                Err(err) => FetchOutcome::Transient(err.to_string()),
            },
        }
    }

    async fn head(&self, url: &str) -> HeadOutcome {
        let response = match self.client.head(url).send().await {
            Ok(response) => response,
            Err(err) => return HeadOutcome::Transient(err.to_string()),
        };
        let status = response.status();
        if status.as_u16() == 404 {
            return HeadOutcome::NotFound;
        }
        if !(200..300).contains(&status.as_u16()) {
            return HeadOutcome::Transient(format!("HTTP {}", status.as_u16()));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let last_modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        HeadOutcome::Present {
            etag,
            last_modified,
            bytes,
        }
    }
}

/// What the UI receives for one app.
#[derive(Debug, Clone)]
pub struct CoverArt {
    /// Which asset family the art came from.
    pub variant: CoverVariant,
    /// Absolute path of the cached image file.
    pub path: PathBuf,
    /// Decoded pixel size of the image.
    pub size: (u32, u32),
}

/// Why a cover could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverError {
    /// No asset of any variant exists for this app.
    NoAsset,
    /// The fetch failed transiently and will be retried later.
    Transient(String),
    /// The cache directory could not be used.
    Io(String),
}

/// Result of asking for one app's cover.
#[derive(Debug, Clone)]
pub enum CoverResult {
    /// Art is available.
    Found(CoverArt),
    /// No art exists for this app; the UI shows the title card.
    Missing(CoverError),
}

/// How long the caller should wait before asking for a cover again.
///
/// The UI uses this to gate the next request: a transient failure must be
/// retried soon, while a definitive answer is left alone.
pub fn retry_after(result: &CoverResult) -> Duration {
    match result {
        CoverResult::Found(_) => COVER_RECHECK_INTERVAL,
        CoverResult::Missing(CoverError::Transient(_))
        | CoverResult::Missing(CoverError::Io(_)) => COVER_TRANSIENT_RETRY,
        CoverResult::Missing(CoverError::NoAsset) => COVER_RECHECK_INTERVAL,
    }
}

/// Fetch, cache and track cover art.
///
/// One instance is shared by the whole app: it owns the single HTTP client and
/// the concurrency limiter, so a library-wide refresh cannot turn into an
/// `N x variants` request burst.
pub struct CoverService {
    http: std::sync::Arc<dyn CoverHttp>,
    images_dir: PathBuf,
    /// Resolves the store-published header URL for titles that no longer
    /// publish art on the hash-free CDN path.
    store: std::sync::Arc<dyn StoreHeaderResolver>,
    /// Bounds how many cover requests may be in flight at once.
    gate: tokio::sync::Semaphore,
    /// Variants that failed transiently and must not be retried yet.
    backoff: std::sync::Mutex<HashMap<(u32, &'static str), u64>>,
}

impl CoverService {
    /// Build a service that downloads from the real Steam CDN.
    pub fn new(images_dir: PathBuf) -> Result<Self> {
        let http = std::sync::Arc::new(ReqwestCoverHttp::new()?);
        let store = std::sync::Arc::new(ReqwestStoreHeaderResolver::new()?);
        Ok(Self::with_http_and_store(http, store, images_dir))
    }

    /// Build a service around an arbitrary [`CoverHttp`].
    pub fn with_http(http: std::sync::Arc<dyn CoverHttp>, images_dir: PathBuf) -> Self {
        Self::with_http_and_store(http, std::sync::Arc::new(NoStoreHeaderResolver), images_dir)
    }

    /// Build a service around an arbitrary [`CoverHttp`] and
    /// [`StoreHeaderResolver`].
    pub fn with_http_and_store(
        http: std::sync::Arc<dyn CoverHttp>,
        store: std::sync::Arc<dyn StoreHeaderResolver>,
        images_dir: PathBuf,
    ) -> Self {
        CoverService {
            http,
            images_dir,
            store,
            gate: tokio::sync::Semaphore::new(4),
            backoff: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Directory holding cached images and per-appid state files.
    pub fn images_dir(&self) -> &Path {
        &self.images_dir
    }

    /// Ensure a cover for `appid` is available, downloading it if needed.
    ///
    /// Returns the art and where it is cached. The caller must not assume
    /// the returned variant is the most preferred one: the preferred variant
    /// may simply not exist for this app.
    pub async fn ensure(&self, appid: u32) -> CoverResult {
        self.ensure_inner(appid, false).await
    }

    /// Re-check every variant for `appid`, ignoring freshness windows.
    ///
    /// Used by "Refresh Library": the user asked for a fresh look, so cached
    /// records are revalidated. Requests are still conditional and valid
    /// cached files are never deleted.
    pub async fn refresh(&self, appid: u32) -> CoverResult {
        self.ensure_inner(appid, true).await
    }

    async fn ensure_inner(&self, appid: u32, force: bool) -> CoverResult {
        if let Err(err) = tokio::fs::create_dir_all(&self.images_dir).await {
            return CoverResult::Missing(CoverError::Io(err.to_string()));
        }

        let mut state = self.load_state(appid).await;
        let now = now_unix();
        // Set when a variant was skipped because it is backing off after a
        // transient failure. The answer is then "not known yet", not "no art":
        // reporting `NoAsset` would put the UI on its 24 h cooldown.
        let mut backing_off = false;

        // A cached, decodable file plus a fresh record means no traffic at
        // all. Check the preferred variants first so the best art is used.
        for variant in CoverVariant::ALL {
            if self.is_backed_off(appid, variant, now) {
                backing_off = true;
                continue;
            }
            let path = self.images_dir.join(variant.cache_file(appid));
            let fresh = state.is_fresh_present(variant, now);
            // A refresh deliberately re-checks even a fresh record, so the
            // cached file is revalidated rather than served blind.
            if fresh && !force && decodable(&path).await {
                if let Some(size) = image_size(&path).await {
                    return CoverResult::Found(CoverArt {
                        variant,
                        path,
                        size,
                    });
                }
            }
            if !force && state.is_fresh_absent(variant, now) {
                // Known-missing asset: do not re-probe it, but keep looking
                // for the next variant.
                continue;
            }
            // The store-published header has a per-asset hash in its URL, so
            // it is fetched through a different path than the fixed CDN
            // families.
            let fetched = if variant == CoverVariant::StoreHeader {
                self.fetch_store_header(appid, &mut state, now).await
            } else {
                self.fetch_variant(appid, variant, &mut state, now).await
            };
            match fetched {
                Ok(Some(art)) => {
                    self.save_state(appid, &state).await;
                    return CoverResult::Found(art);
                }
                Ok(None) => {
                    // This variant is absent; try the next one.
                    continue;
                }
                Err(err) => {
                    self.save_state(appid, &state).await;
                    // The network failed, but a cached copy may still be
                    // perfectly good. Serve it rather than blanking the
                    // poster: an offline app should show the art it has.
                    if let Some(art) = self.best_cached_cover(appid, &state).await {
                        return CoverResult::Found(art);
                    }
                    return CoverResult::Missing(err);
                }
            }
        }

        self.save_state(appid, &state).await;
        if backing_off {
            return CoverResult::Missing(CoverError::Transient(
                "a variant is backing off after a transient failure".to_string(),
            ));
        }
        CoverResult::Missing(CoverError::NoAsset)
    }

    /// The best cached cover for `appid`, ignoring freshness.
    ///
    /// Any variant recorded as present counts, even if its record is stale:
    /// the point is to show *something* when the network is unavailable. A
    /// variant whose file is missing or undecodable does not count.
    async fn best_cached_cover(&self, appid: u32, state: &CoverState) -> Option<CoverArt> {
        for variant in CoverVariant::ALL {
            if !matches!(state.get(variant), Some(VariantState::Present { .. })) {
                continue;
            }
            let path = self.images_dir.join(variant.cache_file(appid));
            let Some(size) = image_size(&path).await else {
                continue;
            };
            return Some(CoverArt {
                variant,
                path,
                size,
            });
        }
        None
    }

    /// Fetch the store-published header image for `appid`.
    ///
    /// Newer titles publish their artwork only under a content-addressed CDN
    /// path whose hash is exposed by the store's app-details API. This is the
    /// last resort in the chain: it yields a landscape banner (the header
    /// image), never a portrait.
    async fn fetch_store_header(
        &self,
        appid: u32,
        state: &mut CoverState,
        now: u64,
    ) -> Result<Option<CoverArt>, CoverError> {
        let variant = CoverVariant::StoreHeader;
        match self.store.resolve(appid).await {
            StoreOutcome::Found(url) => self.fetch_url(appid, variant, &url, state, now).await,
            StoreOutcome::NoStorePage => {
                // Definitive: the app has no store page, so it publishes no
                // artwork at all. Record it so the store API is not asked
                // again for a week.
                *state.entry(variant) = VariantState::Absent { checked_at: now };
                Ok(None)
            }
            StoreOutcome::Unavailable(message) => {
                // The store could not be asked, or answered with something
                // unusable. That says nothing about the app's artwork, so
                // nothing is persisted and the variant is retried later.
                tracing::warn!(
                    appid,
                    error = %message,
                    "store header lookup failed transiently"
                );
                self.mark_backoff(appid, variant, now);
                Err(CoverError::Transient(message))
            }
        }
    }

    /// Fetch one variant, updating `state` in place.
    ///
    /// `Ok(None)` means "this variant does not exist, try another one";
    /// `Err` means the fetch failed transiently and the whole attempt should
    /// stop.
    async fn fetch_variant(
        &self,
        appid: u32,
        variant: CoverVariant,
        state: &mut CoverState,
        now: u64,
    ) -> Result<Option<CoverArt>, CoverError> {
        let Some(url) = variant.url(appid) else {
            // Only the hash-free CDN families reach this path; the
            // store-published header has its own fetcher.
            *state.entry(variant) = VariantState::Absent { checked_at: now };
            return Ok(None);
        };
        self.fetch_url(appid, variant, &url, state, now).await
    }

    /// Fetch `url` for `variant` and record the outcome in `state`.
    ///
    /// This is the single place that talks to the CDN, so the request policy
    /// (conditional GET, HEAD compare, 404 vs transient) is identical for
    /// every asset family.
    async fn fetch_url(
        &self,
        appid: u32,
        variant: CoverVariant,
        url: &str,
        state: &mut CoverState,
        now: u64,
    ) -> Result<Option<CoverArt>, CoverError> {
        let path = self.images_dir.join(variant.cache_file(appid));
        let (mut etag, mut last_modified) = state
            .get(variant)
            .map(|s| s.validators())
            .unwrap_or((None, None));

        // A record may claim the asset is present while the file is gone (it
        // was deleted, or a previous write was interrupted). The validators
        // then describe a body we do not have: a conditional GET would come
        // back 304 and leave us with no file at all. Drop them and fetch
        // unconditionally.
        let file_present = decodable(&path).await;
        if !file_present {
            etag = None;
            last_modified = None;
        }

        // A record with no validators cannot be revalidated with a
        // conditional GET. Compare cheaply instead: a HEAD that reports the
        // same body size proves the cached copy is current, so no body is
        // downloaded. This only applies when the cached file is actually
        // there - otherwise there is nothing to compare against.
        if file_present && etag.is_none() && last_modified.is_none() {
            if let Some(cached_bytes) = state.get(variant).and_then(record_bytes) {
                let _permit = self.gate.acquire().await;
                let started = std::time::Instant::now();
                let head = self.http.head(url).await;
                let elapsed = started.elapsed();
                drop(_permit);
                match head {
                    HeadOutcome::Present {
                        etag: head_etag,
                        last_modified: head_last_modified,
                        bytes: Some(server_bytes),
                    } if server_bytes == cached_bytes => {
                        tracing::debug!(
                            appid,
                            variant = variant.key(),
                            outcome = "unchanged",
                            bytes = server_bytes,
                            elapsed_ms = elapsed.as_millis() as u64,
                            "cover variant unchanged"
                        );
                        *state.entry(variant) = VariantState::Present {
                            etag: head_etag,
                            last_modified: head_last_modified,
                            checked_at: now,
                            bytes: cached_bytes,
                        };
                        return match image_size(&path).await {
                            Some(size) => Ok(Some(CoverArt {
                                variant,
                                path,
                                size,
                            })),
                            None => {
                                *state.entry(variant) = VariantState::Absent { checked_at: now };
                                Ok(None)
                            }
                        };
                    }
                    HeadOutcome::NotFound => {
                        tracing::debug!(
                            appid,
                            variant = variant.key(),
                            outcome = "absent",
                            elapsed_ms = elapsed.as_millis() as u64,
                            "cover variant absent"
                        );
                        *state.entry(variant) = VariantState::Absent { checked_at: now };
                        return Ok(None);
                    }
                    HeadOutcome::Transient(message) => {
                        tracing::warn!(
                            appid,
                            variant = variant.key(),
                            outcome = "transient",
                            elapsed_ms = elapsed.as_millis() as u64,
                            error = %message,
                            "cover variant HEAD failed transiently"
                        );
                        self.mark_backoff(appid, variant, now);
                        return Err(CoverError::Transient(message));
                    }
                    // The size changed, or the server gave no size: fall
                    // through to a full conditional GET.
                    HeadOutcome::Present { .. } => {}
                }
            }
        }

        let _permit = self.gate.acquire().await;
        let started = std::time::Instant::now();
        let outcome = self.http.get(url, etag, last_modified).await;
        let elapsed = started.elapsed();
        drop(_permit);

        match outcome {
            FetchOutcome::NotModified {
                etag,
                last_modified,
            } => {
                tracing::debug!(
                    appid,
                    variant = variant.key(),
                    outcome = "not_modified",
                    elapsed_ms = elapsed.as_millis() as u64,
                    "cover variant revalidated"
                );
                let bytes = tokio::fs::metadata(&path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                let previous = state.get(variant).cloned();
                let etag = etag.or_else(|| previous.as_ref().and_then(etag_of));
                let last_modified =
                    last_modified.or_else(|| previous.as_ref().and_then(last_modified_of));
                *state.entry(variant) = VariantState::Present {
                    etag,
                    last_modified,
                    checked_at: now,
                    bytes,
                };
                match image_size(&path).await {
                    Some(size) => Ok(Some(CoverArt {
                        variant,
                        path,
                        size,
                    })),
                    // A 304 with no usable file on disk is not evidence that
                    // the asset is missing: the server says it exists and is
                    // unchanged. Recording it as absent would blacklist a
                    // perfectly good asset for a week. Treat it as a
                    // transient problem so it is retried.
                    None => {
                        tracing::warn!(
                            appid,
                            variant = variant.key(),
                            outcome = "not_modified_without_file",
                            "server reported the asset unchanged but the cached file is unusable"
                        );
                        self.mark_backoff(appid, variant, now);
                        Err(CoverError::Transient(format!(
                            "{} answered 304 but the cached file is unusable",
                            variant.key()
                        )))
                    }
                }
            }
            FetchOutcome::Body {
                bytes,
                etag,
                last_modified,
            } => {
                tracing::debug!(
                    appid,
                    variant = variant.key(),
                    outcome = "downloaded",
                    bytes = bytes.len(),
                    elapsed_ms = elapsed.as_millis() as u64,
                    "cover variant downloaded"
                );
                // A body that does not decode is not proof that the asset is
                // missing: it can be an HTML error page, a truncated
                // response, or a proxy interstitial. Recording it as absent
                // would blacklist a perfectly good asset for a week, so treat
                // it as a transient failure and retry later. The bad body is
                // never written to the cache.
                if !decodes(&bytes) {
                    tracing::warn!(
                        appid,
                        variant = variant.key(),
                        outcome = "undecodable_body",
                        bytes = bytes.len(),
                        elapsed_ms = elapsed.as_millis() as u64,
                        "server returned a body that is not an image"
                    );
                    self.mark_backoff(appid, variant, now);
                    return Err(CoverError::Transient(format!(
                        "{} returned a body that is not an image",
                        variant.key()
                    )));
                }
                if let Err(err) = write_atomic(&path, &bytes).await {
                    return Err(CoverError::Io(err.to_string()));
                }
                let len = bytes.len() as u64;
                *state.entry(variant) = VariantState::Present {
                    etag,
                    last_modified,
                    checked_at: now,
                    bytes: len,
                };
                match image_size(&path).await {
                    Some(size) => Ok(Some(CoverArt {
                        variant,
                        path,
                        size,
                    })),
                    None => {
                        *state.entry(variant) = VariantState::Absent { checked_at: now };
                        Ok(None)
                    }
                }
            }
            FetchOutcome::NotFound => {
                // Definitive: the asset does not exist. Remember it for a
                // long TTL so it is not probed again on every start.
                tracing::debug!(
                    appid,
                    variant = variant.key(),
                    outcome = "absent",
                    elapsed_ms = elapsed.as_millis() as u64,
                    "cover variant absent"
                );
                *state.entry(variant) = VariantState::Absent { checked_at: now };
                Ok(None)
            }
            FetchOutcome::Transient(message) => {
                // Never persist a transient failure as "absent": that would
                // blacklist the asset for a week. Keep whatever is cached and
                // back off in memory.
                tracing::warn!(
                    appid,
                    variant = variant.key(),
                    outcome = "transient",
                    elapsed_ms = elapsed.as_millis() as u64,
                    error = %message,
                    "cover variant fetch failed transiently"
                );
                self.mark_backoff(appid, variant, now);
                Err(CoverError::Transient(message))
            }
        }
    }

    /// Load the state file for `appid`, migrating older formats.
    async fn load_state(&self, appid: u32) -> CoverState {
        let path = self.state_path(appid);
        let raw = match tokio::fs::read(&path).await {
            Ok(raw) => raw,
            Err(_) => return CoverState::new(appid),
        };
        match serde_json::from_slice::<CoverState>(&raw) {
            Ok(state) if state.version == STATE_VERSION => state,
            // An unknown schema cannot be trusted, so the old records are
            // discarded rather than inherited.
            _ => {
                // Old schemas also named their cache files differently
                // (`<appid>_hero_capsule.jpg`, `<appid>_library_hero_2x.jpg`,
                // ...). Those files belong to no current variant, so drop
                // them instead of keeping megabytes of art nothing reads.
                remove_obsolete_files(&self.images_dir, appid).await;
                CoverState::new(appid)
            }
        }
    }

    /// Write the state file for `appid`.
    async fn save_state(&self, appid: u32, state: &CoverState) {
        let path = self.state_path(appid);
        let mut state = state.clone();
        state.version = STATE_VERSION;
        state.appid = appid;
        if let Ok(bytes) = serde_json::to_vec(&state) {
            let _ = write_atomic(&path, &bytes).await;
        }
    }

    fn state_path(&self, appid: u32) -> PathBuf {
        self.images_dir.join(format!("{appid}_cover_state.json"))
    }

    fn is_backed_off(&self, appid: u32, variant: CoverVariant, now: u64) -> bool {
        let backoff = match self.backoff.lock() {
            Ok(backoff) => backoff,
            Err(poisoned) => poisoned.into_inner(),
        };
        backoff
            .get(&(appid, variant.key()))
            .is_some_and(|until| now < *until)
    }

    fn mark_backoff(&self, appid: u32, variant: CoverVariant, now: u64) {
        let mut backoff = match self.backoff.lock() {
            Ok(backoff) => backoff,
            Err(poisoned) => poisoned.into_inner(),
        };
        backoff.insert((appid, variant.key()), now + TRANSIENT_BACKOFF.as_secs());
    }
}

/// Unix seconds since the epoch.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// The cached body size recorded for a variant, if it is present.
fn record_bytes(state: &VariantState) -> Option<u64> {
    match state {
        VariantState::Present { bytes, .. } => Some(*bytes),
        VariantState::Absent { .. } => None,
    }
}

fn etag_of(state: &VariantState) -> Option<String> {
    match state {
        VariantState::Present { etag, .. } => etag.clone(),
        VariantState::Absent { .. } => None,
    }
}

fn last_modified_of(state: &VariantState) -> Option<String> {
    match state {
        VariantState::Present { last_modified, .. } => last_modified.clone(),
        VariantState::Absent { .. } => None,
    }
}

/// Write `bytes` to `path` atomically: a temporary file plus a rename, so a
/// crash mid-write never leaves a truncated image behind.
async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to rename into {}", path.display()))?;
    Ok(())
}

/// True when `bytes` decodes as an image.
fn decodes(bytes: &[u8]) -> bool {
    image::load_from_memory(bytes).is_ok()
}

/// True when the file at `path` exists and decodes as an image.
async fn decodable(path: &Path) -> bool {
    match tokio::fs::read(path).await {
        Ok(bytes) => decodes(&bytes),
        Err(_) => false,
    }
}

/// Pixel size of the image at `path`, if it decodes.
async fn image_size(path: &Path) -> Option<(u32, u32)> {
    let bytes = tokio::fs::read(path).await.ok()?;
    let image = image::load_from_memory(&bytes).ok()?;
    Some((image.width(), image.height()))
}

/// Scale `size` down so neither edge exceeds `max_edge`, preserving aspect.
pub fn fit_within(size: (u32, u32), max_edge: u32) -> (u32, u32) {
    let (w, h) = size;
    let longest = w.max(h);
    if longest <= max_edge || longest == 0 {
        return (w, h);
    }
    let scale = max_edge as f64 / longest as f64;
    (
        ((w as f64 * scale).round() as u32).max(1),
        ((h as f64 * scale).round() as u32).max(1),
    )
}

/// Load the cached image at `path`, downscaled so neither edge exceeds
/// [`MAX_TEXTURE_EDGE`].
///
/// Returns RGBA bytes ready for upload to the GPU. Synchronous on purpose:
/// it runs on the egui thread, and the files involved are a few hundred KB.
pub fn load_texture_bytes(path: &Path) -> Result<(Vec<u8>, u32, u32)> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let image = image::load_from_memory(&bytes)
        .with_context(|| format!("failed to decode {}", path.display()))?;
    let (w, h) = fit_within((image.width(), image.height()), MAX_TEXTURE_EDGE);
    let rgba = if (w, h) == (image.width(), image.height()) {
        image.to_rgba8()
    } else {
        image::imageops::resize(
            &image.to_rgba8(),
            w,
            h,
            image::imageops::FilterType::Triangle,
        )
    };
    Ok((rgba.into_raw(), w, h))
}

/// Remove cache files and state that belong to no current variant.
///
/// Old schemas named their files differently (`<appid>_hero_capsule.jpg`,
/// `<appid>_header_image.jpg`), so a migrated directory can hold art that
/// nothing reads. Current files are left alone.
pub async fn remove_obsolete_files(images_dir: &Path, appid: u32) {
    let current: Vec<String> = CoverVariant::ALL
        .iter()
        .map(|variant| variant.cache_file(appid))
        .collect();
    let mut entries = match tokio::fs::read_dir(images_dir).await {
        Ok(entries) => entries,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        let belongs_to_app = name.starts_with(&format!("{appid}_"));
        if !belongs_to_app {
            continue;
        }
        if current.iter().any(|c| c == &name) {
            continue;
        }
        let _ = tokio::fs::remove_file(&path).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// An in-memory [`CoverHttp`] that models the Steam CDN.
    ///
    /// Each URL holds a *resource*: a body plus its validators. A request that
    /// carries a matching validator is answered `304 Not Modified`, exactly as
    /// the live CDN does; a request without one gets the body. This is closer
    /// to the real server than a fixed script, so the tests exercise the same
    /// paths the live one does.
    struct FakeHttp {
        /// URL -> the resource the CDN currently serves.
        resources: Mutex<HashMap<String, FakeResource>>,
        /// URLs whose next request must fail transiently, with the count left.
        failures: Mutex<HashMap<String, usize>>,
        /// URLs that always answer 304, whatever the client sends.
        always_not_modified: Mutex<HashSet<String>>,
        /// Every URL requested, in order.
        calls: Mutex<Vec<String>>,
        /// Number of requests served.
        count: AtomicUsize,
    }

    #[derive(Clone)]
    struct FakeResource {
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    }

    impl FakeHttp {
        fn new() -> Self {
            FakeHttp {
                resources: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
                always_not_modified: Mutex::new(HashSet::new()),
                calls: Mutex::new(Vec::new()),
                count: AtomicUsize::new(0),
            }
        }

        /// Publish a resource at `url`, as the CDN would.
        fn publish(&self, url: &str, body: Vec<u8>, etag: Option<&str>) {
            self.resources.lock().unwrap().insert(
                url.to_string(),
                FakeResource {
                    body,
                    etag: etag.map(str::to_string),
                    last_modified: Some("Mon, 10 Feb 2025 17:57:16 GMT".to_string()),
                },
            );
        }

        /// Remove the resource at `url`: the CDN answers 404.
        fn remove(&self, url: &str) {
            self.resources.lock().unwrap().remove(url);
        }

        /// Make the next `times` requests for `url` fail transiently.
        fn fail_next(&self, url: &str, times: usize) {
            self.failures.lock().unwrap().insert(url.to_string(), times);
        }

        /// Make `url` always answer 304, whatever the client sends.
        ///
        /// Models a CDN that claims the asset is unchanged even when the
        /// client has no copy of it.
        fn always_not_modified(&self, url: &str) {
            self.always_not_modified
                .lock()
                .unwrap()
                .insert(url.to_string());
        }

        /// Publish a body that is *not* a decodable image (an HTML error
        /// page served with a 200, as some CDNs do).
        fn publish_garbage(&self, url: &str) {
            self.resources.lock().unwrap().insert(
                url.to_string(),
                FakeResource {
                    body: b"<html><body>Service Unavailable</body></html>".to_vec(),
                    etag: Some("\"garbage\"".to_string()),
                    last_modified: Some("Mon, 10 Feb 2025 17:57:16 GMT".to_string()),
                },
            );
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl CoverHttp for FakeHttp {
        async fn get(
            &self,
            url: &str,
            etag: Option<&str>,
            last_modified: Option<&str>,
        ) -> FetchOutcome {
            self.calls.lock().unwrap().push(url.to_string());
            self.count.fetch_add(1, Ordering::SeqCst);

            let mut failures = self.failures.lock().unwrap();
            if let Some(remaining) = failures.get_mut(url) {
                if *remaining > 0 {
                    *remaining -= 1;
                    return FetchOutcome::Transient("simulated transient failure".into());
                }
            }
            drop(failures);

            if self.always_not_modified.lock().unwrap().contains(url) {
                return FetchOutcome::NotModified {
                    etag: Some("\"v1\"".to_string()),
                    last_modified: Some("Mon, 10 Feb 2025 17:57:16 GMT".to_string()),
                };
            }

            let resource = self.resources.lock().unwrap().get(url).cloned();
            let Some(resource) = resource else {
                return FetchOutcome::NotFound;
            };
            // nginx honours If-Modified-Since; the Steam CDN answers 304 for a
            // matching Last-Modified even when the ETag does not match.
            let unchanged = match (&resource.etag, etag) {
                (Some(known), Some(sent)) => known == sent,
                _ => match (&resource.last_modified, last_modified) {
                    (Some(known), Some(sent)) => known == sent,
                    _ => false,
                },
            };
            if unchanged {
                return FetchOutcome::NotModified {
                    etag: resource.etag,
                    last_modified: resource.last_modified,
                };
            }
            FetchOutcome::Body {
                bytes: resource.body,
                etag: resource.etag,
                last_modified: resource.last_modified,
            }
        }

        async fn head(&self, url: &str) -> HeadOutcome {
            self.calls.lock().unwrap().push(url.to_string());
            self.count.fetch_add(1, Ordering::SeqCst);
            let resource = self.resources.lock().unwrap().get(url).cloned();
            match resource {
                Some(resource) => HeadOutcome::Present {
                    etag: resource.etag,
                    last_modified: resource.last_modified,
                    bytes: Some(resource.body.len() as u64),
                },
                None => HeadOutcome::NotFound,
            }
        }
    }

    /// A [`StoreHeaderResolver`] that serves a fixed URL per appid.
    struct FakeStore {
        urls: Mutex<HashMap<u32, String>>,
        /// Lookups still to answer with an unusable body (a 200 carrying an
        /// HTML page instead of the app-details JSON).
        unusable: AtomicUsize,
        /// Number of times the resolver was consulted.
        calls: AtomicUsize,
    }

    impl FakeStore {
        fn new() -> Self {
            FakeStore {
                urls: Mutex::new(HashMap::new()),
                unusable: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
            }
        }

        fn publish(&self, appid: u32, url: &str) {
            self.urls.lock().unwrap().insert(appid, url.to_string());
        }

        /// Make the next `times` lookups answer 200 with an unusable body.
        fn fail_next(&self, times: usize) {
            self.unusable.store(times, Ordering::SeqCst);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl StoreHeaderResolver for FakeStore {
        async fn resolve(&self, appid: u32) -> StoreOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.unusable.load(Ordering::SeqCst) > 0 {
                self.unusable.fetch_sub(1, Ordering::SeqCst);
                return StoreOutcome::Unavailable("200 with an HTML body".to_string());
            }
            match self.urls.lock().unwrap().get(&appid) {
                Some(url) => StoreOutcome::Found(url.clone()),
                None => StoreOutcome::NoStorePage,
            }
        }
    }

    fn jpeg_bytes(width: u32, height: u32) -> Vec<u8> {
        let image = image::RgbImage::new(width, height);
        let mut buffer = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut buffer, image::ImageFormat::Jpeg)
            .expect("encode jpeg");
        buffer.into_inner()
    }

    fn make_service(http: Arc<FakeHttp>, dir: &Path) -> CoverService {
        CoverService::with_http(http, dir.to_path_buf())
    }

    #[tokio::test]
    async fn fresh_cache_makes_zero_requests() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        let url = CoverVariant::Portrait2x.url(570).unwrap();
        http.publish(&url, jpeg_bytes(600, 900), Some("\"v1\""));

        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert_eq!(http.count(), 1, "first ensure downloads once");

        // Second ensure: fresh record + valid file => no traffic at all.
        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert_eq!(http.count(), 1, "fresh cache must not touch the network");
    }

    #[tokio::test]
    async fn stale_plus_304_leaves_file_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        http.publish(&url, jpeg_bytes(600, 900), Some("\"v1\""));

        service.ensure(570).await;
        let path = dir.path().join(CoverVariant::Portrait2x.cache_file(570));
        let before = tokio::fs::read(&path).await.unwrap();

        // Age the record past the freshness window.
        age_state(dir.path(), 570, PRESENT_TTL.as_secs() + 1).await;

        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        let after = tokio::fs::read(&path).await.unwrap();
        assert_eq!(before, after, "304 must not rewrite the file");
        assert_eq!(http.count(), 2);
    }

    #[tokio::test]
    async fn stale_plus_200_replaces_file() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        http.publish(&url, jpeg_bytes(600, 900), Some("\"v1\""));

        service.ensure(570).await;
        let path = dir.path().join(CoverVariant::Portrait2x.cache_file(570));
        assert_eq!(image_size(&path).await, Some((600, 900)));

        // The asset changes on the CDN: a new ETag and a new body.
        http.publish(&url, jpeg_bytes(300, 450), Some("\"v2\""));

        age_state(dir.path(), 570, PRESENT_TTL.as_secs() + 1).await;
        service.ensure(570).await;

        assert_eq!(image_size(&path).await, Some((300, 450)));
        assert_eq!(http.count(), 2);
    }

    #[tokio::test]
    async fn not_found_is_persisted_and_not_reprobed() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait.url(570).unwrap();
        http.remove(&url);

        // No asset at all for any variant.
        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Missing(CoverError::NoAsset)));
        // Every CDN variant was probed once, and the failures are recorded.
        let calls = http.calls();
        assert_eq!(calls.len(), CoverVariant::CDN.len());

        // A second ensure must not re-probe the absent variants.
        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Missing(CoverError::NoAsset)));
        assert_eq!(
            http.count(),
            CoverVariant::CDN.len(),
            "absent assets must not be re-probed within the TTL"
        );
    }

    #[tokio::test]
    async fn store_header_is_used_when_no_cdn_asset_exists() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let store = Arc::new(FakeStore::new());
        let service = CoverService::with_http_and_store(
            http.clone(),
            store.clone(),
            dir.path().to_path_buf(),
        );

        // No CDN family exists for this app...
        for variant in CoverVariant::CDN {
            http.remove(&variant.url(570).unwrap());
        }
        // ...but the store publishes a header image for it.
        let header_url = "https://example.invalid/store_item_assets/steam/apps/570/abc/header.jpg";
        store.publish(570, header_url);
        http.publish(header_url, jpeg_bytes(460, 215), Some("\"v1\""));

        let result = service.ensure(570).await;
        match result {
            CoverResult::Found(art) => {
                assert_eq!(art.variant, CoverVariant::StoreHeader);
                assert!(!art.variant.is_portrait());
            }
            other => panic!("expected store header art, got {other:?}"),
        }
        assert_eq!(store.calls(), 1);
    }

    #[tokio::test]
    async fn portrait_present_means_the_store_is_never_consulted() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let store = Arc::new(FakeStore::new());
        let service = CoverService::with_http_and_store(
            http.clone(),
            store.clone(),
            dir.path().to_path_buf(),
        );

        http.publish(
            &CoverVariant::Portrait2x.url(570).unwrap(),
            jpeg_bytes(600, 900),
            None,
        );

        service.ensure(570).await;
        assert_eq!(
            store.calls(),
            0,
            "the store API must not be queried when portrait art exists"
        );
    }

    #[tokio::test]
    async fn an_app_without_a_store_page_is_not_re_resolved_within_the_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let store = Arc::new(FakeStore::new());
        let service = CoverService::with_http_and_store(
            http.clone(),
            store.clone(),
            dir.path().to_path_buf(),
        );

        for variant in CoverVariant::CDN {
            http.remove(&variant.url(570).unwrap());
        }
        // The store has no page for this app, so the resolver returns None.

        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Missing(CoverError::NoAsset)));
        assert_eq!(store.calls(), 1);

        // A second ensure must not ask the store again.
        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Missing(CoverError::NoAsset)));
        assert_eq!(
            store.calls(),
            1,
            "the store must not be re-queried within the TTL"
        );
    }

    /// A store lookup whose 200 body is not the app-details JSON (an HTML
    /// block page) says nothing about the app. It must not be recorded as
    /// "no art", so the next session finds the real header with no state
    /// cleared in between.
    #[tokio::test]
    async fn an_html_store_response_does_not_blacklist_the_header() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let store = Arc::new(FakeStore::new());
        let header =
            "https://cdn.akamai.steamstatic.com/store_item_assets/steam/apps/570/abc/header.jpg";

        // Only the store publishes art for this app.
        for variant in CoverVariant::CDN {
            http.remove(&variant.url(570).unwrap());
        }
        http.publish(header, jpeg_bytes(460, 215), Some("\"h1\""));
        store.fail_next(1);

        let service = CoverService::with_http_and_store(
            http.clone(),
            store.clone(),
            dir.path().to_path_buf(),
        );
        let result = service.ensure(570).await;
        assert!(
            matches!(result, CoverResult::Missing(CoverError::Transient(_))),
            "an unusable store body is transient, not a missing asset: {result:?}"
        );

        // Nothing may be persisted for the store header.
        let raw = tokio::fs::read(dir.path().join("570_cover_state.json"))
            .await
            .unwrap();
        let state: CoverState = serde_json::from_slice(&raw).unwrap();
        assert!(
            !matches!(
                state.get(CoverVariant::StoreHeader),
                Some(VariantState::Absent { .. })
            ),
            "an unusable store body must not be persisted as absent"
        );

        // The store recovers. A new service on the same state (the backoff
        // lives in memory only) must find the header.
        store.publish(570, header);
        let service = CoverService::with_http_and_store(
            http.clone(),
            store.clone(),
            dir.path().to_path_buf(),
        );
        let result = service.ensure(570).await;
        assert!(
            matches!(result, CoverResult::Found(_)),
            "the retry must find the store header: {result:?}"
        );
        let path = dir.path().join(CoverVariant::StoreHeader.cache_file(570));
        assert_eq!(image_size(&path).await, Some((460, 215)));
    }

    /// A variant that is backing off must not be reported as absent: the
    /// answer is still "unknown", so the UI must not start its 24 h cooldown.
    #[tokio::test]
    async fn a_backed_off_variant_is_not_reported_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();
        http.publish_garbage(&url);

        let first = service.ensure(570).await;
        assert!(matches!(
            first,
            CoverResult::Missing(CoverError::Transient(_))
        ));
        let before = http.calls().iter().filter(|call| **call == url).count();

        let second = service.ensure(570).await;
        assert!(
            matches!(second, CoverResult::Missing(CoverError::Transient(_))),
            "a backed-off variant must not be reported as absent: {second:?}"
        );
        let after = http.calls().iter().filter(|call| **call == url).count();
        assert_eq!(before, after, "the backoff must suppress the request");
    }

    #[tokio::test]
    async fn transient_failure_is_not_persisted_and_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        http.publish(&url, jpeg_bytes(600, 900), Some("\"v1\""));
        http.fail_next(&url, 1);

        // First call fails transiently.
        let result = service.ensure(570).await;
        assert!(matches!(
            result,
            CoverResult::Missing(CoverError::Transient(_))
        ));

        // The failure must NOT be recorded as absent, so a later attempt
        // retries. Clear the in-memory backoff to simulate the next session.
        service.backoff.lock().unwrap().clear();
        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert_eq!(http.count(), 2);
    }

    #[tokio::test]
    async fn portrait_present_means_landscape_never_requested() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        http.publish(
            &CoverVariant::Portrait2x.url(570).unwrap(),
            jpeg_bytes(600, 900),
            None,
        );

        service.ensure(570).await;
        let calls = http.calls();
        assert_eq!(calls, vec![CoverVariant::Portrait2x.url(570).unwrap()]);
        assert!(
            !calls
                .iter()
                .any(|c| c.contains("header") || c.contains("library_hero")),
            "landscape variants must not be requested once portrait art exists"
        );
    }

    #[tokio::test]
    async fn landscape_only_falls_back_to_banner() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        // Portrait art absent, banner present.
        http.remove(&CoverVariant::Portrait.url(570).unwrap());
        http.remove(&CoverVariant::Portrait2x.url(570).unwrap());
        http.publish(
            &CoverVariant::Banner.url(570).unwrap(),
            jpeg_bytes(460, 215),
            None,
        );

        let result = service.ensure(570).await;
        match result {
            CoverResult::Found(art) => {
                assert_eq!(art.variant, CoverVariant::Banner);
                assert!(!art.variant.is_portrait());
            }
            other => panic!("expected banner art, got {other:?}"),
        }
        let calls = http.calls();
        assert!(calls.contains(&CoverVariant::Banner.url(570).unwrap()));
        assert!(!calls.contains(&CoverVariant::Hero.url(570).unwrap()));
    }

    #[tokio::test]
    async fn nothing_available_returns_a_result() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        // Every CDN variant 404s.
        for variant in CoverVariant::CDN {
            http.remove(&variant.url(570).unwrap());
        }

        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Missing(CoverError::NoAsset)));
    }

    #[tokio::test]
    async fn old_state_file_is_migrated_and_poison_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        // The previous schema: no `version`, and a `failed: true` that would
        // otherwise suppress the fetch for 24 hours.
        let legacy = serde_json::json!({
            "cached_variant": null,
            "last_checked_unix_secs": now_unix(),
            "failed": true
        });
        tokio::fs::write(
            dir.path().join("570_cover_state.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .await
        .unwrap();

        http.publish(
            &CoverVariant::Portrait2x.url(570).unwrap(),
            jpeg_bytes(600, 900),
            None,
        );

        // The poisoned legacy state must not prevent the download.
        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert_eq!(http.count(), 1);

        // The state file is now the new schema.
        let raw = tokio::fs::read(dir.path().join("570_cover_state.json"))
            .await
            .unwrap();
        let state: CoverState = serde_json::from_slice(&raw).unwrap();
        assert_eq!(state.version, STATE_VERSION);
    }

    #[tokio::test]
    async fn a_record_without_validators_is_compared_with_a_head_request() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        // The asset is published without validators at all.
        http.publish(&url, jpeg_bytes(600, 900), None);

        service.ensure(570).await;
        let path = dir.path().join(CoverVariant::Portrait2x.cache_file(570));
        let before = tokio::fs::read(&path).await.unwrap();

        // Age the record so it is rechecked.
        age_state(dir.path(), 570, PRESENT_TTL.as_secs() + 1).await;
        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));

        // The file must be untouched: an unchanged Content-Length is enough
        // evidence, so no body is downloaded.
        let after = tokio::fs::read(&path).await.unwrap();
        assert_eq!(
            before, after,
            "an unchanged asset must not be re-downloaded"
        );
    }

    #[tokio::test]
    async fn migrating_an_old_cache_deletes_the_obsolete_files() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        // The previous schema and its cache file names.
        tokio::fs::write(
            dir.path().join("570_cover_state.json"),
            serde_json::to_vec(&serde_json::json!({
                "cached_variant": "hero_capsule",
                "last_checked_unix_secs": now_unix(),
                "failed": false
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let obsolete = dir.path().join("570_hero_capsule.jpg");
        tokio::fs::write(&obsolete, jpeg_bytes(374, 448))
            .await
            .unwrap();

        http.publish(
            &CoverVariant::Portrait2x.url(570).unwrap(),
            jpeg_bytes(600, 900),
            None,
        );

        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert!(
            !obsolete.exists(),
            "the obsolete cache file must be deleted during migration"
        );
    }

    #[tokio::test]
    async fn two_app_starts_make_zero_body_downloads() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        http.publish(
            &CoverVariant::Portrait2x.url(570).unwrap(),
            jpeg_bytes(600, 900),
            Some("\"v1\""),
        );

        service.ensure(570).await;
        assert_eq!(http.count(), 1);

        // A "second app start" is a fresh service over the same cache dir.
        let second = make_service(http.clone(), dir.path());
        let result = second.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert_eq!(http.count(), 1, "a second start must not re-download");
    }

    #[tokio::test]
    async fn refresh_revalidates_but_keeps_valid_files() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        http.publish(
            &CoverVariant::Portrait2x.url(570).unwrap(),
            jpeg_bytes(600, 900),
            Some("\"v1\""),
        );

        service.ensure(570).await;
        let path = dir.path().join(CoverVariant::Portrait2x.cache_file(570));
        let before = tokio::fs::read(&path).await.unwrap();

        // Refresh bypasses the freshness window and revalidates.
        let result = service.refresh(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert_eq!(http.count(), 2, "refresh must revalidate");
        let after = tokio::fs::read(&path).await.unwrap();
        assert_eq!(before, after, "refresh must keep a valid cached file");
    }

    #[tokio::test]
    async fn every_exit_path_delivers_a_result() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        // Transient failure on the first variant: the call still returns.
        http.fail_next(&CoverVariant::Portrait2x.url(570).unwrap(), 1);
        let result = service.ensure(570).await;
        assert!(matches!(
            result,
            CoverResult::Missing(CoverError::Transient(_))
        ));

        // All absent: the call still returns.
        let dir2 = tempfile::tempdir().unwrap();
        let http2 = Arc::new(FakeHttp::new());
        let service2 = make_service(http2.clone(), dir2.path());
        for variant in CoverVariant::CDN {
            http2.remove(&variant.url(1).unwrap());
        }
        let result = service2.ensure(1).await;
        assert!(matches!(result, CoverResult::Missing(CoverError::NoAsset)));
    }

    #[tokio::test]
    async fn oversized_art_is_downscaled_before_upload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.jpg");
        tokio::fs::write(&path, jpeg_bytes(3840, 1240))
            .await
            .unwrap();

        let (bytes, w, h) = load_texture_bytes(&path).unwrap();
        assert!(w <= MAX_TEXTURE_EDGE && h <= MAX_TEXTURE_EDGE);
        assert_eq!(bytes.len(), (w * h * 4) as usize);
    }

    #[test]
    fn fit_within_preserves_aspect() {
        assert_eq!(fit_within((3840, 1240), 1024), (1024, 331));
        assert_eq!(fit_within((300, 450), 1024), (300, 450));
        assert_eq!(fit_within((0, 0), 1024), (0, 0));
        // The poster slot is 250x375 logical px, so 500x750 is the 2x target.
        assert_eq!(fit_within((600, 900), 750), (500, 750));
        assert_eq!(fit_within((1920, 620), 750), (750, 242));
    }

    #[tokio::test]
    async fn obsolete_cache_files_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let obsolete = dir.path().join("570_hero_capsule.jpg");
        tokio::fs::write(&obsolete, jpeg_bytes(374, 448))
            .await
            .unwrap();
        let keep = dir.path().join(CoverVariant::Portrait.cache_file(570));
        tokio::fs::write(&keep, jpeg_bytes(300, 450)).await.unwrap();

        remove_obsolete_files(dir.path(), 570).await;

        assert!(!obsolete.exists(), "obsolete file must be removed");
        assert!(keep.exists(), "current file must be kept");
    }

    /// A 304 with no usable file on disk must not be recorded as "absent":
    /// the server says the asset exists, so blacklisting it for a week would
    /// be wrong.
    #[tokio::test]
    async fn a_304_without_a_cached_file_never_becomes_absent() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        // A record that claims the asset is present, but no file exists and
        // the server keeps answering 304.
        let state = CoverState {
            version: STATE_VERSION,
            appid: 570,
            variants: HashMap::from([(
                CoverVariant::Portrait2x.key().to_string(),
                VariantState::Present {
                    etag: Some("\"v1\"".to_string()),
                    last_modified: Some("Mon, 10 Feb 2025 17:57:16 GMT".to_string()),
                    checked_at: 0,
                    bytes: 1234,
                },
            )]),
        };
        tokio::fs::write(
            dir.path().join("570_cover_state.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .await
        .unwrap();
        http.always_not_modified(&url);

        let result = service.ensure(570).await;
        assert!(
            matches!(result, CoverResult::Missing(CoverError::Transient(_))),
            "a 304 without a file is a transient problem, not a missing asset"
        );

        // The record must not have been flipped to "absent".
        let raw = tokio::fs::read(dir.path().join("570_cover_state.json"))
            .await
            .unwrap();
        let state: CoverState = serde_json::from_slice(&raw).unwrap();
        assert!(
            !matches!(
                state.get(CoverVariant::Portrait2x),
                Some(VariantState::Absent { .. })
            ),
            "a 304 must never blacklist the asset"
        );
    }

    /// A transient failure must not blank a game whose art is already
    /// cached: the cached copy is served instead.
    #[tokio::test]
    async fn offline_with_a_stale_cache_serves_the_cached_file() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        // The art was downloaded once, then the record went stale.
        http.publish(&url, jpeg_bytes(600, 900), Some("\"v1\""));
        service.ensure(570).await;
        let path = dir.path().join(CoverVariant::Portrait2x.cache_file(570));
        assert!(path.exists());
        age_state(dir.path(), 570, PRESENT_TTL.as_secs() + 1).await;

        // Now the network is down.
        http.fail_next(&url, 1);

        let result = service.ensure(570).await;
        match result {
            CoverResult::Found(art) => {
                assert_eq!(art.variant, CoverVariant::Portrait2x);
                assert!(art.path.exists());
            }
            other => panic!("expected the cached art, got {other:?}"),
        }
    }

    /// The same, for a game that only has landscape art.
    #[tokio::test]
    async fn offline_with_a_stale_cache_serves_a_banner_only_app() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());

        // No portrait art exists; the banner does.
        for variant in [CoverVariant::Portrait2x, CoverVariant::Portrait] {
            http.remove(&variant.url(570).unwrap());
        }
        let banner = CoverVariant::Banner.url(570).unwrap();
        http.publish(&banner, jpeg_bytes(460, 215), Some("\"v1\""));
        service.ensure(570).await;
        age_state(dir.path(), 570, PRESENT_TTL.as_secs() + 1).await;

        // The network is down for the banner too.
        http.fail_next(&banner, 1);

        let result = service.ensure(570).await;
        match result {
            CoverResult::Found(art) => {
                assert_eq!(art.variant, CoverVariant::Banner);
                assert!(art.path.exists());
            }
            other => panic!("expected the cached banner, got {other:?}"),
        }
    }

    /// A record that claims the asset is present but whose file was deleted
    /// must be refetched, not treated as a 304 with nothing to show.
    #[tokio::test]
    async fn a_deleted_file_with_a_matching_etag_is_refetched() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        http.publish(&url, jpeg_bytes(600, 900), Some("\"v1\""));
        service.ensure(570).await;
        let path = dir.path().join(CoverVariant::Portrait2x.cache_file(570));
        assert!(path.exists());

        // The file is deleted but the record still carries the ETag.
        std::fs::remove_file(&path).unwrap();
        age_state(dir.path(), 570, PRESENT_TTL.as_secs() + 1).await;

        let result = service.ensure(570).await;
        assert!(matches!(result, CoverResult::Found(_)));
        assert!(
            path.exists(),
            "the deleted file must be downloaded again, not left missing"
        );
        assert_eq!(image_size(&path).await, Some((600, 900)));
    }

    /// A 200 whose body is not an image (an HTML error page) must not
    /// blacklist the asset: the next attempt has to succeed.
    #[tokio::test]
    async fn an_html_body_then_real_art_succeeds_without_a_blackout() {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::new());
        let service = make_service(http.clone(), dir.path());
        let url = CoverVariant::Portrait2x.url(570).unwrap();

        // The CDN answers 200 with an HTML error page.
        http.publish_garbage(&url);

        let result = service.ensure(570).await;
        assert!(
            matches!(result, CoverResult::Missing(CoverError::Transient(_))),
            "an undecodable body is a transient failure, not a missing asset"
        );

        // The state must not record it as absent.
        let raw = tokio::fs::read(dir.path().join("570_cover_state.json"))
            .await
            .unwrap();
        let state: CoverState = serde_json::from_slice(&raw).unwrap();
        assert!(
            !matches!(
                state.get(CoverVariant::Portrait2x),
                Some(VariantState::Absent { .. })
            ),
            "an undecodable body must not be persisted as absent"
        );

        // The CDN recovers. The backoff lives in memory only, so a new
        // service on the same state (as after a restart) must succeed
        // without anything being cleared.
        http.publish(&url, jpeg_bytes(600, 900), Some("\"v2\""));
        let service = make_service(http.clone(), dir.path());

        let result = service.ensure(570).await;
        assert!(
            matches!(result, CoverResult::Found(_)),
            "the retry must succeed"
        );
        let path = dir.path().join(CoverVariant::Portrait2x.cache_file(570));
        assert_eq!(image_size(&path).await, Some((600, 900)));
    }

    /// The UI retries sooner after a transient failure than after a
    /// definitive answer, so one flaky request does not blank a game for a
    /// day.
    #[test]
    fn a_transient_error_is_retried_sooner_than_a_definitive_one() {
        let transient = CoverResult::Missing(CoverError::Transient("timeout".into()));
        let definitive = CoverResult::Missing(CoverError::NoAsset);
        let found = CoverResult::Found(CoverArt {
            variant: CoverVariant::Portrait2x,
            path: PathBuf::from("/tmp/x.jpg"),
            size: (600, 900),
        });

        assert!(retry_after(&transient) < retry_after(&definitive));
        assert!(retry_after(&transient) < COVER_RECHECK_INTERVAL);
        assert_eq!(retry_after(&definitive), COVER_RECHECK_INTERVAL);
        assert_eq!(retry_after(&found), COVER_RECHECK_INTERVAL);
    }

    /// Age every record of `appid` by `seconds` so it becomes stale.
    async fn age_state(dir: &Path, appid: u32, seconds: u64) {
        let path = dir.join(format!("{appid}_cover_state.json"));
        let raw = tokio::fs::read(&path).await.unwrap();
        let mut state: CoverState = serde_json::from_slice(&raw).unwrap();
        for record in state.variants.values_mut() {
            match record {
                VariantState::Present { checked_at, .. } => {
                    *checked_at = checked_at.saturating_sub(seconds)
                }
                VariantState::Absent { checked_at } => {
                    *checked_at = checked_at.saturating_sub(seconds)
                }
            }
        }
        tokio::fs::write(&path, serde_json::to_vec(&state).unwrap())
            .await
            .unwrap();
    }
}
