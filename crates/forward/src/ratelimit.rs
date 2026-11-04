use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use url::Url;

const MAX_OPENS_PER_WINDOW: usize = 3;
const MAX_TRACKED_OPENS: usize = 64;
const OPEN_WINDOW: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
pub enum OpenDecision {
    Permit,
    Drop { count: usize },
}

struct OpenedUrl {
    url: String,
    opened_at: Instant,
    origin: Option<IpAddr>,
}

pub struct RecentOpens {
    entries: VecDeque<OpenedUrl>,
}

impl RecentOpens {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_TRACKED_OPENS),
        }
    }

    pub fn record(&mut self, url: &Url, now: Instant, origin: Option<IpAddr>) -> OpenDecision {
        self.entries
            .retain(|entry| now.duration_since(entry.opened_at) < OPEN_WINDOW);
        let count = self
            .entries
            .iter()
            .filter(|entry| entry.origin == origin && entry.url == url.as_str())
            .count()
            + 1;
        if count > MAX_OPENS_PER_WINDOW {
            return OpenDecision::Drop { count };
        }
        if self.entries.len() == MAX_TRACKED_OPENS {
            self.entries.pop_front();
        }
        self.entries.push_back(OpenedUrl {
            url: url.as_str().to_owned(),
            opened_at: now,
            origin,
        });
        OpenDecision::Permit
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use url::Url;

    use super::{OpenDecision, RecentOpens};

    #[test]
    fn drops_fourth_open_for_same_url_within_window() {
        // Given: a recent-open guard and one URL.
        let mut guard = RecentOpens::new();
        let url = Url::parse("https://example.com/redirect").unwrap();
        let now = Instant::now();

        // When: the URL is opened a fourth time inside two seconds.
        for _ in 0..3 {
            assert_eq!(guard.record(&url, now, None), OpenDecision::Permit);
        }

        // Then: the fourth open is rejected with its occurrence count.
        assert_eq!(
            guard.record(&url, now, None),
            OpenDecision::Drop { count: 4 }
        );
    }

    #[test]
    fn limits_distinct_urls_to_fixed_capacity() {
        // Given: a recent-open guard receiving many distinct URLs.
        let mut guard = RecentOpens::new();
        let now = Instant::now();

        // When: more URLs arrive than the guard can retain.
        for index in 0..65 {
            let url = Url::parse(&format!("https://{index}.example.com/")).unwrap();
            assert_eq!(guard.record(&url, now, None), OpenDecision::Permit);
        }

        // Then: only the fixed recent-open capacity remains in memory.
        assert_eq!(guard.entries.len(), 64);
        assert_eq!(
            guard.record(
                &Url::parse("https://example.com/redirect").unwrap(),
                now + Duration::from_secs(2),
                None,
            ),
            OpenDecision::Permit
        );
    }

    #[test]
    fn one_peer_cannot_suppress_another_peers_open_of_the_same_url() {
        let mut guard = RecentOpens::new();
        let url = Url::parse("https://auth.example/login").unwrap();
        let now = Instant::now();
        let a = Some("100.64.0.2".parse().unwrap());
        let b = Some("100.64.0.3".parse().unwrap());
        for _ in 0..3 {
            assert_eq!(guard.record(&url, now, a), OpenDecision::Permit);
        }
        assert_eq!(guard.record(&url, now, a), OpenDecision::Drop { count: 4 });
        assert_eq!(guard.record(&url, now, b), OpenDecision::Permit);
    }
}
