//! Opening a URL in the user's browser.

/// Tries to open `url`. Returns whether a browser was launched; the caller has already printed
/// the URL, so a failure only means the user copies it by hand.
pub fn open(url: &str) -> bool {
    match webbrowser::open(url) {
        Ok(()) => true,
        Err(err) => {
            tracing::debug!(%err, "could not open a browser");
            false
        }
    }
}
