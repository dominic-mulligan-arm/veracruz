//! The Linux root envlave server.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for copyright
//! and licensing information.

use clap::{App, Arg};
use env_logger;
use err_derive::Error;
use log::{error, info};
use std::{process::exit, str::FromStr};
use url::Url;

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The default URL of the Veracruz proxy attestation server.
const DEFAULT_PROXY_ATTESTATION_SERVER_URL: &'static str = "https://localhost:8080";

////////////////////////////////////////////////////////////////////////////////
// Errors.
////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, Error, Eq, Hash, Ord, PartialOrd, PartialEq)]
enum LinuxRootEnclaveServerError {
    #[error(display = "A command line argument was not correctly formed and could not be parsed.")]
    /// A command line argument was not correctly formed and could not be parsed.
    CommandLineParsingError,
}

////////////////////////////////////////////////////////////////////////////////
// Command-line parsing.
////////////////////////////////////////////////////////////////////////////////

/// Struct capturing the command line arguments passed to the utility.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CommandLineConfiguration {
    /// URL of the proxy attestation server.
    proxy_attestation_server_url: Url,
    /// Optional number of attempts to retry a failed sent message.  Here,
    /// `None` denotes no upper bound on the number of connection attempts.
    max_retry_attempts: Option<u64>,
}

impl CommandLineConfiguration {
    /// Creates a new `CommandLineConfiguration` with the proxy attestation
    /// server's URL set to `localhost` and no maximum retry attempts set.
    #[inline]
    pub fn new() -> Self {
        Self {
            proxy_attestation_server_url: Url::parse(DEFAULT_PROXY_ATTESTATION_SERVER_URL)
                .expect("Internal invariant failed: parsing of localhost URL failed."),
            max_retry_attempts: None,
        }
    }

    /// Returns the maximum number of retry attempts to make when trying to
    /// establish a connection with an external service.
    #[inline]
    pub fn max_retry_attempts(&self) -> Option<&u64> {
        self.max_retry_attempts.as_ref()
    }

    /// Returns the URL of the proxy attestation service.
    #[inline]
    pub fn proxy_attestation_server_url(&self) -> &Url {
        &self.proxy_attestation_server_url
    }

    /// Sets the maximum number of retry attempts to make when trying to
    /// establish a connection with an external service to `attempts`.
    #[inline]
    pub fn set_max_retry_attempts<T>(&mut self, attempts: T) -> &mut Self
    where
        T: Into<u64>,
    {
        self.max_retry_attempts = Some(attempts.into());
        self
    }

    /// Sets the URL of the proxy attestation service to `url`.
    #[inline]
    pub fn set_proxy_attestation_server_url<T>(&mut self, url: T) -> &mut Self
    where
        T: Into<Url>,
    {
        self.proxy_attestation_server_url = url.into();
        self
    }
}

////////////////////////////////////////////////////////////////////////////////
// Attestation.
////////////////////////////////////////////////////////////////////////////////

fn perform_native_attestation(
    configuration: &CommandLineConfiguration,
) -> Result<(), LinuxRootEnclaveServerError> {
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////
// Entry point.
////////////////////////////////////////////////////////////////////////////////

fn entry_point() -> Result<(), LinuxRootEnclaveServerError> {
    let app = App::new("linux-root-enclave-server")
        .arg(
            Arg::new("proxy-attestation-server-url")
                .short('u')
                .about("The URL of the Veracruz proxy attestation server.")
                .default_missing_value(DEFAULT_PROXY_ATTESTATION_SERVER_URL),
        )
        .arg(
            Arg::new("max-retry-attempts")
                .short('r')
                .about(
                    "The maximum number of retry attempts when trying to contact an external service (infinite if no limit supplied).",
                ),
        );

    let matches = app.get_matches();
    let mut configuration = CommandLineConfiguration::new();

    if let Some(url) = matches.value_of("proxy-attestation-server-url") {
        let url = Url::parse(url).map_err(|_e| {
            error!("Failed to parse Veracruz proxy attestation server URL.");
            LinuxRootEnclaveServerError::CommandLineParsingError
        })?;

        configuration.set_proxy_attestation_server_url(url);
    } else {
        info!(
            "No proxy attestation server URL provided.  Using default: {}.",
            DEFAULT_PROXY_ATTESTATION_SERVER_URL
        );
    }

    if let Some(max_retries) = matches.value_of("max-retry-attempts") {
        let retries = u64::from_str(max_retries).map_err(|_e| {
            error!("Failed to parse maximum retry attempts.");
            LinuxRootEnclaveServerError::CommandLineParsingError
        })?;

        configuration.set_max_retry_attempts(retries);
    } else {
        info!("No maximum retry number supplied.  Using infinite retries.");
    }

    let enclave = perform_native_attestation(&configuration)?;

    Ok(())
}

fn main() {
    env_logger::init();

    entry_point().map_err(|e| {
        eprintln!("Error: {}.", e);
        exit(-1);
    });
}
