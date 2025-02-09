mod common;

use std::sync::Arc;

use boa_engine::{Context, Source};
use boa_parser::Error as BoaParserError;
use clap::Parser;
use common::COMMON_STRINGS;
use reqwest_spooftls::{Client, Error as HttpError, Fingerprint};
use scraper::{Html, Selector};
use tokio::{fs, task::JoinSet};
use url::Url;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The supplied URL that will be sifted
    #[arg(short, long)]
    url: Url,

    /// Spoof TLS handshake to behave like a browser
    #[arg(short, long)]
    spoof: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let sifter = Sifter::new(args.spoof);

    let create_dir = fs::create_dir_all(format!("./{}", args.url.domain().unwrap())).await;
    if let Err(err) = create_dir {
        println!(
            "{} | failed to create directory: {}",
            args.url.domain().unwrap(),
            err
        );
        return;
    }

    match sifter.sift(&args.url).await {
        Ok(mut join_set) => {
            while let Some(task) = join_set.join_next().await {
                let (url, sifted) = task.unwrap();

                match sifted {
                    Ok(sifted) => {
                        if !sifted.is_empty() {
                            let write_file = fs::write(
                                format!(
                                    "./{}/{}.txt",
                                    args.url.domain().unwrap(),
                                    url.path_segments().unwrap().last().unwrap()
                                ),
                                sifted.join("\n"),
                            )
                            .await;

                            match write_file {
                                Ok(_) => {
                                    println!("{} | {} strings found", url.as_str(), sifted.len());
                                }
                                Err(err) => {
                                    println!("{} | failed to write file: {}", url.as_str(), err)
                                }
                            }
                        }
                    }
                    Err(SiftJSError::Http(http)) => {
                        println!(
                            "{} | failed http request {}",
                            url.as_str(),
                            http.status()
                                .map(|s| s.to_string())
                                .unwrap_or("unknown".to_string())
                        );
                    }
                    Err(SiftJSError::JavaScript(parser)) => {
                        println!("{} | failed to parse javascript {}", url.as_str(), parser);
                    }
                }
            }
        }
        Err(SiftError::Http(http)) => {
            println!(
                "{} | failed http request {}",
                args.url.as_str(),
                http.status()
                    .map(|s| s.to_string())
                    .unwrap_or("unknown".to_string())
            );
        }
    }
}

struct Sifter {
    http_client: Client,
}

enum SiftError {
    Http(HttpError),
}

enum SiftJSError {
    Http(HttpError),
    JavaScript(BoaParserError),
}

impl Sifter {
    fn new(spoof: bool) -> Arc<Self> {
        let http_client = {
            let client = Client::builder();

            if spoof {
                client.use_fingerprint(Fingerprint::Chrome131)
            } else {
                client
            }
        }
        .build()
        .unwrap();

        Arc::new(Self { http_client })
    }

    async fn sift(
        self: &Arc<Self>,
        url: &Url,
    ) -> Result<JoinSet<(Url, Result<Vec<String>, SiftJSError>)>, SiftError> {
        let res = self
            .http_client
            .get(url.as_str())
            .send()
            .await
            .map_err(|err| SiftError::Http(err))?
            .text()
            .await
            .map_err(|err| SiftError::Http(err))?;

        let parsed_html = Html::parse_document(&res);

        let js_urls = parsed_html
            .root_element()
            .select(&Selector::parse("script").unwrap())
            .filter_map(|e| e.attr("src").map(|src| url.clone().join(src).unwrap()))
            .collect::<Vec<_>>();

        let mut set = JoinSet::new();
        for url in js_urls {
            set.spawn({
                let sifter = self.clone();

                async move {
                    let sifted = sifter.sift_js_url(&url.clone()).await;
                    (url, sifted)
                }
            });
        }

        Ok(set)
    }

    async fn sift_js_url(self: &Arc<Self>, url: &Url) -> Result<Vec<String>, SiftJSError> {
        let res = self
            .http_client
            .get(url.as_str())
            .send()
            .await
            .map_err(|err| SiftJSError::Http(err))?
            .text()
            .await
            .map_err(|err| SiftJSError::Http(err))?;

        let mut parser = boa_parser::Parser::new(Source::from_bytes(&res));
        let mut ctx = Context::default();

        parser
            .parse_eval(true, ctx.interner_mut())
            .map_err(|err| SiftJSError::JavaScript(err))?;

        Ok(ctx
            .interner()
            .resolve_all()
            .iter()
            .filter_map(|s| {
                let string = s.to_string();

                if string.is_empty() || COMMON_STRINGS.contains(string.as_str()) {
                    None
                } else {
                    Some(string.replace('\n', ""))
                }
            })
            .collect::<Vec<_>>())
    }
}
