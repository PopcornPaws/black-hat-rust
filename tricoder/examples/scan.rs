use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use structopt::StructOpt;
use tricoder::Subdomain;

use std::time::Duration;

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(long, short = "t")]
    target: String,
}

fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    let client = Client::builder()
        .redirect(Policy::limited(4))
        .timeout(Duration::from_secs(10))
        .build()?;

    let pool = rayon::ThreadPoolBuilder::new().num_threads(8).build()?;

    pool.install(|| {
        let mut subdomains = Subdomain::enumerate(&client, &opt.target).unwrap();
        subdomains.par_iter_mut().for_each(Subdomain::scan_ports);

        for subdomain in subdomains {
            println!("{}:", subdomain.domain());
            for port in subdomain.open_ports() {
                println!("{}", port.port())
            }
            println!();
        }
    });
    Ok(())
}
