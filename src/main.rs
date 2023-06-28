mod network;
use network::{get_local_ips, ipstr_starts_with};

mod connection;
use connection::{cread, cwrite};

mod db;
use db::{connect_to_db};

use clap::{Arg, Command, ArgAction};
use std::time::{SystemTime, UNIX_EPOCH};
use mongodb::{error::Error};

fn unix_timestamp() -> u64 {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    since_epoch.as_secs()
}

#[tokio::main]
async fn main() -> Result<(), Error> {

    let args = Command::new("ParaView Server Cluster")
        .version("1.0")
        .author("Johannes Blaschke")
        .about("Manages a cluster of ParaView Servers")
        .arg(
            Arg::new("operation")
            .short('o')
            .long("operation")
            .value_name("OPERATION")
            .help("Operation to be performed")
            .num_args(1)
            .required(true)
            .value_parser(["list_interfaces", "list_ips", "listen", "claim"])
        )
        .arg(
            Arg::new("interface_name")
            .short('n')
            .long("name")
            .value_name("NAME")
            .help("Interface Name")
            .num_args(1)
            .required(false)
        )
        .arg(
            Arg::new("ip_start")
            .short('i')
            .long("ip-start")
            .value_name("STARTING OCTETS")
            .help("Only return ip addresses whose starting octets match these.")
            .num_args(1)
            .required(false)
        )
        .arg(
            Arg::new("ip_version")
            .long("ip-version")
            .value_name("IP VERSION")
            .help("Output results only matching this IP version")
            .num_args(1)
            .required(false)
            .value_parser(clap::value_parser!(i32))
        )
        .arg(
            Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Don't output headers")
            .num_args(0)
            .required(false)
            .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("host")
            .long("host")
            .value_name("HOST")
            .help("Host to bind to")
            .num_args(1)
            .required(false)
        )
        .arg(
            Arg::new("port")
            .long("port")
            .value_name("PORT")
            .help("Port to bind server and client to.")
            .num_args(1)
            .required(false)
            .value_parser(clap::value_parser!(i32))
        )
        .arg(
            Arg::new("db_host")
            .long("db-host")
            .value_name("DATABSE HOST")
            .help("Database Host Address")
            .num_args(1)
            .required(false)
        )
        .arg(
            Arg::new("db_port")
            .long("db-port")
            .value_name("PORT")
            .help("Port to bind to on database server")
            .num_args(1)
            .required(false)
            .value_parser(clap::value_parser!(i32))
        )
        .arg(
            Arg::new("db_user")
            .long("db-user")
            .value_name("DATABSE USER")
            .help("Username for database server")
            .num_args(1)
            .required(false)
        )
        .arg(
            Arg::new("db_password")
            .long("db-password")
            .value_name("PASSWORD")
            .help("Password for database")
            .num_args(1)
            .required(false)
        )
        .arg(
            Arg::new("db_name")
            .long("db-name")
            .value_name("NAME")
            .help("Name of database")
            .num_args(1)
            .required(false)
        )
        .get_matches();

    let ips = get_local_ips();

    let ip_version =   args.get_one::<i32>("ip_version");
    let verbose    = * args.get_one::<bool>("verbose").unwrap();
    let mut print_v4 = false;
    let mut print_v6 = false;
    if ip_version.is_some() {
        match * ip_version.unwrap() {
            4 => print_v4 = true,
            6 => print_v6 = true,
            _ => panic!(
                "Please specify IP version 4 or 6, or ommit `--ip-version` for both."
            )
        }
    } else {
        print_v4 = true;
        print_v6 = true;
    }

    let operation = args.get_one::<String>("operation").unwrap();
    match operation.as_str() {
        "list_interfaces" => {
            let mut ipv4_names = Vec::new();
            let mut ipv6_names = Vec::new();

            if print_v4 {
                if verbose {println!("IPv4 Interfaces:");}
                for ip in ips.ipv4_addrs {
                    let name: & String = & ip.name.unwrap_or_default();
                    if ! ipv4_names.contains(name) {
                        if verbose {
                            println!(" - {}", name);
                        } else {
                            println!("{}", name);
                        }
                        ipv4_names.push(name.to_string());
                    }
                }
            }

            if print_v6 {
                if verbose {println!("IPv6 Interfaces:");}
                for ip in ips.ipv6_addrs {
                    let name: & String = & ip.name.unwrap_or_default();
                    if ! ipv6_names.contains(name) {
                        if verbose {
                            println!(" - {}", name);
                        } else {
                            println!("{}", name);
                        }
                        ipv6_names.push(name.to_string());
                    }
                }
            }
        }

        "list_ips" => {
            assert!(args.contains_id("interface_name"));
            let name = args.get_one::<String>("interface_name").unwrap().as_str();
            let starting_octets = args.get_one::<String>("ip_start");

            if print_v4 {
                if verbose {println!("IPv4 Addresses for {}:", name);}
                for ip in ips.ipv4_addrs {
                    if name == ip.name.unwrap_or_default() {
                        if ! ipstr_starts_with(& ip.ip, & starting_octets){
                            continue;
                        }
                        if verbose {
                            println!(" - {}", ip.ip);
                        } else {
                            println!("{}", ip.ip);
                        }
                    }
                }
            }

            if print_v6 {
                if verbose {println!("IPv6 Addresses for {}:", name);}
                for ip in ips.ipv6_addrs {
                    if name == ip.name.unwrap_or_default() {
                        if ! ipstr_starts_with(& ip.ip, & starting_octets){
                            continue;
                        }
                        if verbose {
                            println!(" - {}", ip.ip);
                        } else {
                            println!("{}", ip.ip);
                        }
                    }
                }
            }
        }

        "listen" => {
            assert!(args.contains_id("host"));
            assert!(args.contains_id("port"));
            assert!(args.contains_id("db_host"));
            assert!(args.contains_id("db_port"));
            assert!(args.contains_id("db_user"));
            assert!(args.contains_id("db_password"));
            assert!(args.contains_id("db_name"));

            let host =   args.get_one::<String>("host").unwrap().as_str();
            let port = * args.get_one::<i32>("port").unwrap();

            let db_host =   args.get_one::<String>("db_host").unwrap().as_str();
            let db_port = * args.get_one::<i32>("db_port").unwrap();
            let db_user =   args.get_one::<String>("db_user").unwrap().as_str();
            let db_password = args.get_one::<String>("db_password").unwrap().as_str();
            let db_name =   args.get_one::<String>("db_name").unwrap().as_str();

            let db = connect_to_db(
                db_user, db_password, db_host, db_port, db_name
            ).await?;
            let coll = db.collection::<Item>(db_name);

            println!("Listening for clients...");
            let rec = cread(host, port)?;
            println!("REC: {:?}", rec);
        }

        "claim" => {
            assert!(args.contains_id("host"));
            assert!(args.contains_id("port"));

            let host =   args.get_one::<String>("host").unwrap().as_str();
            let port = * args.get_one::<i32>("port").unwrap();

            let _rec = cwrite(
                host, port, & String::from(format!("{}", unix_timestamp()))
            );
        }

        &_ => todo!()
    }

    Ok(())
}
