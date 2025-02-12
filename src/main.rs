mod caesar;
mod cipher;
mod enigma;
mod polyalphabetic;

use clap::{Arg, Command};

fn main() -> std::io::Result<()> {
    let matches = Command::new("cipher")
        .version("0.1.0")
        .about("A simple cipher tool")
        .subcommand(
            Command::new("caesar")
                .about("Caesar cipher")
                .arg(Arg::new("input").short('i').long("input").required(true))
                .arg(Arg::new("output").short('o').long("output").required(true))
                .arg(
                    Arg::new("shift")
                        .short('s')
                        .long("shift")
                        .default_value("3")
                        .value_parser(clap::value_parser!(i32)),
                ),
        )
        .subcommand(
            Command::new("poly")
                .about("Polyalphabetic cipher")
                .arg(Arg::new("input").short('i').long("input").required(true))
                .arg(Arg::new("output").short('o').long("output").required(true))
                .arg(
                    Arg::new("keyword")
                        .short('k')
                        .long("keyword")
                        .required(true),
                )
                .arg(
                    Arg::new("decrypt")
                        .short('d')
                        .long("decrypt")
                        .action(clap::ArgAction::SetFalse),
                ),
        )
        .subcommand(
            Command::new("enigma")
                .about("Enigma cipher")
                .arg(Arg::new("input").short('i').long("input").required(true))
                .arg(Arg::new("output").short('o').long("output").required(true))
                .arg(
                    Arg::new("reflector_file")
                        .long("reflector_file")
                        .default_value("reflector.txt"),
                )
                .arg(
                    Arg::new("rotor_num")
                        .short('n')
                        .long("rotor_num")
                        .default_value("3"),
                )
                .arg(
                    Arg::new("passwords_file")
                        .long("passwords_file")
                        .default_value("passwords.txt"),
                )
                .arg(
                    Arg::new("rotors_cursor_file")
                        .long("rotors_cursor_file")
                        .default_value("rotors_cursor.txt"),
                )
                .arg(
                    Arg::new("plugboard_file")
                        .long("plugboard_file")
                        .default_value("plugboard.txt"),
                )
                .arg(
                    Arg::new("reflector_from")
                        .short('r')
                        .long("reflector_from")
                        .default_value("M"),
                )
                .arg(
                    Arg::new("rotors_from")
                        .long("rotors_from")
                        .default_value("M"),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("caesar", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
            let output = sub_matches.get_one::<String>("output").unwrap();
            let shift = *sub_matches.get_one::<i32>("shift").unwrap();
            let mut cipher =
                caesar::CaesarCipher::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ", input, output, shift);
            cipher.encrypt()
        }
        Some(("poly", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
            let output = sub_matches.get_one::<String>("output").unwrap();
            let keyword = sub_matches.get_one::<String>("keyword").unwrap();
            let decrypt = sub_matches.get_flag("decrypt");
            let mut cipher = polyalphabetic::PolyalphabeticCipher::new(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                input,
                output,
                keyword,
                decrypt,
            );
            cipher.encrypt()
        }
        Some(("enigma", sub_matches)) => {
            let input = sub_matches.get_one::<String>("input").unwrap();
            let output = sub_matches.get_one::<String>("output").unwrap();
            let reflector_from = sub_matches.get_one::<String>("reflector_from").unwrap();
            let reflector_file = sub_matches.get_one::<String>("reflector_file").unwrap();
            let rotor_num: usize = sub_matches
                .get_one::<String>("rotor_num")
                .unwrap()
                .parse()
                .unwrap();
            let rotors_from = sub_matches.get_one::<String>("rotors_from").unwrap();
            let passwords_file = sub_matches.get_one::<String>("passwords_file").unwrap();
            let rotors_cursor_file = sub_matches.get_one::<String>("rotors_cursor_file").unwrap();
            let plugboard_file = sub_matches.get_one::<String>("plugboard_file").unwrap();

            let mut enigma = enigma::EnigmaMachine::new(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                input,
                output,
                reflector_file,
                rotor_num,
                passwords_file,
                rotors_cursor_file,
                plugboard_file,
                reflector_from,
                rotors_from,
            );
            enigma.encrypt()
        }
        _ => unreachable!("Exhausted list of subcommands"),
    }
}
