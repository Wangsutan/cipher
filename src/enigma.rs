use crate::cipher::Cipher;
use rand::rng;
use rand::seq::SliceRandom;
use serde_json;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};

#[derive(Clone)]
struct Rotor {
    order: Vec<usize>,
    cursor: usize,
}

impl Rotor {
    fn new(order: Vec<usize>, cursor: usize) -> Self {
        Rotor { order, cursor }
    }

    fn generate_order(&mut self, alphabet: &str) -> () {
        self.order = (1..alphabet.len()).collect::<Vec<usize>>();
        self.order.shuffle(&mut rng());
    }

    fn set_order(&mut self, order_vec: Vec<usize>) {
        self.order = order_vec;
    }

    fn generate_cursor(&mut self) -> () {
        let right_edge_of_order = self.order.len();
        use rand::Rng;
        self.cursor = rand::rng().random_range(0..right_edge_of_order);
    }

    fn set_cursor(&mut self, cursor: usize) -> Result<(), String> {
        let right_edge_of_order = self.order.len();
        if cursor < right_edge_of_order {
            self.cursor = cursor;
            Ok(())
        } else {
            Err("Invalid cursor".to_string())
        }
    }

    fn step(&mut self) {
        self.cursor = (self.cursor + 1) % self.order.len();
    }
}

pub struct EnigmaMachine {
    base: Cipher,
    rotors: Vec<Rotor>,
    reflector: HashMap<char, char>,
    plugboard: HashMap<char, char>,
}

impl EnigmaMachine {
    pub fn new(
        alphabet: &str,
        input_file: &str,
        output_file: &str,
        reflector_file: &str,
        rotor_num: usize,
        passwords_file: &str,
        rotors_cursor_file: &str,
        plugboard_file: &str,
        reflector_from: &str,
        rotors_from: &str,
    ) -> Self {
        let mut enigma = EnigmaMachine {
            base: Cipher::new(alphabet, input_file, output_file),
            rotors: vec![Rotor::new(vec![], 0); rotor_num],
            reflector: HashMap::new(),
            plugboard: HashMap::new(),
        };

        enigma.set_reflector(reflector_from, alphabet, reflector_file);
        enigma.set_rotors(rotor_num, passwords_file, rotors_cursor_file, rotors_from);
        enigma.set_plugboard(plugboard_file);

        enigma
    }

    fn set_reflector(&mut self, reflector_from: &str, alphabet: &str, reflector_file: &str) {
        if reflector_from == "m" {
            self.create_reflector(alphabet, reflector_file);
        } else {
            self.load_reflector(reflector_file);
        }
    }

    fn create_reflector(&mut self, alphabet: &str, reflector_file: &str) {
        let mut plugs: Vec<char> = alphabet.chars().collect();
        plugs.shuffle(&mut rng());

        let num = plugs.len() / 2;
        let dict1: HashMap<char, char> = plugs[..num]
            .iter()
            .cloned()
            .zip(plugs[num..].iter().cloned())
            .collect();
        let dict2: HashMap<char, char> = plugs[num..]
            .iter()
            .cloned()
            .zip(plugs[..num].iter().cloned())
            .collect();

        self.reflector = dict1.into_iter().chain(dict2.into_iter()).collect();

        let reflector_str =
            serde_json::to_string(&self.reflector).expect("Failed to serialize reflector");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(reflector_file)
            .expect("Failed to open reflector file for writing");
        file.write_all(reflector_str.as_bytes())
            .expect("Failed to write reflector to file");
    }

    fn load_reflector(&mut self, reflector_file: &str) {
        let file = File::open(reflector_file).expect("Failed to open reflector file");
        let reader = BufReader::new(file);

        let reflector_str = reader
            .lines()
            .next()
            .expect("Failed to read reflector file")
            .expect("Failed to read line");
        if let Ok(reflector_map) = serde_json::from_str::<HashMap<char, char>>(&reflector_str) {
            for (key, value) in reflector_map {
                self.reflector.insert(key, value);
            }
        } else {
            eprintln!("Invalid reflector format in file");
        }
    }

    fn set_rotors(
        &mut self,
        rotor_num: usize,
        passwords_file: &str,
        rotors_cursor_file: &str,
        rotors_from: &str,
    ) {
        if rotors_from == "m" {
            self.generate_rotors(passwords_file, rotors_cursor_file);
        } else {
            self.load_rotors(rotor_num, passwords_file, rotors_cursor_file);
        }
    }

    fn generate_rotors(&mut self, passwords_file: &str, rotors_cursor_file: &str) {
        for rotor in &mut self.rotors {
            rotor.generate_order(&self.base.alphabet);
            rotor.generate_cursor();
        }

        let mut passwords_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(passwords_file)
            .expect("Failed to open passwords file for writing");
        let mut rotors_cursor_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(rotors_cursor_file)
            .expect("Failed to open rotors cursor file for writing");

        for rotor in &self.rotors {
            let order_str = serde_json::to_string(&rotor.order).expect("Failed to serialize order");
            passwords_file
                .write_all(format!("{}\n", order_str).as_bytes())
                .expect("Failed to write order to file");
            rotors_cursor_file
                .write_all(format!("{}\n", rotor.cursor).as_bytes())
                .expect("Failed to write cursor to file");
        }
    }

    fn load_rotors(&mut self, rotor_num: usize, passwords_file: &str, rotors_cursor_file: &str) {
        let passwords_file = File::open(passwords_file).expect("Failed to open passwords file");
        let rotors_cursor_file =
            File::open(rotors_cursor_file).expect("Failed to open rotors cursor file");

        let passwords_reader = BufReader::new(passwords_file);
        let cursors_reader = BufReader::new(rotors_cursor_file);

        let passwords: Vec<Vec<usize>> = passwords_reader
            .lines()
            .map(|line| {
                serde_json::from_str::<Vec<usize>>(&line.expect("Failed to read line"))
                    .expect("Failed to parse order")
            })
            .collect();
        let cursors: Vec<usize> = cursors_reader
            .lines()
            .map(|line| {
                line.expect("Failed to read line")
                    .parse()
                    .expect("Failed to parse cursor")
            })
            .collect();

        if passwords.len() != rotor_num || cursors.len() != rotor_num {
            panic!("The numbers of passwords and rotors are not equal.");
        }

        for i in 0..rotor_num {
            self.rotors[i].set_order(passwords[i].clone());
            self.rotors[i]
                .set_cursor(cursors[i])
                .expect("Invalid cursor cursor");
        }
    }

    fn set_plugboard(&mut self, plugboard_file: &str) {
        let file = File::open(plugboard_file).expect("Failed to open plugboard file");
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.expect("Failed to read line");
            if let Some((left, right)) = line.split_once('-') {
                let left = left
                    .trim()
                    .chars()
                    .next()
                    .expect("Invalid plugboard format")
                    .to_ascii_uppercase();
                let right = right
                    .trim()
                    .chars()
                    .next()
                    .expect("Invalid plugboard format")
                    .to_ascii_uppercase();
                self.plugboard.insert(left, right);
                self.plugboard.insert(right, left);
            }
        }
    }

    fn use_plugboard(&self, ch: char) -> char {
        *self.plugboard.get(&ch).unwrap_or(&ch)
    }

    pub fn encrypt(&mut self) -> std::io::Result<()> {
        self.base.get_text()?;
        self.base.clean_text();

        let plain_text: Vec<char> = self.base.plain_text.chars().collect();
        for c in plain_text {
            let mut ch = self.use_plugboard(c);
            ch = self.encipher_and_decipher(ch, 1);
            ch = *self.reflector.get(&ch).unwrap_or(&ch);
            ch = self.encipher_and_decipher(ch, -1);
            ch = self.use_plugboard(ch);

            self.base.encrypted_text.push(ch);
            self.link_and_move_rotors(0)?;
        }
        self.base.save_file()
    }

    fn encipher_and_decipher(&self, mut ch: char, sign: i32) -> char {
        for rotor in &self.rotors {
            let shift = rotor.order[rotor.cursor] as i32 * sign;
            let idx = ((ch as i32 - 'A' as i32 + shift).rem_euclid(26)) as usize;
            ch = (idx as usize + 'A' as usize) as u8 as char;
        }
        ch
    }

    pub fn link_and_move_rotors(&mut self, i: usize) -> std::io::Result<()> {
        self.rotors[i].step();
        if self.rotors[i].cursor == 0 && i < self.rotors.len() - 1 {
            self.link_and_move_rotors(i + 1)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod rotor_tests {
    use super::*;

    #[test]
    fn test_rotor_generate_order() {
        let mut rotor = Rotor::new(vec![], 0);
        rotor.generate_order("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(rotor.order.len(), 25);
        assert!(rotor.order.iter().all(|&x| x >= 1 && x <= 25));
    }

    #[test]
    fn test_rotor_generate_cursor() {
        let mut rotor = Rotor::new(vec![], 0);
        rotor.generate_order("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        rotor.generate_cursor();
        assert!(rotor.cursor < rotor.order.len());
    }

    #[test]
    fn test_rotor_step() {
        let mut rotor = Rotor::new(vec![1, 2, 3, 4, 5], 0);
        rotor.step();
        assert_eq!(rotor.cursor, 1);
        rotor.step();
        assert_eq!(rotor.cursor, 2);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_encryption() {
        let mut enigma = EnigmaMachine::new(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "input.txt",
            "output.txt",
            "reflector.txt",
            3,
            "passwords.txt",
            "rotors_cursor.txt",
            "plugboard.txt",
            "M",
            "M",
        );

        enigma.encrypt().unwrap();

        // 验证输出文件内容
        let output = std::fs::read_to_string("output.txt").expect("Failed to read output file");
        assert_eq!(output.trim(), "WUPHWYUVMK");
    }
}
