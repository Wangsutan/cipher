use crate::cipher::Cipher;
use log::{error, info, warn};
use rand::{Rng, rng, seq::SliceRandom};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};

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

    fn set_order(&mut self, alphabet: &str, order_vec: Vec<usize>) -> io::Result<()> {
        // 检查密码本长度
        if order_vec.len() != alphabet.len() - 1 {
            warn!(
                "Invalid order vector length. Expected: {}, Found: {}. Order vector: {:?}",
                alphabet.len() - 1,
                order_vec.len(),
                order_vec
            );
        }

        // 检查密码本中是否存在重复元素
        let mut seen = HashSet::new();
        for &item in &order_vec {
            if seen.contains(&item) {
                warn!(
                    "Duplicate element found in order vector. Order vector: {:?}",
                    order_vec
                );
            }
            seen.insert(item);
        }

        self.order = order_vec;
        Ok(())
    }

    fn generate_cursor(&mut self) -> () {
        self.cursor = rand::rng().random_range(0..self.order.len());
    }

    fn set_cursor(&mut self, cursor: usize) -> io::Result<()> {
        if cursor < self.order.len() {
            self.cursor = cursor;
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid cursor",
            ))
        }
    }

    fn step(&mut self) {
        self.cursor = (self.cursor + 1) % self.order.len();
    }
}

pub struct EnigmaMachine<'a> {
    base: Cipher<'a>,
    reflector: HashMap<char, char>,
    rotors: Vec<Rotor>,
    plugboard: HashMap<char, char>,
}

impl<'a> EnigmaMachine<'a> {
    pub fn new(
        alphabet: &'a str,
        input_file: &'a str,
        output_file: &'a str,
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
            reflector: HashMap::new(),
            rotors: vec![Rotor::new(vec![], 0); rotor_num],
            plugboard: HashMap::new(),
        };

        let _ = enigma.set_reflector(reflector_from, alphabet, reflector_file);
        let _ = enigma.set_rotors(
            alphabet,
            rotor_num,
            passwords_file,
            rotors_cursor_file,
            rotors_from,
        );
        let _ = enigma.set_plugboard(plugboard_file);

        enigma
    }

    fn set_reflector(
        &mut self,
        reflector_from: &str,
        alphabet: &str,
        reflector_file: &str,
    ) -> io::Result<()> {
        if reflector_from == "m" {
            info!("Creating reflector and save it to: {}", reflector_from);
            self.create_reflector(alphabet, reflector_file)?;
        } else {
            info!("Reading reflector from: {}", reflector_from);
            self.load_reflector(reflector_file)?;
        }

        Ok(())
    }

    fn create_reflector(&mut self, alphabet: &str, reflector_file: &str) -> io::Result<()> {
        let mut plugs: Vec<char> = alphabet.chars().collect();
        plugs.shuffle(&mut rng());

        let num = plugs.len() / 2;
        let mut reflector = HashMap::new();
        for i in 0..num {
            let left = plugs[i];
            let right = plugs[i + num];
            reflector.insert(left, right);
            reflector.insert(right, left);
        }

        self.reflector = reflector;

        let reflector_str = serde_json::to_string(&self.reflector)?;
        let mut file = File::create(reflector_file)?;
        file.write_all(reflector_str.as_bytes())?;

        Ok(())
    }

    fn load_reflector(&mut self, reflector_file: &str) -> io::Result<()> {
        let file = File::open(reflector_file)?;
        let reader = BufReader::new(file);

        let reflector_str = reader
            .lines()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "File is empty"))??;

        let reflector_map: HashMap<char, char> = serde_json::from_str(&reflector_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        for (key, value) in reflector_map {
            self.reflector.insert(key, value);
        }

        Ok(())
    }

    fn set_rotors(
        &mut self,
        alphabet: &str,
        rotor_num: usize,
        passwords_file: &str,
        rotors_cursor_file: &str,
        rotors_from: &str,
    ) -> io::Result<()> {
        if rotors_from == "m" {
            info!("Creating rotors and save them to {passwords_file} and {rotors_cursor_file}");
            self.generate_rotors(passwords_file, rotors_cursor_file)?;
        } else {
            info!("Setting rotors from {passwords_file} and {rotors_cursor_file}");
            self.load_rotors(alphabet, rotor_num, passwords_file, rotors_cursor_file)?;
        }

        Ok(())
    }

    fn generate_rotors(
        &mut self,
        passwords_file: &str,
        rotors_cursor_file: &str,
    ) -> io::Result<()> {
        let mut passwords_file = File::create(passwords_file)?;
        let mut rotors_cursor_file = File::create(rotors_cursor_file)?;

        for rotor in &mut self.rotors {
            rotor.generate_order(&self.base.alphabet);
            let order_str = serde_json::to_string(&rotor.order)?;
            passwords_file.write_all(format!("{}\n", order_str).as_bytes())?;

            rotor.generate_cursor();
            rotors_cursor_file.write_all(format!("{}\n", rotor.cursor).as_bytes())?;
        }

        Ok(())
    }

    fn load_rotors(
        &mut self,
        alphabet: &str,
        rotor_num: usize,
        passwords_file: &str,
        rotors_cursor_file: &str,
    ) -> io::Result<()> {
        let passwords_file = File::open(passwords_file)?;
        let passwords_reader = BufReader::new(passwords_file);
        let passwords: Vec<Vec<usize>> = passwords_reader
            .lines()
            .map(|line| {
                serde_json::from_str::<Vec<usize>>(&line.expect("Failed to read line"))
                    .expect("Failed to parse order")
            })
            .collect();

        // 检查每个 Vec<usize> 的长度是否一致
        let expected_length = passwords[0].len();
        for (i, order_vec) in passwords.iter().enumerate() {
            if order_vec.len() != expected_length {
                warn!(
                    "Inconsistent order vector length for rotor {}. Expected: {}, Found: {}. Order vector: {:?}",
                    i + 1,
                    expected_length,
                    order_vec.len(),
                    order_vec
                );
            }
        }

        let rotors_cursor_file = File::open(rotors_cursor_file)?;
        let cursors_reader = BufReader::new(rotors_cursor_file);
        let cursors: Vec<usize> = cursors_reader
            .lines()
            .map(|line| {
                line.expect("Failed to read line")
                    .parse()
                    .expect("Failed to parse cursor")
            })
            .collect();

        if passwords.len() != rotor_num || cursors.len() != rotor_num {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The number of rotors does not match the expected number",
            ));
        }

        for i in 0..rotor_num {
            self.rotors[i].set_order(alphabet, passwords[i].clone())?;
            self.rotors[i].set_cursor(cursors[i])?;
        }

        Ok(())
    }

    fn set_plugboard(&mut self, plugboard_file: &str) -> io::Result<()> {
        let file = File::open(plugboard_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if let Some((left, right)) = line.split_once('-') {
                let left = left
                    .trim()
                    .chars()
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid plugboard format")
                    })?
                    .to_ascii_uppercase();
                let right = right
                    .trim()
                    .chars()
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Invalid plugboard format")
                    })?
                    .to_ascii_uppercase();

                // 检查重复键
                if self.plugboard.contains_key(&left) {
                    error!(
                        "Duplicate key found in plugboard: {}. Key already exists.",
                        left
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Duplicate key in plugboard",
                    ));
                }

                // 检查重复值
                if self.plugboard.values().any(|&v| v == right) {
                    error!(
                        "Duplicate value found in plugboard: {}. Value already exists.",
                        right
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Duplicate value in plugboard",
                    ));
                }

                self.plugboard.insert(left, right);
                self.plugboard.insert(right, left);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid plugboard format",
                ));
            }
        }

        Ok(())
    }

    fn use_plugboard(&self, ch: char) -> char {
        *self.plugboard.get(&ch).unwrap_or(&ch)
    }

    pub fn encrypt(&mut self) -> std::io::Result<()> {
        self.base.get_text()?;
        self.base.clean_text();

        info!("Encrypting text...");

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
            let idx = self.base.alphabet.chars().position(|c| c == ch).unwrap();
            let new_idx =
                ((idx as i32 + shift).rem_euclid(self.base.alphabet.len() as i32)) as usize;
            ch = self.base.alphabet.chars().nth(new_idx).unwrap();
        }
        ch
    }

    pub fn link_and_move_rotors(&mut self, i: usize) -> std::io::Result<()> {
        self.rotors[i].step();
        info!("Rotor {i} Stepped");
        if self.rotors[i].cursor == 0 && i < self.rotors.len() - 1 {
            info!("Linking rotor {} to rotor {}", i, i + 1);
            self.link_and_move_rotors(i + 1)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod reflector_tests {
    use super::*;
    use std::collections::HashMap;

    fn test_reflector(alphabet: &str, reflector: &HashMap<char, char>) {
        // 检查反射器的键值对数量
        assert_eq!(alphabet.len(), reflector.len(), "Reflector size mismatch");

        // 检查反射器的对称性
        for (key, value) in reflector {
            assert_eq!(
                reflector.get(value).unwrap(),
                key,
                "Reflector symmetry mismatch"
            );
        }

        // 检查反射器中是否有重复的键或值
        let keys: Vec<char> = reflector.keys().cloned().collect();
        let values: Vec<char> = reflector.values().cloned().collect();

        // 检查是否有重复的键
        assert_eq!(
            keys.len(),
            keys.iter().collect::<std::collections::HashSet<_>>().len(),
            "Duplicate keys found in reflector"
        );

        // 检查是否有重复的值
        assert_eq!(
            values.len(),
            values
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "Duplicate values found in reflector"
        );
    }

    #[test]
    fn test_create_reflector() {
        use tempfile::NamedTempFile;

        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let input_file = NamedTempFile::new().expect("Failed to create temporary input file");
        let reflector_file_path = input_file.path();

        let enigma = EnigmaMachine::new(
            alphabet,
            "input.txt",
            "output.txt",
            reflector_file_path.to_str().unwrap(),
            3,
            "passwords.txt",
            "rotors_cursor.txt",
            "plugboard.txt",
            "m", // 手动创建反射器
            "M",
        );

        test_reflector(alphabet, &enigma.reflector);
    }

    #[test]
    fn test_load_reflector() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let reflector_file = "reflector.txt";

        let enigma = EnigmaMachine::new(
            alphabet,
            "input.txt",
            "output.txt",
            reflector_file,
            3,
            "passwords.txt",
            "rotors_cursor.txt",
            "plugboard.txt",
            "M", // 读取反射器
            "M",
        );

        test_reflector(alphabet, &enigma.reflector);
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
    use log::info;

    #[test]
    fn test_full_encryption() {
        env_logger::init();

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
        let input = std::fs::read_to_string("input.txt").expect("Failed to read output file");
        let output = std::fs::read_to_string("output.txt").expect("Failed to read output file");
        info!("Input: {}", input);
        info!("Output: {}", output);
        assert_eq!(output.trim(), "UDMHSOPVKJ");

        let mut have_same_char: bool = false;
        for (c_in, c_out) in input.chars().zip(output.chars()) {
            if c_in == c_out {
                have_same_char = true;
                break;
            }
        }
        assert!(!have_same_char, "It is not a Enigma!");
    }
}
