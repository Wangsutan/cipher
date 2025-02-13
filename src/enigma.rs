use crate::cipher::Cipher;
use log::{error, info, warn};
use rand::{Rng, rng, seq::SliceRandom};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Result, Write};

/// 转子，恩尼格玛的一种核心部件，一般有3个或更多。
#[derive(Clone)]
struct Rotor {
    /// 密码本，上面是乱序的偏移量。
    order: Vec<usize>,
    /// 指向密码本上特定偏移量的指针。
    cursor: usize,
}

impl Rotor {
    /// 设置一个转子，包括其密码本和指针。
    fn new(order: Vec<usize>, cursor: usize) -> Self {
        Rotor { order, cursor }
    }

    /// 生成密码本，其值在1到字母表长度减1的范围内，并且是乱序的。
    fn generate_order(&self, alphabet: &str) -> Result<Vec<usize>> {
        let mut order: Vec<usize> = (1..alphabet.len()).collect::<Vec<usize>>();
        order.shuffle(&mut rng());
        Ok(order)
    }

    /// 设置转子的密码本，主要是做一些数据合法性校验。
    fn set_order(&self, alphabet: &str, order_vec: &Vec<usize>) -> Result<Vec<usize>> {
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
        for &item in order_vec {
            if seen.contains(&item) {
                warn!(
                    "Duplicate element found in order vector. Order vector: {:?}",
                    order_vec
                );
            }
            seen.insert(item);
        }

        Ok(order_vec.to_vec())
    }

    /// 生成转子的指针。
    fn generate_cursor(&self) -> usize {
        rand::rng().random_range(0..self.order.len())
    }

    /// 设置转子的指针，需要做合法性校验。
    fn set_cursor(&self, cursor: usize) -> Result<usize> {
        if cursor < self.order.len() {
            Ok(cursor)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid cursor",
            ))
        }
    }

    /// 转子的步进。
    fn step(&mut self) {
        self.cursor = (self.cursor + 1) % self.order.len();
    }
}

/// 恩尼格玛机的一种实现方式，它包含一个Cipher结构体，并且追加了反射器、转子序列和插线板这些新字段。
pub struct EnigmaMachine<'a> {
    base: Cipher<'a>,
    reflector: HashMap<char, char>,
    rotors: Vec<Rotor>,
    plugboard: HashMap<char, char>,
}

impl<'a> EnigmaMachine<'a> {
    /// 创建一个恩尼格玛机，设置其反射器、转子序列和插线板。
    /// 反射器和转子序列可以是生成的，也可以是载入的。
    /// 插线板是由人工设置的，该恩尼格玛机自动载入。
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

        enigma.reflector = enigma
            .set_reflector(reflector_from, alphabet, reflector_file)
            .unwrap();
        enigma.rotors = enigma
            .set_rotors(
                alphabet,
                rotor_num,
                passwords_file,
                rotors_cursor_file,
                rotors_from,
            )
            .unwrap();
        enigma.plugboard = enigma.set_plugboard(plugboard_file).unwrap();

        enigma
    }

    /// 设置反射器，分生成和载入两种方式。
    fn set_reflector(
        &self,
        reflector_from: &str,
        alphabet: &str,
        reflector_file: &str,
    ) -> Result<HashMap<char, char>> {
        if reflector_from == "m" {
            info!("Creating reflector and save it to: {}", reflector_file);
            self.create_reflector(alphabet, reflector_file)
        } else {
            info!("Reading reflector from: {}", reflector_file);
            self.load_reflector(reflector_file)
        }
    }

    /// 创建一个反射器，并记录到文件中。
    fn create_reflector(
        &self,
        alphabet: &str,
        reflector_file: &str,
    ) -> Result<HashMap<char, char>> {
        let mut plugs: Vec<char> = alphabet.chars().collect();
        plugs.shuffle(&mut rng());

        let num = plugs.len() / 2;
        let mut reflector: HashMap<char, char> = HashMap::new();
        for i in 0..num {
            let left = plugs[i];
            let right = plugs[i + num];
            reflector.insert(left, right);
            reflector.insert(right, left);
        }

        let reflector_str = serde_json::to_string(&reflector)?;
        let mut file = File::create(reflector_file)?;
        file.write_all(reflector_str.as_bytes())?;

        Ok(reflector)
    }

    /// 载入一个反射器，是从文件读取的。
    fn load_reflector(&self, reflector_file: &str) -> Result<HashMap<char, char>> {
        let file = File::open(reflector_file)?;
        let reader = BufReader::new(file);

        let reflector_str = reader
            .lines()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "File is empty"))??;

        let reflector: HashMap<char, char> = serde_json::from_str(&reflector_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(reflector)
    }

    /// 使用反射器变换字符。如果反射器不支持该字符，就返回该字符本身。
    fn use_reflector(&self, ch: char) -> char {
        *self.reflector.get(&ch).unwrap_or(&ch)
    }

    /// 设置转子序列，存在生成和载入两种方式。
    fn set_rotors(
        &self,
        alphabet: &str,
        rotor_num: usize,
        passwords_file: &str,
        rotors_cursor_file: &str,
        rotors_from: &str,
    ) -> Result<Vec<Rotor>> {
        if rotors_from == "m" {
            info!("Creating rotors and save them to {passwords_file} and {rotors_cursor_file}");
            self.generate_rotors(alphabet, rotor_num, passwords_file, rotors_cursor_file)
        } else {
            info!("Setting rotors from {passwords_file} and {rotors_cursor_file}");
            self.load_rotors(alphabet, rotor_num, passwords_file, rotors_cursor_file)
        }
    }

    /// 生成给定数量的转子，并且记录其密码本和指针到相应文件中。
    fn generate_rotors(
        &self,
        alphabet: &str,
        rotor_num: usize,
        passwords_file: &str,
        rotors_cursor_file: &str,
    ) -> Result<Vec<Rotor>> {
        let mut rotors: Vec<Rotor> = Vec::with_capacity(rotor_num);
        let mut passwords_file = File::create(passwords_file)?;
        let mut rotors_cursor_file = File::create(rotors_cursor_file)?;

        for _ in 0..rotor_num {
            let mut rotor = Rotor::new(vec![], 0);

            rotor.order = rotor.generate_order(alphabet).unwrap();
            let order_str = serde_json::to_string(&rotor.order)?;
            passwords_file.write_all(format!("{}\n", order_str).as_bytes())?;

            rotor.cursor = rotor.generate_cursor();
            rotors_cursor_file.write_all(format!("{}\n", rotor.cursor).as_bytes())?;

            rotors.push(rotor);
        }
        Ok(rotors)
    }

    /// 从相应的密码本文件和指针文件中，读取转子序列的信息。需要作一些合法性校验。
    fn load_rotors(
        &self,
        alphabet: &str,
        rotor_num: usize,
        passwords_file: &str,
        rotors_cursor_file: &str,
    ) -> Result<Vec<Rotor>> {
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

        let mut rotors: Vec<Rotor> = Vec::with_capacity(rotor_num);
        for i in 0..rotor_num {
            let mut rotor: Rotor = Rotor::new(vec![], 0);
            rotor.order = rotor.set_order(alphabet, &passwords[i])?;
            rotor.cursor = rotor.set_cursor(cursors[i])?;
            rotors.push(rotor);
        }

        Ok(rotors)
    }

    /// 从相应配置文件载入插线板。需要做一些合法性校验。
    fn set_plugboard(&self, plugboard_file: &str) -> Result<HashMap<char, char>> {
        let mut plugboard: HashMap<char, char> = HashMap::new();

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
                if plugboard.contains_key(&left) {
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
                if plugboard.values().any(|&v| v == right) {
                    error!(
                        "Duplicate value found in plugboard: {}. Value already exists.",
                        right
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Duplicate value in plugboard",
                    ));
                }

                plugboard.insert(left, right);
                plugboard.insert(right, left);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid plugboard format",
                ));
            }
        }

        Ok(plugboard)
    }

    /// 使用插线板，字符如果能转换就转换，不能转换则保持原样。
    fn use_plugboard(&self, ch: char) -> char {
        *self.plugboard.get(&ch).unwrap_or(&ch)
    }

    /// 核心的加密过程。这里存在许多副作用。
    pub fn encrypt(&mut self) -> std::io::Result<()> {
        self.base.get_text()?;
        self.base.clean_text();

        info!("Encrypting text...");

        let plain_text: Vec<char> = self.base.plain_text.chars().collect();
        for c in plain_text {
            let mut ch = self.use_plugboard(c);
            ch = self.encipher_and_decipher(ch, 1);
            ch = self.use_reflector(ch);
            ch = self.encipher_and_decipher(ch, -1);
            ch = self.use_plugboard(ch);

            self.base.encrypted_text.push(ch);
            self.link_and_move_rotors(0)?;
        }
        self.base.save_file()
    }

    /// 字符通过转子进行加密的过程。
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

    /// 恩尼格玛极有特色的转子步进方式，其中存在连接关系。
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
        rotor.order = rotor.generate_order("ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        assert_eq!(rotor.order.len(), 25);
        assert!(rotor.order.iter().all(|&x| x >= 1 && x <= 25));
    }

    #[test]
    fn test_rotor_generate_cursor() {
        let mut rotor = Rotor::new(vec![], 0);
        rotor.order = rotor.generate_order("ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        rotor.cursor = rotor.generate_cursor();
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
