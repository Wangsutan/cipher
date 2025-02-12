use std::fs;

pub struct Cipher {
    pub alphabet: String,
    pub input_file: String,
    pub output_file: String,
    pub plain_text: String,
    pub encrypted_text: String,
}

impl Cipher {
    pub fn new(alphabet: &str, input_file: &str, output_file: &str) -> Self {
        Cipher {
            alphabet: alphabet.to_string(),
            input_file: input_file.to_string(),
            output_file: output_file.to_string(),
            plain_text: String::new(),
            encrypted_text: String::new(),
        }
    }

    pub fn get_text(&mut self) -> std::io::Result<()> {
        self.plain_text = fs::read_to_string(&self.input_file)?;
        Ok(())
    }

    pub fn clean_text(&mut self) {
        self.plain_text = self
            .plain_text
            .chars()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| c.to_ascii_uppercase())
            .collect();
    }

    pub fn save_file(&self) -> std::io::Result<()> {
        fs::write(&self.output_file, &self.encrypted_text)
    }

    pub fn change_index(&self, alphabet_len: i32, index: i32, shift: i32) -> usize {
        ((index + shift).rem_euclid(alphabet_len)) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_index() {
        let cipher = Cipher::new("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "input.txt", "output.txt");

        // 测试正常情况
        assert_eq!(cipher.change_index(26, 0, 1), 1); // 0 + 1 = 1
        assert_eq!(cipher.change_index(26, 25, 1), 0); // 25 + 1 = 26, 26 % 26 = 0
        assert_eq!(cipher.change_index(26, 10, 5), 15); // 10 + 5 = 15
        assert_eq!(cipher.change_index(26, 10, 16), 0); // 10 + 16 = 26, 26 % 26 = 0

        // 测试负偏移
        assert_eq!(cipher.change_index(26, 5, -1), 4); // 5 - 1 = 4, 4 % 26 = 4
        assert_eq!(cipher.change_index(26, 5, -25), 6); // 5 - 25 = -20, -20 % 26 = 6
    }
}
