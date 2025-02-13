use crate::cipher::Cipher;

pub struct PolyalphabeticCipher<'a> {
    base: Cipher<'a>,
    key: Vec<i32>,
    decrypt: bool,
}

impl<'a> PolyalphabeticCipher<'a> {
    pub fn new(
        alphabet: &'a str,
        input_file: &'a str,
        output_file: &'a str,
        keyword: &str,
        decrypt: bool,
    ) -> Self {
        let key = keyword
            .chars()
            .map(|ch| alphabet.find(ch).unwrap() as i32 + 1)
            .collect();

        PolyalphabeticCipher {
            base: Cipher::new(alphabet, input_file, output_file),
            key,
            decrypt,
        }
    }

    fn encrypt_char(
        &self,
        alphabet: &str,
        ch: char,
        key: &Vec<i32>,
        idx: usize,
        sign: i32,
    ) -> char {
        let shift = key[idx % key.len()] * sign;
        let alphabet_len = alphabet.len() as i32;
        let idx = alphabet.find(ch).unwrap() as i32;
        let new_idx = self.base.change_index(alphabet_len, idx, shift);
        alphabet.chars().nth(new_idx).expect("Index out of range")
    }

    pub fn encrypt(&mut self) -> std::io::Result<()> {
        self.base.get_text()?;
        self.base.clean_text();

        let sign = if self.decrypt { -1 } else { 1 };

        self.base.encrypted_text = self
            .base
            .plain_text
            .chars()
            .enumerate()
            .map(|(i, ch)| self.encrypt_char(&self.base.alphabet, ch, &self.key, i, sign))
            .collect();

        self.base.save_file()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::read_to_string;
    use tempfile::NamedTempFile;

    #[test]
    fn test_polyalphabetic_cipher_encrypt() {
        let input_file = NamedTempFile::new().expect("Failed to create temporary input file");
        let input_path = input_file.path();

        let output_file = NamedTempFile::new().expect("Failed to create temporary output file");
        let output_path = output_file.path();

        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let keyword = "CAT";

        let input_content = "ILOVEYOU";
        std::fs::write(input_path, input_content).expect("Failed to write to input file");

        let mut cipher = PolyalphabeticCipher::new(
            alphabet,
            input_path.to_str().expect("Invalid input path"),
            output_path.to_str().expect("Invalid output path"),
            keyword,
            false,
        );
        cipher.encrypt().expect("Encryption failed");

        let encrypted_content = read_to_string(output_path).expect("Failed to read output file");
        let expected_encrypted_content = "LMIYFSRV";
        assert_eq!(encrypted_content.trim(), expected_encrypted_content);
    }
}
