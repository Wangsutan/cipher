use crate::cipher::Cipher;

pub struct CaesarCipher<'a> {
    base: Cipher<'a>,
    shift: i32,
}

impl<'a> CaesarCipher<'a> {
    pub fn new(alphabet: &'a str, input_file: &'a str, output_file: &'a str, shift: i32) -> Self {
        CaesarCipher {
            base: Cipher::new(alphabet, input_file, output_file),
            shift,
        }
    }

    fn encrypt_char(&self, alphabet: &str, ch: char, shift: i32) -> char {
        if let Some(idx) = alphabet.find(ch) {
            let new_idx = self
                .base
                .change_index(alphabet.len() as i32, idx as i32, shift);
            alphabet.chars().nth(new_idx).expect("Index out of range")
        } else {
            panic!("Character '{ch}' not found in alphabet");
        }
    }

    pub fn encrypt(&mut self) -> std::io::Result<()> {
        self.base.get_text()?;
        self.base.clean_text();

        self.base.encrypted_text = self
            .base
            .plain_text
            .chars()
            .map(|ch| self.encrypt_char(&self.base.alphabet, ch, self.shift))
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
    fn test_caesar_cipher_encrypt() {
        let input_file = NamedTempFile::new().expect("Failed to create temporary input file");
        let input_path = input_file.path();

        let output_file = NamedTempFile::new().expect("Failed to create temporary output file");
        let output_path = output_file.path();

        let input_content = "HELLO";
        std::fs::write(input_path, input_content).expect("Failed to write to input file");

        let mut cipher = CaesarCipher::new(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            input_path.to_str().expect("Invalid input path"),
            output_path.to_str().expect("Invalid output path"),
            3,
        );
        cipher.encrypt().expect("Encryption failed");

        let encrypted_content = read_to_string(output_path).expect("Failed to read output file");
        let expected_encrypted_content = "KHOOR";
        assert_eq!(encrypted_content.trim(), expected_encrypted_content);
    }
}
