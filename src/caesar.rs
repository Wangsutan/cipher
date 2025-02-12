use crate::cipher::Cipher;

pub struct CaesarCipher {
    base: Cipher,
    shift: i32,
}

impl CaesarCipher {
    pub fn new(alphabet: &str, input_file: &str, output_file: &str, shift: i32) -> Self {
        CaesarCipher {
            base: Cipher::new(alphabet, input_file, output_file),
            shift,
        }
    }

    fn encrypt_char(&self, alphabet: &str, c: char, shift: i32) -> char {
        let alphabet_len = alphabet.len() as i32;
        let idx = alphabet.find(c).unwrap() as i32;
        let new_idx = self.base.change_index(alphabet_len, idx, shift);
        alphabet.chars().nth(new_idx as usize).unwrap()
    }

    pub fn encrypt(&mut self) -> std::io::Result<()> {
        self.base.get_text()?;
        self.base.clean_text();

        self.base.encrypted_text = self
            .base
            .plain_text
            .chars()
            .map(|c| self.encrypt_char(&self.base.alphabet, c, self.shift))
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
        // 创建临时输入文件
        let input_file = NamedTempFile::new().expect("Failed to create temporary input file");
        let input_path = input_file.path();

        // 创建临时输出文件
        let output_file = NamedTempFile::new().expect("Failed to create temporary output file");
        let output_path = output_file.path();

        // 写入测试内容到输入文件
        let input_content = "HELLO";
        std::fs::write(input_path, input_content).expect("Failed to write to input file");

        // 创建 CaesarCipher 实例并加密
        let mut cipher = CaesarCipher::new(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            input_path.to_str().unwrap(),
            output_path.to_str().unwrap(),
            3,
        );
        cipher.encrypt().expect("Encryption failed");

        // 读取加密后的输出文件
        let encrypted_content = read_to_string(output_path).expect("Failed to read output file");

        // 预期加密结果
        let expected_encrypted_content = "KHOOR";

        // 比较加密结果
        assert_eq!(encrypted_content.trim(), expected_encrypted_content);
    }
}
