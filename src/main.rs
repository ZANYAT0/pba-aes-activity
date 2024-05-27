//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.
//!
//!



use aes::{
	cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
	Aes128,
};
use aes::cipher::consts::U16;
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;
const SYM_KEY: &[u8; 16] = &[
	6, 108, 74, 203, 170, 212, 94, 238, 171, 104, 19, 17, 248, 197, 127, 138,
];

fn main() {
	let test_str = "Hello Polkadot Blockchain Academy Singapore 2024!!!";
	let result = ecb_encrypt(Vec::from(test_str.as_bytes()), *SYM_KEY);
	println!("encrypted string: {:?}", result);

	let decrypted = ecb_decrypt(result, *SYM_KEY);
	println!("decrypted string: {:?}", String::from_utf8(decrypted));

	let result = cbc_encrypt(Vec::from(test_str.as_bytes()), *SYM_KEY);
	println!("cbc encrypted string: {:?}", result);

	let decrypted = cbc_encrypt(result, *SYM_KEY);
	println!("cbc decrypted string: {:?}", String::from_utf8(decrypted));
	// todo!("Maybe this should be a library crate. TBD");


}

fn xor_arrays<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
	let mut result = [0u8; N];
	for i in 0..N {
		result[i] = a[i] ^ b[i];
	}
	result
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.encrypt_block(&mut block);

	block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.decrypt_block(&mut block);

	block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
	// When twe have a multiple the second term is 0
	let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

	for _ in 0..number_pad_bytes {
		data.push(number_pad_bytes as u8);
	}

	data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
	let mut blocks = Vec::new();
	let mut i = 0;
	while i < data.len() {
		let mut block: [u8; BLOCK_SIZE] = Default::default();
		block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
		blocks.push(block);

		i += BLOCK_SIZE;
	}

	blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
	let mut data = Vec::new();
	for block in blocks {
		data.extend_from_slice(&block);
	}
	data
}

/// Does the opposite of the pad function.
fn un_pad(data: Vec<u8>) -> Vec<u8> {
	let mut data_mut = data;
	let pad_length = data_mut[data_mut.len() - 1] as usize;
	data_mut.truncate(data_mut.len() - pad_length);
	if pad_length == BLOCK_SIZE {
		data_mut.truncate(data_mut.len() - BLOCK_SIZE);
	}
	data_mut
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
	let padded_text = pad(plain_text);
	let cipher = Aes128::new(&GenericArray::from(key));
	let encrypted_blocks: Vec<[u8; 16]> = group(padded_text).into_iter().map(|block| {
		let encrypted_block = block;
		let mut block_array: GenericArray<u8, U16> = GenericArray::from(encrypted_block);
		cipher.encrypt_block(&mut block_array);
		block_array.into()
	}).collect();
	let encrypted_text: Vec<u8> = un_group(encrypted_blocks);
	encrypted_text
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let cipher = Aes128::new(&GenericArray::from(key));
    let encrypted_blocks: Vec<[u8; 16]> = group(cipher_text);
    let decrypted_blocks: Vec<[u8; 16]> = encrypted_blocks.into_iter().map(|block| {
        let mut block_array: GenericArray<u8, U16> = GenericArray::clone_from_slice(&block);
        cipher.decrypt_block(&mut block_array);
        block_array.into()
    }).collect();
    let decrypted_text: Vec<u8> = un_group(decrypted_blocks);
    un_pad(decrypted_text)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let padded_text = pad(plain_text);
	let cipher = Aes128::new(&GenericArray::from(key));
	let mut rng = rand::thread_rng();
	let iv: [u8; BLOCK_SIZE] = rng.gen();

	let mut xor_key = iv;
	let mut encrypted_blocks: Vec<[u8; 16]> = vec![iv]; // Start with the IV
	for block in group(padded_text) {
		let mut block_array: GenericArray<u8, U16> = GenericArray::from(xor_arrays(block, xor_key));
		cipher.encrypt_block(&mut block_array);
		xor_key = block_array.clone().into();
		encrypted_blocks.push(block_array.into());
	}

	un_group(encrypted_blocks)
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	let cipher = Aes128::new(&GenericArray::from(key));
	let blocks: Vec<[u8; BLOCK_SIZE]> = group(cipher_text);
	if blocks.is_empty() {
		return Vec::new();
	}
	let iv = blocks[0];

	let mut previous_block = iv;
	let mut decrypted_blocks: Vec<[u8; BLOCK_SIZE]> = Vec::new();
	for &block in &blocks[1..] {
		let mut block_array: GenericArray<u8, U16> = GenericArray::from(block);
		cipher.decrypt_block(&mut block_array);
		let decrypted_block = xor_arrays(block_array.into(), previous_block);
		decrypted_blocks.push(decrypted_block);
		previous_block = block;
	}

	let decrypted_text = un_group(decrypted_blocks);
	un_pad(decrypted_text)
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random nonce
	todo!()
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	todo!()
}