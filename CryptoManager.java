package crypto;

public class CryptoManager {
	
	private static final char LOWER_BOUND = ' ';
	private static final char UPPER_BOUND = '_';
	private static final int RANGE = UPPER_BOUND - LOWER_BOUND + 1;

	/**
	 * This method determines if a string is within the allowable bounds of ASCII codes 
	 * according to the LOWER_BOUND and UPPER_BOUND characters
	 * @param plainText a string to be encrypted, if it is within the allowable bounds
	 * @return true if all characters are within the allowable bounds, false if any character is outside
	 */
	public static boolean stringInBounds (String plainText) {
		// Loop through each character in the plainText
		for(int i=0; i < plainText.length(); i++) {
			char c = plainText.charAt(i);
			if(c < LOWER_BOUND || c > UPPER_BOUND) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Encrypts a string according to the Caesar Cipher.  The integer key specifies an offset
	 * and each character in plainText is replaced by the character \"offset\" away from it 
	 * @param plainText an uppercase string to be encrypted.
	 * @param key an integer that specifies the offset of each character
	 * @return the encrypted string
	 */
	public static String encryptCaesar(String plainText, int key) {
		 // Convert the plainText to uppercase to simplify the algorithm
		plainText = plainText.toUpperCase();
		 // Check if the plainText is within the allowable bounds
		if(!stringInBounds(plainText)) {
			throw new IllegalArgumentException("Input string contains invalid characters");
		}
		
		StringBuilder encrypted = new StringBuilder();
		
		 // Loop through each character in the plainText
		for(int i=0; i < plainText.length(); i++) {
			char c = plainText.charAt(i);
			
			// Shift the character by the key value
			int shifted = (c - LOWER_BOUND + key) % RANGE + LOWER_BOUND;
			
			// Add the shifted character to the encrypted string
			encrypted.append((char)shifted);
		}
		
		// Return the encrypted string
		return encrypted.toString();
	}
	
	/**
	 * Encrypts a string according the Bellaso Cipher.  Each character in plainText is offset 
	 * according to the ASCII value of the corresponding character in bellasoStr, which is repeated
	 * to correspond to the length of plainText
	 * @param plainText an uppercase string to be encrypted.
	 * @param bellasoStr an uppercase string that specifies the offsets, character by character.
	 * @return the encrypted string
	 */
	public static String encryptBellaso(String plainText, String bellasoStr) {
		 // Convert the plainText to uppercase to simplify the algorithm
		plainText = plainText.toUpperCase();
		 // Check if the plainText is within the allowable bounds
		if(!stringInBounds(plainText)) {
			throw new IllegalArgumentException("Input string contains invalid characters");
		}
	    StringBuilder encrypted = new StringBuilder();
	    
	    // Repeat the bellasoStr to match the length of the plainText
	    String repeatedBellaso = repeatToMatchLength(bellasoStr, plainText.length());
	    
	    // Loop through each character in the plainText
	    for (int i = 0; i < plainText.length(); i++) {
	        char plainChar = plainText.charAt(i);
	        char bellasoChar = repeatedBellaso.charAt(i);
	        int shifted;
	        // Shift the plainChar by the ASCII value of the corresponding bellasoChar
	        shifted = (int)plainChar + (int)bellasoChar;
	        // Wrap the shifted character around if it goes beyond the upper bound
	        while(shifted > (int)UPPER_BOUND) {
	            shifted -= RANGE;
	        }
	        // Add the shifted character to the encrypted string
	        encrypted.append((char)shifted);
	    }
	    
	    // Return the encrypted string
	    return encrypted.toString();
	}

	/**
	 * Repeats the input string to match the specified length by appending the string to itself.
	 * If the input string is already longer than the specified length, it is truncated.
	 * @param str the string to be repeated
	 * @param length the desired length of the repeated string
	 * @return the repeated string
	 */
	private static String repeatToMatchLength(String str, int length) {
	    StringBuilder repeated = new StringBuilder();
	    while (repeated.length() < length) {
	        repeated.append(str);
	    }
	    return repeated.substring(0, length);
	}
	
	/**
	 * Decrypts a string according to the Caesar Cipher.  The integer key specifies an offset
	 * and each character in encryptedText is replaced by the character \"offset\" characters before it.
	 * This is the inverse of the encryptCaesar method.
	 * @param encryptedText an encrypted string to be decrypted.
	 * @param key an integer that specifies the offset of each character
	 * @return the plain text string
	 */
	public static String decryptCaesar(String encryptedText, int key) {
	    // Convert the encryptedText to uppercase to simplify the algorithm
	    encryptedText = encryptedText.toUpperCase();

	    StringBuilder decrypted = new StringBuilder();

	    // Loop through each character in the encryptedText
	    for (int i = 0; i < encryptedText.length(); i++) {
	        char c = encryptedText.charAt(i);

	        // Shift the character back by the key value
	        int shifted = (c - LOWER_BOUND - (key % RANGE) + RANGE) % RANGE + LOWER_BOUND;

	        // Add the shifted character to the decrypted string
	        decrypted.append((char)shifted);
	    }

	    // Return the decrypted string
	    return decrypted.toString();
	}

	
	/**
	 * Decrypts a string according the Bellaso Cipher.  Each character in encryptedText is replaced by
	 * the character corresponding to the character in bellasoStr, which is repeated
	 * to correspond to the length of plainText.  This is the inverse of the encryptBellaso method.
	 * @param encryptedText an uppercase string to be encrypted.
	 * @param bellasoStr an uppercase string that specifies the offsets, character by character.
	 * @return the decrypted string
	 */
	public static String decryptBellaso(String encryptedText, String bellasoStr) {
	    // Check if the encryptedText is within the allowable bounds
	    if(!stringInBounds(encryptedText)) {
	        throw new IllegalArgumentException("Input string contains invalid characters");
	    }
	    StringBuilder decrypted = new StringBuilder();
	    
	    // Repeat the bellasoStr to match the length of the encryptedText
	    String repeatedBellaso = repeatToMatchLength(bellasoStr, encryptedText.length());
	    
	    // Loop through each character in the encryptedText
	    for (int i = 0; i < encryptedText.length(); i++) {
	        char encryptedChar = encryptedText.charAt(i);
	        char bellasoChar = repeatedBellaso.charAt(i);
	        int shifted;
	        // Shift the encryptedChar back by the ASCII value of the corresponding bellasoChar
	        shifted = (int)encryptedChar - (int)bellasoChar;
	        // Wrap the shifted character around if it goes below the lower bound
	        while(shifted < (int)LOWER_BOUND) {
	            shifted += RANGE;
	        }
	        // Add the shifted character to the decrypted string
	        decrypted.append((char)shifted);
	    }
	    
	    // Return the decrypted string
	    return decrypted.toString();
	}
}