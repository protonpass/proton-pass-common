package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.authenticator.commonrust.AuthenticatorCrypto
import proton.android.authenticator.commonrust.AuthenticatorMobileClient

class AuthenticatorCryptoTest {

    private val crypto = AuthenticatorCrypto()

    @Test
    fun `can generate encryption key`() {
        val key = crypto.generateKey()
        assertThat(key.size).isEqualTo(32)
    }
    
    @Test
    fun `can encrypt and decrypt`() {
        val client = AuthenticatorMobileClient()
        val label1 = "MYLABEL1"
        val label2 = "MYLABEL2"

        val entry1 = client.entryFromUri(entryUriWithLabel(label1))
        val entry2 = client.entryFromUri(entryUriWithLabel(label2))

        val key = crypto.generateKey()
        val encrypted = crypto.encryptManyEntries(listOf(entry1, entry2), key)
        
        assertThat(encrypted.size).isEqualTo(2)

        val decrypted = crypto.decryptManyEntries(encrypted, key)
        assertThat(decrypted.size).isEqualTo(2)

        assertThat(decrypted[0].name).isEqualTo(label1)
        assertThat(decrypted[1].name).isEqualTo(label2)
    }

    @Test
    fun `generateKey generates different keys`() {
        val key1 = crypto.generateKey()
        val key2 = crypto.generateKey()

        assertThat(key1).isNotEqualTo(key2)
    }

    private fun entryUriWithLabel(label: String): String =
        "otpauth://totp/$label?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"
}