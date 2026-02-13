package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.PassphraseConfig
import proton.android.pass.commonrust.PassphraseGenerator
import proton.android.pass.commonrust.RandomPasswordConfig
import proton.android.pass.commonrust.RandomPasswordGenerator
import proton.android.pass.commonrust.WordSeparator

class PasswordGeneratorTest {

    @Test
    fun `can generate random password with basic config`() {
        val generator = RandomPasswordGenerator()
        val config = RandomPasswordConfig(
            length = 16u,
            numbers = true,
            uppercaseLetters = true,
            symbols = true
        )

        val password = generator.generate(config)

        assertThat(password).isNotEmpty()
        assertThat(password.length).isEqualTo(16)
    }

    @Test
    fun `generated password respects length`() {
        val generator = RandomPasswordGenerator()
        val config = RandomPasswordConfig(
            length = 32u,
            numbers = true,
            uppercaseLetters = true,
            symbols = false
        )

        val password = generator.generate(config)

        assertThat(password.length).isEqualTo(32)
    }

    @Test
    fun `can generate passphrase`() {
        val generator = PassphraseGenerator()
        val config = PassphraseConfig(
            separator = WordSeparator.HYPHENS,
            capitalise = true,
            includeNumbers = false,
            count = 4u
        )

        val passphrase = generator.generateRandomPassphrase(config)

        assertThat(passphrase).isNotEmpty()
        assertThat(passphrase).contains("-")
    }

    @Test
    fun `can generate random words`() {
        val generator = PassphraseGenerator()

        val words = generator.randomWords(5u)

        assertThat(words).hasSize(5)
        words.forEach { word ->
            assertThat(word).isNotEmpty()
        }
    }

    @Test
    fun `can generate passphrase from words`() {
        val generator = PassphraseGenerator()
        val words = listOf("test", "example", "words", "here")
        val config = PassphraseConfig(
            separator = WordSeparator.UNDERSCORES,
            capitalise = false,
            includeNumbers = true,
            count = words.size.toUInt()
        )

        val passphrase = generator.generatePassphrase(words, config)

        assertThat(passphrase).isNotEmpty()
        assertThat(passphrase).contains("_")
    }
}
