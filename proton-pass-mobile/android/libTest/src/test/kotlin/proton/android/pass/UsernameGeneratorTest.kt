package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.UsernameGenerator
import proton.android.pass.commonrust.UsernameGeneratorConfig
import proton.android.pass.commonrust.WordSeparator
import proton.android.pass.commonrust.WordTypes

class UsernameGeneratorTest {

    private fun allWordTypes() = WordTypes(adjectives = true, nouns = true, verbs = true)

    @Test
    fun `can generate username with all word types`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = false,
            capitalise = false,
            separator = null,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result).isNotEmpty()
        assertThat(result.all { it.isLetter() }).isTrue()
    }

    @Test
    fun `word count zero returns empty string`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 0u,
            includeNumbers = false,
            capitalise = false,
            separator = null,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result).isEmpty()
    }

    @Test
    fun `include numbers appends or prepends a digit`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = true,
            capitalise = false,
            separator = null,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result).isNotEmpty()
        val hasLeadingDigit = result.first().isDigit()
        val hasTrailingDigit = result.last().isDigit()
        assertThat(hasLeadingDigit || hasTrailingDigit).isTrue()
    }

    @Test
    fun `capitalise produces at least one uppercase letter`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = false,
            capitalise = true,
            separator = null,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result.any { it.isUpperCase() }).isTrue()
    }

    @Test
    fun `hyphen separator joins words with hyphens`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 3u,
            includeNumbers = false,
            capitalise = false,
            separator = WordSeparator.HYPHENS,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result).contains("-")
        assertThat(result.split("-")).hasSize(3)
    }

    @Test
    fun `underscore separator joins words with underscores`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = false,
            capitalise = false,
            separator = WordSeparator.UNDERSCORES,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result).contains("_")
    }

    @Test
    fun `only nouns word type generates non-empty username`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = false,
            capitalise = false,
            separator = null,
            leetspeak = false,
            wordTypes = WordTypes(adjectives = false, nouns = true, verbs = false)
        )

        val result = generator.generate(config)

        assertThat(result).isNotEmpty()
    }

    @Test
    fun `single word config returns single word`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 1u,
            includeNumbers = false,
            capitalise = false,
            separator = WordSeparator.HYPHENS,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result).isNotEmpty()
        assertThat(result).doesNotContain("-")
    }

    @Test
    fun `multiple generators produce different usernames`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = false,
            capitalise = false,
            separator = null,
            leetspeak = false,
            wordTypes = allWordTypes()
        )

        val results = (1..10).map { generator.generate(config) }.toSet()

        assertThat(results.size).isGreaterThan(1)
    }

    @Test
    fun `leetspeak produces non-alphabetic characters`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = false,
            capitalise = false,
            separator = null,
            leetspeak = true,
            wordTypes = allWordTypes()
        )

        val result = generator.generate(config)

        assertThat(result).isNotEmpty()
        assertThat(result.any { it.isDigit() }).isTrue()
    }

    @Test(expected = Exception::class)
    fun `no word types selected throws error`() {
        val generator = UsernameGenerator()
        val config = UsernameGeneratorConfig(
            wordCount = 2u,
            includeNumbers = false,
            capitalise = false,
            separator = null,
            leetspeak = false,
            wordTypes = WordTypes(adjectives = false, nouns = false, verbs = false)
        )

        generator.generate(config)
    }
}
