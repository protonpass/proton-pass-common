package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.TotpAlgorithm
import proton.android.pass.commonrust.TotpHandler
import proton.android.pass.commonrust.TotpTokenGenerator
import proton.android.pass.commonrust.TotpUriParser
import proton.android.pass.commonrust.TotpUriSanitizer

class TotpTest {

    @Test
    fun `can parse TOTP URI`() {
        val parser = TotpUriParser()
        val uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"

        val totp = parser.parse(uri)

        assertThat(totp.label).isEqualTo("MYLABEL")
        assertThat(totp.secret).isEqualTo("MYSECRET")
        assertThat(totp.issuer).isEqualTo("MYISSUER")
        assertThat(totp.algorithm).isEqualTo(TotpAlgorithm.SHA256)
        assertThat(totp.digits).isEqualTo(8.toUByte())
        assertThat(totp.period).isEqualTo(15.toUShort())
    }

    @Test
    fun `can generate TOTP token`() {
        val generator = TotpTokenGenerator()
        val uri = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"

        val result = generator.generateToken(uri, 1739284795uL)

        assertThat(result.token).isNotEmpty()
        assertThat(result.token.length).isEqualTo(8)
        assertThat(result.token).isEqualTo("44326356")
        assertThat(result.timestamp).isEqualTo(1739284795uL)
    }

    @Test
    fun `TOTP handler can get algorithm`() {
        val parser = TotpUriParser()
        val handler = TotpHandler()
        val totp = parser.parse(
            "otpauth://totp/test?secret=SECRET&algorithm=SHA512&digits=6&period=30"
        )

        val algorithm = handler.getAlgorithm(totp)

        assertThat(algorithm).isEqualTo(TotpAlgorithm.SHA512)
    }

    @Test
    fun `TOTP handler can get digits`() {
        val parser = TotpUriParser()
        val handler = TotpHandler()
        val totp = parser.parse(
            "otpauth://totp/test?secret=SECRET&algorithm=SHA1&digits=8&period=30"
        )

        val digits = handler.getDigits(totp)

        assertThat(digits).isEqualTo(8.toUByte())
    }

    @Test
    fun `TOTP handler can get period`() {
        val parser = TotpUriParser()
        val handler = TotpHandler()
        val totp = parser.parse(
            "otpauth://totp/test?secret=SECRET&algorithm=SHA1&digits=6&period=60"
        )

        val period = handler.getPeriod(totp)

        assertThat(period).isEqualTo(60.toUShort())
    }

    @Test
    fun `TOTP sanitizer can format URI for editing`() {
        val sanitizer = TotpUriSanitizer()

        val readable = sanitizer.uriForEditing(
            "otpauth://totp/john.doe?secret=some_secret&algorithm=SHA1&digits=6&period=30"
        )

        assertThat(readable).isEqualTo("some_secret")
    }

    @Test
    fun `TOTP sanitizer can save edited URI`() {
        val sanitizer = TotpUriSanitizer()
        val original = "otpauth://totp/?secret=original_secret&issuer=original_issuer"

        val saved = sanitizer.uriForSaving(original, "new secret")

        assertThat(saved).contains("newsecret")
        assertThat(saved).contains("original_issuer")
    }
}
