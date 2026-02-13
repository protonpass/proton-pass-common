package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.CreditCardDetector
import proton.android.pass.commonrust.CreditCardType

class CreditCardDetectorTest {

    @Test
    fun `can detect Visa card`() {
        val detector = CreditCardDetector()

        val type = detector.detect("4111111111111111")

        assertThat(type).isEqualTo(CreditCardType.VISA)
    }

    @Test
    fun `can detect Mastercard`() {
        val detector = CreditCardDetector()

        val type = detector.detect("5555555555554444")

        assertThat(type).isEqualTo(CreditCardType.MASTERCARD)
    }

    @Test
    fun `can detect American Express`() {
        val detector = CreditCardDetector()

        val type = detector.detect("378282246310005")

        assertThat(type).isEqualTo(CreditCardType.AMERICAN_EXPRESS)
    }

    @Test
    fun `invalid card number returns unknown`() {
        val detector = CreditCardDetector()

        val type = detector.detect("1234567890")

        assertThat(type).isEqualTo(CreditCardType.UNKNOWN)
    }

    @Test
    fun `empty string returns unknown`() {
        val detector = CreditCardDetector()

        val type = detector.detect("")

        assertThat(type).isEqualTo(CreditCardType.UNKNOWN)
    }
}
