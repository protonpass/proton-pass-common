package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Test
import proton.android.authenticator.AuthenticatorCodeResponseModel
import proton.android.authenticator.commonrust.MobileCurrentTimeProvider
import proton.android.authenticator.commonrust.MobileTotpGenerator
import proton.android.authenticator.commonrust.MobileTotpGeneratorCallback

class TotpGeneratorTest {

    @Test
    fun canInvokeGenerator() = runTest {
        launch(Dispatchers.Default) {
            val entry1 = TestUtils.getEntry1()
            val entry2 = TestUtils.getEntry2()

            val period = 100 // generate codes every 100ms
            val generator = MobileTotpGenerator(
                periodMs = period.toUInt(),
                onlyOnCodeChange = false,
                currentTime = object : MobileCurrentTimeProvider {
                    var idx = 0
                    override fun now(): ULong = when (idx) {
                        0 -> 1741764120
                        1 -> 1741789012
                        2 -> 1741890123
                        else -> throw RuntimeException("Should not request")
                    }.toULong().also { idx += 1 }
                }
            )

            val generated = mutableListOf<List<AuthenticatorCodeResponseModel>>()
            val handle = generator.start(
                entries = listOf(entry1, entry2),
                callback = object : MobileTotpGeneratorCallback {
                    override fun onCodes(codes: List<AuthenticatorCodeResponseModel>) {
                        generated.add(codes)
                    }
                }
            )

            // Wait for the necessary time to generate 3 codes
            val times = 3
            delay((times * period).toLong())

            assertThat(generated.size).isEqualTo(times)

            // Cancel the generation
            handle.cancel()

            // Assert that no more codes are generated
            delay((period * 2).toLong())
            assertThat(generated.size).isEqualTo(times)

            // Assert codes are right
            assertThat(generated[0].size).isEqualTo(2)
            assertThat(generated[0][0].currentCode).isEqualTo("55894277")
            assertThat(generated[0][0].nextCode).isEqualTo("32755418")
            assertThat(generated[0][1].currentCode).isEqualTo("03271278")
            assertThat(generated[0][1].nextCode).isEqualTo("94297675")
            assertThat(generated[1].size).isEqualTo(2)
            assertThat(generated[1][0].currentCode).isEqualTo("74506379")
            assertThat(generated[1][0].nextCode).isEqualTo("66003564")
            assertThat(generated[1][1].currentCode).isEqualTo("66986124")
            assertThat(generated[1][1].nextCode).isEqualTo("11675313")
            assertThat(generated[2].size).isEqualTo(2)
            assertThat(generated[2][0].currentCode).isEqualTo("07871325")
            assertThat(generated[2][0].nextCode).isEqualTo("49179669")
            assertThat(generated[2][1].currentCode).isEqualTo("77812358")
            assertThat(generated[2][1].nextCode).isEqualTo("54935379")
        }

    }

    @Test
    fun canInvokeGeneratorOnlyOnCodeChange() = runTest {
        launch(Dispatchers.Default) {
            val entry = TestUtils.getEntry1()

            val period = 100 // generate codes every 100ms
            val generator = MobileTotpGenerator(
                periodMs = period.toUInt(),
                onlyOnCodeChange = true,
                currentTime = object : MobileCurrentTimeProvider {
                    var idx = 0
                    override fun now(): ULong = when (idx) {
                        0 -> 1741764120 // Generate
                        1 -> 1741764121 // Don't generate
                        2 -> 1741764122 // Don't generate
                        3 -> 1741890120 // Generate
                        else -> throw RuntimeException("Should not request")
                    }.toULong().also { idx += 1 }
                }
            )

            val generated = mutableListOf<List<AuthenticatorCodeResponseModel>>()
            val handle = generator.start(
                entries = listOf(entry),
                callback = object : MobileTotpGeneratorCallback {
                    override fun onCodes(codes: List<AuthenticatorCodeResponseModel>) {
                        generated.add(codes)
                    }
                }
            )

            // Wait for the necessary time to generate 4 ticks
            val times = 4
            delay((times * period).toLong())

            assertThat(generated.size).isEqualTo(2)

            // Cancel the generation
            handle.cancel()

            // Assert codes are right
            assertThat(generated[0].size).isEqualTo(1)
            assertThat(generated[0][0].currentCode).isEqualTo("55894277")
            assertThat(generated[0][0].nextCode).isEqualTo("32755418")

            assertThat(generated[1].size).isEqualTo(1)
            assertThat(generated[1][0].currentCode).isEqualTo("07871325")
            assertThat(generated[1][0].nextCode).isEqualTo("49179669")
        }

    }

}