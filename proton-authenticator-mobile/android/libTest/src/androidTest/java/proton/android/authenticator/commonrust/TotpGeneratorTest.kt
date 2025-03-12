package proton.android.authenticator.commonrust

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TotpGeneratorTest {

    @Test
    fun canInvokeEntryFromUri() {
        val client = AuthenticatorMobileClient()
        val entry = client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")

        assertThat(entry.name).isEqualTo("MYLABEL")
    }

    @Test
    fun canInvokeGenerator() = runTest {
        registerAuthenticatorLogger(object : AuthenticatorLogger {
            override fun log(level: AuthenticatorLogLevel, message: String) {
                println("[$level] $message")
            }
        })

        launch(Dispatchers.Default) {
            val entry1 = getEntry1()
            val entry2 = getEntry2()

            val period = 100 // generate codes every 100ms
            val generator = MobileTotpGenerator(
                period = period.toUInt(),
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

            val generated = mutableListOf<List<AuthenticatorCodeResponse>>()
            val handle = generator.start(
                entries = listOf(entry1, entry2),
                callback = object : MobileTotpGeneratorCallback {
                    override fun onCodes(codes: List<AuthenticatorCodeResponse>) {
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

    private fun getEntry1(): AuthenticatorEntryModel {
        val client = AuthenticatorMobileClient()
        return client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")
    }

    private fun getEntry2(): AuthenticatorEntryModel {
        val client = AuthenticatorMobileClient()
        return client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET123&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")
    }
}