package proton.android.authenticator.commonrust

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TotpGenerationBenchmark {

    @Test
    fun generateSha1Totp() {
        generationBenchmark("SHA1")
    }

    @Test
    fun generateSha256Totp() {
        generationBenchmark("SHA256")
    }

    @Test
    fun generateSha512Totp() {
        generationBenchmark("SHA512")
    }

    private fun generationBenchmark(algorithm: String) {
        val client = AuthenticatorMobileClient()
        val sha1Entry = client.entryFromUri(getEntryUri(algorithm))

        val benchmarker = MobileTotpBenchmark(10_000u)
        val count = benchmarker.run(sha1Entry)
        println("Generated $count codes in 10 seconds. Codes per second: ${count / 10u}")
    }

    private fun getEntryUri(algorithm: String): String = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=${algorithm}&digits=8&period=15"

}