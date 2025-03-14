package proton.authenticator.android.benchmark

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import proton.android.authenticator.benchmark.R
import proton.android.authenticator.commonrust.AuthenticatorMobileClient
import proton.android.authenticator.commonrust.MobileTotpBenchmark

class MainActivity: Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)

        findViewById<Button>(R.id.run_button).setOnClickListener {
            runTest()
        }
    }

    private fun runTest() {
        generationBenchmark("SHA1")
        generationBenchmark("SHA256")
        generationBenchmark("SHA512")
    }

    private fun generationBenchmark(algorithm: String) {
        val client = AuthenticatorMobileClient()
        val sha1Entry = client.entryFromUri(getEntryUri(algorithm))

        val benchmarker = MobileTotpBenchmark(10_000u)
        val count = benchmarker.run(sha1Entry)
        println("[$algorithm] Generated $count codes in 10 seconds. Codes per second: ${count / 10u}")
    }

    private fun getEntryUri(algorithm: String): String = "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=${algorithm}&digits=8&period=15"
}