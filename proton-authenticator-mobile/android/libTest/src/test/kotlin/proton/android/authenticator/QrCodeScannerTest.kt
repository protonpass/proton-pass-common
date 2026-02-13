package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.authenticator.commonrust.QrCodeScanner
import java.io.File

class QrCodeScannerTest {

    private val scanner = QrCodeScanner()

    @Test
    fun `can import example QR code`() {
        val contents = importQrCode("example.png")

        val content = scanner.scanQrCode(contents)
        assertThat(content).isEqualTo("This is an example")
    }

    @Test
    fun `empty content returns null`() {
        val content = scanner.scanQrCode(byteArrayOf())
        assertThat(content).isNull()
    }

    @Test
    fun `can import google authenticator export QR code 1`() {
        canImportGoogleAuthenticatorQrCode("GoogleAuthenticatorExport_1.png")
    }

    @Test
    fun `can import google authenticator export QR code 2`() {
        canImportGoogleAuthenticatorQrCode("GoogleAuthenticatorExport_2.png")
    }

    @Test
    fun `can import google authenticator export QR code 3`() {
        canImportGoogleAuthenticatorQrCode("GoogleAuthenticatorExport_3.png")
    }

    private fun canImportGoogleAuthenticatorQrCode(filename: String) {
        val contents = importQrCode(filename)

        val content = scanner.scanQrCode(contents)
        assertThat(content).contains("otpauth-migration://")
    }

    private fun importQrCode(filename: String) =
        File("../../../proton-authenticator/test_data/qr/${filename}").readBytes()
}