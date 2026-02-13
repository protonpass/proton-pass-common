package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.authenticator.commonrust.AuthenticatorImportException
import proton.android.authenticator.commonrust.AuthenticatorImporter
import java.io.File
import kotlin.test.fail

class AuthenticatorImportTest {

    private val importer = AuthenticatorImporter()

    @Test
    fun `can import from pass zip`() {
        val path = "../../../proton-authenticator/test_data/authenticator/pass/PassExport.zip"
        val asFile = File(path)
        val contents = asFile.readBytes()

        val imported = importer.importFromPassZip(contents)
        assertThat(imported.entries.size).isEqualTo(7)
        assertThat(imported.errors.size).isEqualTo(1)
    }

    @Test
    fun `import password protected from proton authenticator without password throws MissingPassword`() {
        val input = """
            {"version": 1, "salt": "abcdefg", "content": "abcdefg" }
        """.trimIndent()

        try {
            importer.importFromProtonAuthenticator(input)
            fail()
        } catch (e: AuthenticatorImportException) {
            when (e) {
                is AuthenticatorImportException.MissingPassword -> {}
                else -> fail("Should have thrown AuthenticatorImportException.MissingPassword, got ${e}")
            }
        }
    }
}