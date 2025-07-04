package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import uniffi.proton_authenticator_common_mobile.AuthenticatorImporter
import java.io.File

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
}