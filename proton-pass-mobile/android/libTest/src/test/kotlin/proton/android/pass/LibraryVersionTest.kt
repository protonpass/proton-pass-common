package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.libraryVersion

class LibraryVersionTest {

    @Test
    fun `library version is not empty`() {
        val version = libraryVersion()

        assertThat(version).isNotEmpty()
    }

    @Test
    fun `library version has expected format`() {
        val version = libraryVersion()

        // Version should be in format x.y.z
        val parts = version.split(".")
        assertThat(parts.size).isAtLeast(2)
    }
}
