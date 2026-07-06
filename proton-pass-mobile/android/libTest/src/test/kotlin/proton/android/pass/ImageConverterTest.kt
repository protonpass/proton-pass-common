package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.ConvertImageException
import proton.android.pass.commonrust.ImageConverter
import java.io.File
import kotlin.test.assertFailsWith

class ImageConverterTest {

    private fun getTestImage(name: String): ByteArray {
        val testFile = File("src/test/resources/images/$name")
        return testFile.readBytes()
    }

    @Test
    fun `can convert JPEG to WebP`() {
        val converter = ImageConverter()
        val jpegBytes = getTestImage("sample.jpg")
        
        val result = converter.convertTo256Webp(jpegBytes)
        
        assertThat(result).isNotEmpty()
        // Verify it's a valid WebP by checking the RIFF header
        assertThat(result[0].toInt() and 0xFF).isEqualTo(0x52) // 'R'
        assertThat(result[1].toInt() and 0xFF).isEqualTo(0x49) // 'I'
        assertThat(result[2].toInt() and 0xFF).isEqualTo(0x46) // 'F'
        assertThat(result[3].toInt() and 0xFF).isEqualTo(0x46) // 'F'
    }

    @Test
    fun `can convert PNG to WebP`() {
        val converter = ImageConverter()
        val pngBytes = getTestImage("sample.png")
        
        val result = converter.convertTo256Webp(pngBytes)
        
        assertThat(result).isNotEmpty()
        // Verify it's a valid WebP by checking the RIFF header
        assertThat(result[0].toInt() and 0xFF).isEqualTo(0x52) // 'R'
        assertThat(result[1].toInt() and 0xFF).isEqualTo(0x49) // 'I'
        assertThat(result[2].toInt() and 0xFF).isEqualTo(0x46) // 'F'
        assertThat(result[3].toInt() and 0xFF).isEqualTo(0x46) // 'F'
    }

    @Test
    fun `unsupported format throws error`() {
        val converter = ImageConverter()
        // Try with a text file which should fail
        val txtBytes = getTestImage("sample.txt")
        
        val exception = assertFailsWith<ConvertImageException> {
            converter.convertTo256Webp(txtBytes)
        }

        assertThat(exception).isInstanceOf(ConvertImageException.UnsupportedInputFormat::class.java)
    }
}
