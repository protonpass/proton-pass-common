package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.ImageConverter
import java.io.File

class ImageConverterTest {

    private fun getTestImage(name: String): ByteArray {
        val testFile = File("src/test/resources/images/$name")
        return testFile.readBytes()
    }

    @Test
    fun `can convert JPEG to PNG`() {
        val converter = ImageConverter()
        val jpegBytes = getTestImage("sample.jpg")
        
        val result = converter.convertTo256Png(jpegBytes)
        
        assertThat(result).isNotEmpty()
        // Verify it's a valid PNG by checking the magic number
        assertThat(result[0].toInt() and 0xFF).isEqualTo(0x89)
        assertThat(result[1].toInt() and 0xFF).isEqualTo(0x50) // 'P'
        assertThat(result[2].toInt() and 0xFF).isEqualTo(0x4E) // 'N'
        assertThat(result[3].toInt() and 0xFF).isEqualTo(0x47) // 'G'
    }

    @Test
    fun `can convert PNG to PNG`() {
        val converter = ImageConverter()
        val pngBytes = getTestImage("sample.png")
        
        val result = converter.convertTo256Png(pngBytes)
        
        assertThat(result).isNotEmpty()
        // Verify it's a valid PNG
        assertThat(result[0].toInt() and 0xFF).isEqualTo(0x89)
        assertThat(result[1].toInt() and 0xFF).isEqualTo(0x50)
        assertThat(result[2].toInt() and 0xFF).isEqualTo(0x4E)
        assertThat(result[3].toInt() and 0xFF).isEqualTo(0x47)
    }

    @Test(expected = Exception::class)
    fun `unsupported format throws error`() {
        val converter = ImageConverter()
        // Try with a text file which should fail
        val txtBytes = getTestImage("sample.txt")
        
        converter.convertTo256Png(txtBytes)
    }

    @Test
    fun `output is always PNG format`() {
        val converter = ImageConverter()
        val jpegBytes = getTestImage("sample.jpg")
        
        val result = converter.convertTo256Png(jpegBytes)
        
        // PNG signature: 89 50 4E 47 0D 0A 1A 0A
        assertThat(result[0].toInt() and 0xFF).isEqualTo(0x89)
        assertThat(result[1].toInt() and 0xFF).isEqualTo(0x50) // 'P'
        assertThat(result[2].toInt() and 0xFF).isEqualTo(0x4E) // 'N'
        assertThat(result[3].toInt() and 0xFF).isEqualTo(0x47) // 'G'
    }
}
