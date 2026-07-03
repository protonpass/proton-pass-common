package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.MarkdownNodeKind
import proton.android.pass.commonrust.parseMarkdownDocument

class MarkdownTest {

    @Test
    fun `plain text node offsets match the raw source`() {
        val source = "Hello world"
        val document = parseMarkdownDocument(source)

        val textNode = document.nodes.first { it.kind == MarkdownNodeKind.TEXT }

        assertThat(source.substring(textNode.start.toInt(), textNode.end.toInt())).isEqualTo("Hello world")
    }

    @Test
    fun `bold text node offsets skip the markdown markers`() {
        val source = "Hello **world**"
        val document = parseMarkdownDocument(source)

        val boldTextNode = document.nodes.first {
            it.kind == MarkdownNodeKind.TEXT && it.text == "world"
        }

        assertThat(source.substring(boldTextNode.start.toInt(), boldTextNode.end.toInt())).isEqualTo("world")
    }

    @Test
    fun `heading node offsets match the raw source line`() {
        val source = "# Title\n\nBody text"
        val document = parseMarkdownDocument(source)

        val heading = document.nodes.first { it.id == document.root[0] }

        assertThat(source.substring(heading.start.toInt(), heading.end.toInt()).trimEnd()).isEqualTo("# Title")
    }

    @Test
    fun `list item text node offsets match the raw source`() {
        val source = "- one\n- two\n- three"
        val document = parseMarkdownDocument(source)

        val textNodes = document.nodes.filter { it.kind == MarkdownNodeKind.TEXT }

        val twoNode = textNodes.first { it.text == "two" }
        assertThat(source.substring(twoNode.start.toInt(), twoNode.end.toInt())).isEqualTo("two")
    }

    @Test
    fun `node offsets are UTF-16 code units, matching Kotlin String indexing, not UTF-8 bytes`() {
        // An emoji is 4 bytes in UTF-8 but 2 UTF-16 code units (surrogate pair) — if node.start
        // were a raw byte offset it would diverge from Kotlin's own String.indexOf() here.
        val source = "Hello 😀 **world**"
        val document = parseMarkdownDocument(source)

        val worldNode = document.nodes.first { it.kind == MarkdownNodeKind.TEXT && it.text == "world" }
        val kotlinCharIndexOfWorld = source.indexOf("world")

        assertThat(worldNode.start.toInt()).isEqualTo(kotlinCharIndexOfWorld)
        assertThat(source.substring(worldNode.start.toInt(), worldNode.end.toInt())).isEqualTo("world")
    }
}
