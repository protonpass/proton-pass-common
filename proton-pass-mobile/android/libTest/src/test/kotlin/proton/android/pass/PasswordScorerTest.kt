package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.PasswordScore
import proton.android.pass.commonrust.PasswordScorer

class PasswordScorerTest {

    @Test
    fun `weak password is scored as vulnerable`() {
        val scorer = PasswordScorer()

        val score = scorer.checkScore("123")

        assertThat(score).isEqualTo(PasswordScore.VULNERABLE)
    }

    @Test
    fun `strong password is scored as strong`() {
        val scorer = PasswordScorer()

        val score = scorer.checkScore("Xk9#mP2@qL5-wN8!")

        assertThat(score).isEqualTo(PasswordScore.STRONG)
    }

    @Test
    fun `score password returns detailed result`() {
        val scorer = PasswordScorer()

        val result = scorer.scorePassword("Test123!@#")

        assertThat(result.numericScore).isGreaterThan(0.0)
        assertThat(result.passwordScore).isAnyOf(
            PasswordScore.VULNERABLE,
            PasswordScore.WEAK,
            PasswordScore.STRONG
        )
        assertThat(result.penalties).isNotNull()
    }

    @Test
    fun `very strong password has high score`() {
        val scorer = PasswordScorer()

        val result = scorer.scorePassword("rK8#mP2@qL5-wN8!vB3&xC6*")

        assertThat(result.passwordScore).isEqualTo(PasswordScore.STRONG)
        assertThat(result.numericScore).isGreaterThan(80.0)
    }
}
