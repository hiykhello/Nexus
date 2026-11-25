package org.nexus.android.bridge.workspace

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class SubscriptionInfoParserTest {
    @Test
    fun parsesUserinfoBase64TitleAndSafeUrls() {
        val b64Title = Base64.getEncoder().encodeToString("东京专线 Pro".toByteArray(Charsets.UTF_8))
        val parsed = SubscriptionInfoParser.parseHeaders(
            mapOf(
                "Subscription-Userinfo" to listOf("upload=1048576; download=2097152; total=10737418240; expire=1893456000"),
                "Profile-Title" to listOf("base64:$b64Title"),
                "Profile-Web-Page-URL" to listOf("https://portal.example.com/user"),
                "Support-URL" to listOf("tg://resolve?domain=nexus_support"),
                "Profile-Update-Interval" to listOf("12"),
            ),
        )
        assertEquals(1048576L, parsed.usage.uploadBytes)
        assertEquals(2097152L, parsed.usage.downloadBytes)
        assertEquals(10737418240L, parsed.usage.totalBytes)
        assertEquals(1893456000L, parsed.usage.expireUnixSec)
        assertEquals("东京专线 Pro", parsed.usage.profileTitle)
        assertEquals("https://portal.example.com/user", parsed.usage.webPageUrl)
        assertEquals("tg://resolve?domain=nexus_support", parsed.usage.supportUrl)
        assertEquals(720, parsed.updateIntervalMinutes)
        assertTrue(parsed.usage.hasQuota)
    }

    @Test
    fun decodesPercentEncodedTitleAndBlocksUnsafeUrlSchemes() {
        assertEquals("香港高速 #1", SubscriptionInfoParser.decodeProfileTitle("%E9%A6%99%E6%B8%AF%E9%AB%98%E9%80%9F%20%231"))
        assertEquals("http://127.0.0.1:8080/ok", SubscriptionInfoParser.sanitizeSafeUrl("http://127.0.0.1:8080/ok"))
        assertEquals("", SubscriptionInfoParser.sanitizeSafeUrl("javascript:alert(1)"))
        assertEquals("", SubscriptionInfoParser.sanitizeSafeUrl("file" + ":///etc/passwd"))
        assertEquals("", SubscriptionInfoParser.sanitizeSafeUrl("intent://scan/#Intent;end"))
        assertEquals("", SubscriptionInfoParser.sanitizeSafeUrl("data:text/html,<script>x</script>"))
    }
}
