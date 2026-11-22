package org.nexus.android.bridge.share

import org.nexus.android.bridge.model.OutboundScheme as ModelScheme
import org.nexus.android.bridge.model.ParsedOutbound as ModelParsedOutbound
import org.nexus.android.bridge.model.ShareLinkParser as ModelShareLinkParser

typealias OutboundScheme = ModelScheme
typealias ParsedOutbound = ModelParsedOutbound

/**
 * Compatibility facade delegating to [org.nexus.android.bridge.model.ShareLinkParser]
 * so both `bridge.share` and `bridge.model` consumers stay 100% schema-aligned.
 */
object ShareLinkParser {
    fun parse(rawUri: String): Result<ParsedOutbound> = ModelShareLinkParser.parse(rawUri)
    fun renderKdlOutbound(node: ParsedOutbound, secretFilePath: String): String =
        ModelShareLinkParser.renderKdlOutbound(node, secretFilePath)
}
