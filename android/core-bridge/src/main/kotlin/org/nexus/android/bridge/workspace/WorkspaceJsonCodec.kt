package org.nexus.android.bridge.workspace

import org.json.JSONArray
import org.json.JSONObject

/**
 * Canonical v1 JSON codec facade for Layer 1 portable `workspace.json`.
 * Delegates serialization to [WorkspaceJsonEncoder] and deserialization to [WorkspaceJsonDecoder].
 */
object WorkspaceJsonCodec {
    fun encode(doc: WorkspaceDocument, indentSpaces: Int = 2): String =
        WorkspaceJsonEncoder.encode(doc, indentSpaces)

    fun decode(rawJson: String): WorkspaceDocument =
        WorkspaceJsonDecoder.decode(rawJson)

    internal fun encodeProfile(p: ProfileItem): JSONObject = WorkspaceJsonEncoder.encodeProfile(p)
    internal fun decodeProfile(obj: JSONObject): ProfileItem = WorkspaceJsonDecoder.decodeProfile(obj)

    internal fun encodeSubscription(s: SubscriptionItem): JSONObject = WorkspaceJsonEncoder.encodeSubscription(s)
    internal fun decodeSubscription(obj: JSONObject): SubscriptionItem = WorkspaceJsonDecoder.decodeSubscription(obj)

    internal fun encodeRoutingProfile(rp: RoutingProfileItem): JSONObject = WorkspaceJsonEncoder.encodeRoutingProfile(rp)
    internal fun decodeRoutingProfile(obj: JSONObject): RoutingProfileItem = WorkspaceJsonDecoder.decodeRoutingProfile(obj)

    internal fun encodeDns(d: DnsConfig): JSONObject = WorkspaceJsonEncoder.encodeDns(d)
    internal fun decodeDns(obj: JSONObject): DnsConfig = WorkspaceJsonDecoder.decodeDns(obj)

    internal fun encodeRuleSetAsset(a: RuleSetAsset): JSONObject = WorkspaceJsonEncoder.encodeRuleSetAsset(a)
    internal fun decodeRuleSetAsset(obj: JSONObject): RuleSetAsset = WorkspaceJsonDecoder.decodeRuleSetAsset(obj)

    internal fun encodeFullTemplate(ft: FullTemplateConfig): JSONObject = WorkspaceJsonEncoder.encodeFullTemplate(ft)
    internal fun decodeFullTemplate(obj: JSONObject): FullTemplateConfig = WorkspaceJsonDecoder.decodeFullTemplate(obj)

    internal fun toJsonStringArray(items: List<String>): JSONArray = WorkspaceJsonEncoder.toJsonStringArray(items)
    internal fun toJsonStringMap(map: Map<String, String>): JSONObject = WorkspaceJsonEncoder.toJsonStringMap(map)
    internal fun readStringList(arr: JSONArray?): List<String> = WorkspaceJsonDecoder.readStringList(arr)
    internal fun readStringMap(obj: JSONObject?): Map<String, String> = WorkspaceJsonDecoder.readStringMap(obj)
}
