import Foundation

/// Canonical `/v1/ws` metrics payload (identical to `/v1/status` / summary counters).
public typealias StatusMetricsSnapshot = StatusSnapshot

/// Canonical `/v1/ws` connections channel payload (matching `/v1/connections`).
public struct ConnectionsSnapshot: Sendable, Equatable, Codable {
    public let connections: [ActiveConnectionSnapshot]

    enum CodingKeys: String, CodingKey {
        case connections
    }

    public init(connections: [ActiveConnectionSnapshot] = []) {
        self.connections = connections
    }

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.container(keyedBy: CodingKeys.self),
           let list = try container.decodeIfPresent([ActiveConnectionSnapshot].self, forKey: .connections) {
            self.connections = list
            return
        }
        let single = try decoder.singleValueContainer()
        self.connections = (try? single.decode([ActiveConnectionSnapshot].self)) ?? []
    }
}

/// Multiplexed subscription channels supported by Core `GET /v1/ws`.
public enum ControlWsChannel: String, Sendable, Equatable, Hashable, Codable, CaseIterable {
    case logs = "logs"
    case connections = "connections"
    case metrics = "metrics"
}

/// Client -> Server `subscribe` command payload over `/v1/ws`.
public struct ControlWsSubscribeRequest: Sendable, Equatable, Codable {
    public let type: String
    public let channels: [ControlWsChannel]
    public let since: UInt64
    public let intervalMs: Int

    enum CodingKeys: String, CodingKey {
        case type, channels, since
        case intervalMs = "interval_ms"
    }

    public init(
        channels: [ControlWsChannel] = ControlWsChannel.allCases,
        since: UInt64 = 0,
        intervalMs: Int = 1000
    ) {
        self.type = "subscribe"
        self.channels = channels.isEmpty ? ControlWsChannel.allCases : channels
        self.since = since
        self.intervalMs = max(200, min(10_000, intervalMs))
    }
}

/// Typed events emitted by `HttpControlClient.streamControlWebSocket(...)`.
public enum ControlWsEvent: Sendable, Equatable {
    case connected
    case authOk
    case subscribed([ControlWsChannel])
    case pong
    case log(LogRingEntry)
    case connections(ConnectionsSnapshot)
    case metrics(StatusMetricsSnapshot)
    case serverError(code: String, message: String)
}

private struct RawControlWsEnvelope: Decodable {
    let type: String
    let channels: [String]?
    let code: String?
    let message: String?
}

private struct ControlWsLogFrame: Decodable {
    let data: LogRingEntry
}

private struct ControlWsConnectionsFrame: Decodable {
    let data: ConnectionsSnapshot
}

private struct ControlWsMetricsFrame: Decodable {
    let data: StatusMetricsSnapshot
}

/// Native RFC 6455 multiplexed Control WebSocket client (`GET /v1/ws`) using Foundation's
/// `URLSessionWebSocketTask` (macOS 14+ / iOS 17+, zero external dependencies).
extension HttpControlClient {
    public static let maxWebSocketMessageBytes: Int = 256 * 1024

    /// Builds a `ws://` / `wss://` `/v1/ws` request with `Authorization: Bearer <token>` in headers
    /// and strictly ZERO query parameters (never passes `?token=` or `?secret=` in the URL).
    public nonisolated func makeWebSocketRequest(path: String = "/v1/ws") throws -> URLRequest {
        try Self.buildWebSocketRequest(baseURL: baseURL, bearerToken: bearerToken, path: path)
    }

    public static func buildWebSocketRequest(
        baseURL: URL,
        bearerToken: String? = nil,
        path: String = "/v1/ws"
    ) throws -> URLRequest {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            throw HttpControlError.invalidURL
        }
        switch components.scheme?.lowercased() {
        case "http":
            components.scheme = "ws"
        case "https":
            components.scheme = "wss"
        case "ws", "wss":
            break
        default:
            throw HttpControlError.invalidURL
        }
        guard let host = components.host, !host.isEmpty else {
            throw HttpControlError.invalidURL
        }
        components.path = path.hasPrefix("/") ? path : "/\(path)"
        components.query = nil
        components.queryItems = nil
        components.fragment = nil
        guard let wsURL = components.url else {
            throw HttpControlError.invalidURL
        }
        var request = URLRequest(url: wsURL)
        request.timeoutInterval = 60.0
        if let bearerToken, !bearerToken.isEmpty {
            request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    public static func encodeWsSubscribeMessage(
        channels: [ControlWsChannel] = ControlWsChannel.allCases,
        since: UInt64 = 0,
        intervalMs: Int = 1000
    ) throws -> String {
        let payload = ControlWsSubscribeRequest(channels: channels, since: since, intervalMs: intervalMs)
        let data = try JSONEncoder().encode(payload)
        return String(decoding: data, as: UTF8.self)
    }

    public static func decodeControlWsEvent(_ data: Data) throws -> ControlWsEvent? {
        let decoder = JSONDecoder()
        let envelope = try decoder.decode(RawControlWsEnvelope.self, from: data)
        switch envelope.type.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "auth_ok":
            return .authOk
        case "subscribed":
            let channels = (envelope.channels ?? []).compactMap {
                ControlWsChannel(rawValue: $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
            }
            return .subscribed(channels)
        case "pong":
            return .pong
        case "log":
            return .log(try decoder.decode(ControlWsLogFrame.self, from: data).data)
        case "connections":
            return .connections(try decoder.decode(ControlWsConnectionsFrame.self, from: data).data)
        case "metrics":
            return .metrics(try decoder.decode(ControlWsMetricsFrame.self, from: data).data)
        case "error":
            return .serverError(code: envelope.code ?? "", message: envelope.message ?? "")
        default:
            return nil
        }
    }

    public nonisolated func streamControlWebSocket(
        channels: [ControlWsChannel] = ControlWsChannel.allCases,
        since: UInt64 = 0,
        intervalMs: Int = 1000
    ) -> AsyncThrowingStream<ControlWsEvent, Error> {
        AsyncThrowingStream { continuation in
            let request: URLRequest
            let subscribeText: String
            do {
                request = try self.makeWebSocketRequest()
                subscribeText = try Self.encodeWsSubscribeMessage(
                    channels: channels,
                    since: since,
                    intervalMs: intervalMs
                )
            } catch {
                continuation.finish(throwing: error)
                return
            }

            let wsTask = self.streamSession.webSocketTask(with: request)
            wsTask.maximumMessageSize = Self.maxWebSocketMessageBytes
            let receiveTask = Task {
                wsTask.resume()
                do {
                    try await wsTask.send(.string(subscribeText))
                    if Task.isCancelled {
                        wsTask.cancel(with: .goingAway, reason: nil)
                        continuation.finish()
                        return
                    }
                    continuation.yield(.connected)

                    while !Task.isCancelled {
                        let message = try await wsTask.receive()
                        let rawData: Data
                        switch message {
                        case .string(let text):
                            rawData = Data(text.utf8)
                        case .data(let data):
                            rawData = data
                        @unknown default:
                            continue
                        }
                        if let event = try Self.decodeControlWsEvent(rawData) {
                            continuation.yield(event)
                        }
                    }
                    wsTask.cancel(with: .goingAway, reason: nil)
                    continuation.finish()
                } catch is CancellationError {
                    wsTask.cancel(with: .goingAway, reason: nil)
                    continuation.finish()
                } catch {
                    wsTask.cancel(with: .goingAway, reason: nil)
                    if Task.isCancelled {
                        continuation.finish()
                    } else {
                        continuation.finish(throwing: error)
                    }
                }
            }
            continuation.onTermination = { _ in
                wsTask.cancel(with: .goingAway, reason: nil)
                receiveTask.cancel()
            }
        }
    }
}
