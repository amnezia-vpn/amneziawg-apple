// SPDX-License-Identifier: MIT

import Foundation
import Darwin
import dnssd

/// RFC 2782 RDATA. SRV target names must not use DNS message compression.
struct SRVRecord: Equatable {
    let priority: UInt16
    let weight: UInt16
    let port: UInt16
    let target: String

    init?(rdata: Data) {
        let bytes = [UInt8](rdata)
        guard bytes.count >= 7 else { return nil }
        priority = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        weight = UInt16(bytes[2]) << 8 | UInt16(bytes[3])
        port = UInt16(bytes[4]) << 8 | UInt16(bytes[5])
        var offset = 6
        var labels = [String]()
        while offset < bytes.count {
            let length = Int(bytes[offset])
            offset += 1
            if length == 0 {
                guard offset == bytes.count, offset - 6 <= 255 else { return nil }
                target = labels.isEmpty ? "." : labels.joined(separator: ".") + "."
                guard target == "." || port != 0 else { return nil }
                return
            }
            guard length <= 63, offset + length < bytes.count,
                  let label = String(bytes: bytes[offset..<(offset + length)], encoding: .ascii),
                  label.utf8.allSatisfy({
                      (65...90).contains($0) || (97...122).contains($0) ||
                      (48...57).contains($0) || $0 == 45 || $0 == 95
                  }) else { return nil }
            labels.append(label)
            offset += length
        }
        return nil
    }

    /// Try lower priorities first; select weighted records without replacement.
    static func ordered(_ records: [SRVRecord], random: (ClosedRange<Int>) -> Int = { Int.random(in: $0) }) -> [SRVRecord] {
        var result = [SRVRecord]()
        for priority in Set(records.map { $0.priority }).sorted() {
            var remaining = records.filter { $0.priority == priority }
            while !remaining.isEmpty {
                let total = remaining.reduce(0) { $0 + Int($1.weight) }
                if total == 0 {
                    result.append(remaining.remove(at: random(0...(remaining.count - 1))))
                    continue
                }
                // RFC 2782 places zero-weight entries first and draws inclusively from zero.
                remaining.sort { ($0.weight == 0 ? 0 : 1) < ($1.weight == 0 ? 0 : 1) }
                let draw = random(0...total)
                var cumulative = 0
                let index = remaining.firstIndex {
                    cumulative += Int($0.weight)
                    return cumulative >= draw
                }!
                result.append(remaining.remove(at: index))
            }
        }
        return result
    }
}

enum SRVResolver {
    private final class Query {
        var records = [SRVRecord]()
        var error: DNSServiceErrorType = kDNSServiceErr_NoError
        var finished = false
    }

    /// Use the system DNS-SD resolver, with a bounded wait and no hard-coded DNS server.
    static func lookup(_ name: String) throws -> [SRVRecord] {
        let query = Query()
        var service: DNSServiceRef?
        let callback: DNSServiceQueryRecordReply = { _, flags, _, error, _, type, _, length, data, _, context in
            guard let context = context else { return }
            let query = Unmanaged<Query>.fromOpaque(context).takeUnretainedValue()
            if error != kDNSServiceErr_NoError {
                query.error = error
                query.finished = true
                return
            }
            // ReturnIntermediates may report CNAMEs before the requested RRset.
            guard type == UInt16(kDNSServiceType_SRV) else { return }
            if flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0,
               type == UInt16(kDNSServiceType_SRV), let data = data,
               let record = SRVRecord(rdata: Data(bytes: data, count: Int(length))) {
                query.records.append(record)
            }
            if flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) == 0 {
                query.finished = true
            }
        }
        let error = DNSServiceQueryRecord(
            &service, DNSServiceFlags(kDNSServiceFlagsReturnIntermediates | kDNSServiceFlagsTimeout), 0,
            name, UInt16(kDNSServiceType_SRV), UInt16(kDNSServiceClass_IN), callback,
            Unmanaged.passUnretained(query).toOpaque())
        guard error == kDNSServiceErr_NoError, let service = service else {
            throw DNSResolutionError(errorCode: EAI_FAIL, address: name)
        }
        defer { DNSServiceRefDeallocate(service) }
        let socket = DNSServiceRefSockFD(service)
        guard socket >= 0 else { throw DNSResolutionError(errorCode: EAI_FAIL, address: name) }
        let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
        while !query.finished {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw DNSResolutionError(errorCode: EAI_AGAIN, address: name) }
            let milliseconds = Int32(max(1, (deadline - now) / 1_000_000))
            var descriptor = pollfd(fd: socket, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, milliseconds)
            if ready < 0 && errno == EINTR { continue }
            guard ready > 0, descriptor.revents & Int16(POLLIN) != 0 else {
                throw DNSResolutionError(errorCode: EAI_AGAIN, address: name)
            }
            guard DNSServiceProcessResult(service) == kDNSServiceErr_NoError else {
                throw DNSResolutionError(errorCode: EAI_FAIL, address: name)
            }
        }
        guard query.error == kDNSServiceErr_NoError, !query.records.isEmpty else {
            throw DNSResolutionError(errorCode: EAI_NONAME, address: name)
        }
        return query.records
    }
}
