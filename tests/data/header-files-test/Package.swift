// Copyright (c) 2024 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0 with Runtime Library Exception
//
// See https://swift.org/LICENSE.txt for license information
// See https://swift.org/CONTRIBUTORS.txt for the list of Swift project authors

import Foundation
import Combine
import os.log

/// A thread-safe container that manages the lifecycle of registered services.
///
/// `ServiceContainer` provides dependency injection capabilities by storing
/// factory closures that create service instances on demand. Services can be
/// registered as transient (new instance each time) or singleton (shared instance).
public final class ServiceContainer: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private var factories: [String: () -> Any] = [:]
    private var singletons: [String: Any] = [:]
    private let logger = Logger(subsystem: "com.app", category: "DI")

    public static let shared = ServiceContainer()

    public init() {}

    /// Registers a factory closure for the given type.
    public func register<T>(_ type: T.Type, factory: @escaping () -> T) {
        let key = String(describing: type)
        lock.lock()
        defer { lock.unlock() }
        factories[key] = factory
        logger.debug("Registered service: \(key)")
    }

    /// Registers a singleton instance for the given type.
    public func registerSingleton<T>(_ type: T.Type, factory: @escaping () -> T) {
        let key = String(describing: type)
        lock.lock()
        defer { lock.unlock() }
        singletons[key] = factory()
        logger.debug("Registered singleton: \(key)")
    }

    /// Resolves an instance of the given type.
    public func resolve<T>(_ type: T.Type) -> T? {
        let key = String(describing: type)
        lock.lock()
        defer { lock.unlock() }

        if let singleton = singletons[key] as? T {
            return singleton
        }

        guard let factory = factories[key] else {
            logger.warning("No registration found for: \(key)")
            return nil
        }

        return factory() as? T
    }

    /// Removes all registrations.
    public func reset() {
        lock.lock()
        defer { lock.unlock() }
        factories.removeAll()
        singletons.removeAll()
        logger.info("Container reset")
    }
}