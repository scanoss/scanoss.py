// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// The default IServiceProvider implementation.
    /// </summary>
    public sealed class ServiceProvider : IServiceProvider, IDisposable, IAsyncDisposable
    {
        private readonly ConcurrentDictionary<Type, Func<IServiceProvider, object>> _factories;
        private readonly ConcurrentDictionary<Type, object> _singletons;
        private readonly IServiceCollection _services;
        private bool _disposed;

        internal ServiceProvider(IServiceCollection services)
        {
            _services = services ?? throw new ArgumentNullException(nameof(services));
            _factories = new ConcurrentDictionary<Type, Func<IServiceProvider, object>>();
            _singletons = new ConcurrentDictionary<Type, object>();
        }

        /// <summary>
        /// Gets the service object of the specified type.
        /// </summary>
        public object GetService(Type serviceType)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(ServiceProvider));

            if (serviceType == typeof(IServiceProvider))
                return this;

            if (_singletons.TryGetValue(serviceType, out var singleton))
                return singleton;

            if (_factories.TryGetValue(serviceType, out var factory))
                return factory(this);

            var descriptor = _services.FirstOrDefault(d => d.ServiceType == serviceType);
            if (descriptor == null)
                return null;

            return CreateInstance(descriptor);
        }

        private object CreateInstance(ServiceDescriptor descriptor)
        {
            if (descriptor.ImplementationInstance != null)
                return descriptor.ImplementationInstance;

            if (descriptor.ImplementationFactory != null)
                return descriptor.ImplementationFactory(this);

            var implementationType = descriptor.ImplementationType;
            var constructor = implementationType.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();

            var parameters = constructor.GetParameters()
                .Select(p => GetService(p.ParameterType))
                .ToArray();

            return constructor.Invoke(parameters);
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            foreach (var singleton in _singletons.Values)
            {
                if (singleton is IDisposable disposable)
                    disposable.Dispose();
            }

            _singletons.Clear();
            _factories.Clear();
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            _disposed = true;

            foreach (var singleton in _singletons.Values)
            {
                if (singleton is IAsyncDisposable asyncDisposable)
                    await asyncDisposable.DisposeAsync();
                else if (singleton is IDisposable disposable)
                    disposable.Dispose();
            }

            _singletons.Clear();
            _factories.Clear();
        }
    }
}