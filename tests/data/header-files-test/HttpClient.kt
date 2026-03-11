/*
 * Copyright 2014-2024 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.ktor.client

import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.util.*
import kotlinx.coroutines.*
import kotlin.coroutines.*

class HttpClient(
    private val engine: HttpClientEngine,
    private val config: HttpClientConfig
) : CoroutineScope, Closeable {

    override val coroutineContext: CoroutineContext
        get() = engine.coroutineContext

    private val plugins = mutableMapOf<AttributeKey<*>, Any>()

    suspend fun request(builder: HttpRequestBuilder): HttpResponse {
        val call = engine.execute(builder)
        return call.response
    }

    suspend fun get(urlString: String, block: HttpRequestBuilder.() -> Unit = {}): HttpResponse {
        return request {
            url(urlString)
            method = HttpMethod.Get
            block()
        }
    }

    suspend fun post(urlString: String, block: HttpRequestBuilder.() -> Unit = {}): HttpResponse {
        return request {
            url(urlString)
            method = HttpMethod.Post
            block()
        }
    }

    fun <T : Any> plugin(key: AttributeKey<T>): T {
        @Suppress("UNCHECKED_CAST")
        return plugins[key] as? T
            ?: throw IllegalStateException("Plugin $key is not installed")
    }

    override fun close() {
        engine.close()
    }
}