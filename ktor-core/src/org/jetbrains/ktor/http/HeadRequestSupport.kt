package org.jetbrains.ktor.http

import org.jetbrains.ktor.application.*
import org.jetbrains.ktor.content.*
import org.jetbrains.ktor.features.*
import org.jetbrains.ktor.util.*

object HeadRequestSupport : ApplicationFeature<Unit> {
    override val name = "head-request-handler"
    override val key = AttributeKey<Unit>(name)

    override fun install(application: Application, configure: Unit.() -> Unit) {
        configure(Unit)

        application.intercept(ApplicationCallPipeline.Infrastructure) {
            if (call.request.httpMethod == HttpMethod.Head) {
                it.interceptRespond(RespondPipeline.After) { message ->
                    if (message is FinalContent && message !is FinalContent.NoContent) {
                        call.respond(HeadResponse(message))
                    }
                }
            }
        }
    }

    private class HeadResponse(val delegate: FinalContent) : FinalContent.NoContent() {
        override val headers by lazy { delegate.headers }
        override val status: HttpStatusCode?
            get() = delegate.status
    }
}
