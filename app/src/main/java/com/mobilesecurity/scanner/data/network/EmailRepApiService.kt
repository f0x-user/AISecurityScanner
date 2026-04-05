package com.mobilesecurity.scanner.data.network

import com.mobilesecurity.scanner.data.network.dto.EmailRepResponse
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Path

interface EmailRepApiService {

    @GET("{email}")
    suspend fun getEmailReputation(
        @Path("email") email: String,
        @Header("User-Agent") userAgent: String = "AISecurityScanner"
    ): Response<EmailRepResponse>
}
