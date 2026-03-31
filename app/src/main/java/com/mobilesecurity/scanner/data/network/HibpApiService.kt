package com.mobilesecurity.scanner.data.network

import com.mobilesecurity.scanner.data.network.dto.HibpBreachEntry
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Path

interface HibpApiService {

    @GET("breachedaccount/{account}?truncateResponse=false")
    suspend fun getBreachesForAccount(
        @Path("account") account: String,
        @Header("hibp-api-key") apiKey: String,
        @Header("user-agent") userAgent: String = "SecurityScanner-Android"
    ): Response<List<HibpBreachEntry>>

    @GET("breaches")
    suspend fun getAllBreaches(): Response<List<HibpBreachEntry>>
}

interface PwnedPasswordsApiService {
    @GET("range/{hashPrefix}")
    suspend fun getHashRange(
        @Path("hashPrefix") hashPrefix: String
    ): Response<String>
}
